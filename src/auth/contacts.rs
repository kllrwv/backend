use crate::{Result, auth::UNAVAILABLE};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;
pub struct Store {
    encryption: LessSafeKey,
    indexing: [u8; 32],
    key_check: String,
}
impl Store {
    pub fn from_hex(secret: &str, app_secret: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            secret.len() == 64
                && secret.bytes().all(|byte| byte.is_ascii_hexdigit())
                && !secret.eq_ignore_ascii_case(app_secret),
            "CONTACT_SECRET must be an independent value generated with openssl rand -hex 32"
        );
        let mut root = [0u8; 32];
        for (index, byte) in root.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&secret[index * 2..index * 2 + 2], 16)?;
        }
        Ok(Self::new(&root, app_secret))
    }
    pub fn new(root: &[u8; 32], app_secret: &str) -> Self {
        let encryption = mac(root, "killerwave contact encryption v1", "");
        let check = mac(root, "killerwave contact key check v1", app_secret);
        Self {
            encryption: LessSafeKey::new(
                UnboundKey::new(&AES_256_GCM, &encryption).expect("valid aes-256 key"),
            ),
            indexing: mac(root, "killerwave contact indexing v1", ""),
            key_check: URL_SAFE_NO_PAD.encode(check),
        }
    }
    fn lookup(&self, kind: &str, legacy: &str) -> String {
        format!(
            "v1:{}",
            URL_SAFE_NO_PAD.encode(mac(&self.indexing, kind, legacy))
        )
    }
    pub fn email_lookup(&self, email: &str) -> String {
        let legacy = format!(
            "{:x}",
            Sha256::digest(email.to_ascii_lowercase().as_bytes())
        );
        self.lookup("email", &legacy)
    }
    pub fn phone_lookup(&self, legacy: &str) -> String {
        self.lookup("phone", legacy)
    }
    pub fn seal_email(&self, email: &str, lookup: &str) -> Result<Vec<u8>> {
        self.seal("email", lookup, email)
    }
    pub fn open_email(&self, lookup: &str, ciphertext: Vec<u8>) -> Result<String> {
        self.open("email", lookup, ciphertext)
    }
    pub fn seal_phone_tail(&self, tail: &str, lookup: &str) -> Result<Vec<u8>> {
        self.seal("phone-tail", lookup, tail)
    }
    pub fn open_phone_tail(&self, lookup: &str, ciphertext: Vec<u8>) -> Result<String> {
        self.open("phone-tail", lookup, ciphertext)
    }
    pub fn seal_phone(&self, phone: &str, lookup: &str) -> Result<Vec<u8>> {
        self.seal("phone-number", lookup, phone)
    }
    pub fn open_phone(&self, lookup: &str, ciphertext: Vec<u8>) -> Result<String> {
        self.open("phone-number", lookup, ciphertext)
    }
    pub fn seal_admin_event(&self, event: Uuid, value: &str) -> Result<Vec<u8>> {
        self.seal("admin-event", &event.to_string(), value)
    }
    pub fn open_admin_event(&self, event: Uuid, ciphertext: Vec<u8>) -> Result<String> {
        self.open("admin-event", &event.to_string(), ciphertext)
    }
    pub fn seal_totp(&self, account: Uuid, generation: Uuid, secret: &str) -> Result<Vec<u8>> {
        self.seal("totp", &format!("{account}:{generation}"), secret)
    }
    pub fn open_totp(
        &self,
        account: Uuid,
        generation: Uuid,
        ciphertext: Vec<u8>,
    ) -> Result<String> {
        self.open("totp", &format!("{account}:{generation}"), ciphertext)
    }
    fn seal(&self, kind: &str, lookup: &str, value: &str) -> Result<Vec<u8>> {
        let mut nonce = [0; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| UNAVAILABLE)?;
        let mut ciphertext = value.as_bytes().to_vec();
        self.encryption
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(format!("{kind}:{lookup}")),
                &mut ciphertext,
            )
            .map_err(|_| UNAVAILABLE)?;
        let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.append(&mut ciphertext);
        Ok(result)
    }
    fn open(&self, kind: &str, lookup: &str, mut stored: Vec<u8>) -> Result<String> {
        let nonce = stored.get(..NONCE_LEN).ok_or(UNAVAILABLE)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| UNAVAILABLE)?;
        let plaintext = self
            .encryption
            .open_in_place(
                nonce,
                Aad::from(format!("{kind}:{lookup}")),
                &mut stored[NONCE_LEN..],
            )
            .map_err(|_| UNAVAILABLE)?;
        String::from_utf8(plaintext.to_vec()).map_err(|_| UNAVAILABLE)
    }
    pub async fn migrate(&self, db: &PgPool) -> anyhow::Result<()> {
        let mut tx = db.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(73460650021401)")
            .execute(&mut *tx)
            .await?;
        let key_check: Option<String> =
            sqlx::query_scalar("SELECT key_check FROM contact_storage WHERE singleton")
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(stored) = key_check {
            anyhow::ensure!(
                crate::auth::code_matches(&self.key_check, Some(&stored)),
                "contact storage keys do not match this database"
            );
            tx.commit().await?;
            return Ok(());
        }
        sqlx::raw_sql("LOCK TABLE accounts, auth_flows, account_changes, retired_contacts IN ACCESS EXCLUSIVE MODE;
                      DROP TRIGGER enforce_contact_history ON accounts;")
            .execute(&mut *tx).await?;
        let mut cursor: Option<Uuid> = None;
        loop {
            let rows: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
                "SELECT id,email,phone_key,phone_tail FROM accounts
                 WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT 128",
            )
            .bind(cursor)
            .fetch_all(&mut *tx)
            .await?;
            if rows.is_empty() {
                break;
            }
            for (id, email, legacy_phone, tail) in rows {
                let lookup = self.email_lookup(&email);
                let phone = self.phone_lookup(&legacy_phone);
                let ciphertext = self
                    .seal_email(&email, &lookup)
                    .map_err(|_| anyhow::anyhow!("contact encryption failed"))?;
                let tail = tail
                    .map(|value| self.seal_phone_tail(&value, &phone))
                    .transpose()
                    .map_err(|_| anyhow::anyhow!("contact encryption failed"))?;
                sqlx::query(
                    "UPDATE accounts SET email_lookup=$2,email_ciphertext=$3,phone_key=$4,phone_tail_ciphertext=$5 WHERE id=$1",
                ).bind(id).bind(lookup).bind(ciphertext).bind(phone).bind(tail)
                    .execute(&mut *tx).await?;
                cursor = Some(id);
            }
        }
        let mut cursor: Option<String> = None;
        loop {
            let rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT id,email FROM auth_flows WHERE email IS NOT NULL AND ($1::text IS NULL OR id>$1)
                 ORDER BY id LIMIT 128",
            ).bind(&cursor).fetch_all(&mut *tx).await?;
            if rows.is_empty() {
                break;
            }
            for (id, email) in rows {
                let lookup = self.email_lookup(&email);
                let ciphertext = self
                    .seal_email(&email, &lookup)
                    .map_err(|_| anyhow::anyhow!("contact encryption failed"))?;
                sqlx::query(
                    "UPDATE auth_flows SET email_lookup=$2,email_ciphertext=$3 WHERE id=$1",
                )
                .bind(&id)
                .bind(lookup)
                .bind(ciphertext)
                .execute(&mut *tx)
                .await?;
                cursor = Some(id);
            }
        }
        let mut cursor: Option<Uuid> = None;
        loop {
            let rows: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
                "SELECT id,kind,previous,destination FROM account_changes
                 WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT 128",
            )
            .bind(cursor)
            .fetch_all(&mut *tx)
            .await?;
            if rows.is_empty() {
                break;
            }
            for (id, kind, previous, destination) in rows {
                let (previous, next_lookup, ciphertext) = if kind == "email" {
                    let target = destination
                        .ok_or_else(|| anyhow::anyhow!("email change has no destination"))?;
                    let lookup = self.email_lookup(&target);
                    let cipher = self
                        .seal_email(&target, &lookup)
                        .map_err(|_| anyhow::anyhow!("contact encryption failed"))?;
                    (self.email_lookup(&previous), Some(lookup), Some(cipher))
                } else {
                    (self.phone_lookup(&previous), None, None)
                };
                sqlx::query("UPDATE account_changes SET previous=$2,destination=$3,destination_ciphertext=$4 WHERE id=$1")
                    .bind(id).bind(previous).bind(next_lookup).bind(ciphertext).execute(&mut *tx).await?;
                cursor = Some(id);
            }
        }
        loop {
            let rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT kind,fingerprint FROM retired_contacts WHERE fingerprint NOT LIKE 'v1:%'
                 ORDER BY kind,fingerprint LIMIT 128",
            )
            .fetch_all(&mut *tx)
            .await?;
            if rows.is_empty() {
                break;
            }
            for (kind, fingerprint) in rows {
                sqlx::query(
                    "UPDATE retired_contacts SET fingerprint=$3 WHERE kind=$1 AND fingerprint=$2",
                )
                .bind(&kind)
                .bind(&fingerprint)
                .bind(self.lookup(&kind, &fingerprint))
                .execute(&mut *tx)
                .await?;
            }
        }
        sqlx::raw_sql(include_str!("contact_finalize.sql"))
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO contact_storage(key_check) VALUES($1)")
            .bind(&self.key_check)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
fn mac(key: &[u8; 32], purpose: &str, value: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("valid hmac key");
    mac.update(purpose.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().into()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[sqlx::test(migrations = "./migrations")]
    async fn migrates_saved_contacts_and_pending_changes(db: PgPool) {
        sqlx::raw_sql(
            "INSERT INTO accounts(id, email, password_hash, telegram_id, phone_key, phone_tail)
                 VALUES ('a0000000-0000-4000-8000-000000000001', 'active@example.test', 'hash', 12, 'legacy-phone', '0123');
             INSERT INTO sessions(id, account_id)
                 VALUES ('test-session', 'a0000000-0000-4000-8000-000000000001');
             INSERT INTO auth_flows(id, kind, stage, lang, email, expires_at)
                 VALUES ('test-flow', 'register', 'email', 'ru', 'register@example.test', now());
             INSERT INTO account_changes(account_id, session_id, kind, previous, destination)
                 VALUES ('a0000000-0000-4000-8000-000000000001', 'test-session', 'email', 'active@example.test', 'pending@example.test'),
                        ('a0000000-0000-4000-8000-000000000001', 'test-session', 'phone', 'legacy-phone', NULL);
             INSERT INTO retired_contacts VALUES
                 ('email', contact_fingerprint('email', 'retired@example.test')),
                 ('phone', 'legacy-retired-phone');"
        ).execute(&db).await.unwrap();
        let store = Store::new(&[11; 32], "app-key");
        store.migrate(&db).await.unwrap();
        let (lookup, ciphertext, phone, tail): (String, Vec<u8>, String, Vec<u8>) = sqlx::query_as(
            "SELECT email_lookup,email_ciphertext,phone_key,phone_tail_ciphertext FROM accounts",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(lookup, store.email_lookup("ACTIVE@example.test"));
        assert!(
            store
                .open_email(
                    &store.email_lookup("other@example.test"),
                    ciphertext.clone()
                )
                .is_err()
        );
        assert_eq!(
            store.open_email(&lookup, ciphertext).unwrap(),
            "active@example.test"
        );
        assert_eq!(phone, store.phone_lookup("legacy-phone"));
        assert_eq!(store.open_phone_tail(&phone, tail).unwrap(), "0123");
        let (flow_lookup, flow_cipher): (String, Vec<u8>) = sqlx::query_as(
            "SELECT email_lookup,email_ciphertext FROM auth_flows WHERE id='test-flow'",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            store.open_email(&flow_lookup, flow_cipher).unwrap(),
            "register@example.test"
        );
        let (previous, pending, cipher): (String, String, Vec<u8>) =
            sqlx::query_as("SELECT previous,destination_lookup,destination_ciphertext FROM account_changes WHERE kind='email'")
                .fetch_one(&db).await.unwrap();
        assert_eq!(previous, lookup);
        assert_eq!(pending, store.email_lookup("pending@example.test"));
        assert_eq!(
            store.open_email(&pending, cipher).unwrap(),
            "pending@example.test"
        );
        let previous_phone: String =
            sqlx::query_scalar("SELECT previous FROM account_changes WHERE kind='phone'")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(previous_phone, phone);
        for (kind, value) in [
            ("email", store.email_lookup("retired@example.test")),
            ("phone", store.phone_lookup("legacy-retired-phone")),
        ] {
            assert!(
                sqlx::query_scalar::<_, bool>("SELECT contact_retired($1,$2)")
                    .bind(kind)
                    .bind(value)
                    .fetch_one(&db)
                    .await
                    .unwrap()
            );
        }
        let plaintext_columns: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema='public'
             AND ((table_name='accounts' AND column_name IN ('email','phone_tail'))
               OR (table_name='auth_flows' AND column_name='email')
               OR (table_name='account_changes' AND column_name='destination'))",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(plaintext_columns, 0);
        store.migrate(&db).await.unwrap();
        assert!(Store::new(&[12; 32], "app-key").migrate(&db).await.is_err());
        assert!(
            Store::new(&[11; 32], "new-app-key")
                .migrate(&db)
                .await
                .is_err()
        );
    }
}

use axum::{Json, extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use data_encoding::{BASE32_NOPAD, HEXUPPER};
use rand::{RngCore, rngs::OsRng};
use ring::hmac;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    ApiError, App, Result,
    auth::{self, EXPIRED, INVALID, UNAVAILABLE},
    profile,
};

use super::security;

const ENABLED: ApiError = ApiError(StatusCode::CONFLICT, "totp_enabled");
const DISABLED: ApiError = ApiError(StatusCode::CONFLICT, "totp_disabled");
const WRONG_CODE: ApiError = ApiError(StatusCode::BAD_REQUEST, "totp_wrong");
const WRONG_RECOVERY: ApiError = ApiError(StatusCode::BAD_REQUEST, "recovery_wrong");
const PASSWORD_CHANGED: ApiError = ApiError(StatusCode::UNAUTHORIZED, "credentials");

#[derive(sqlx::FromRow)]
pub struct Account {
    pub generation: Option<Uuid>,
    secret: Option<Vec<u8>>,
    last_step: Option<i64>,
    pub password_hash: String,
    pub review_account: bool,
    username: Option<String>,
}

pub async fn lock_account(db: &mut PgConnection, account: Uuid) -> Result<Account> {
    sqlx::query_as(
        "SELECT totp_generation AS generation, totp_secret AS secret, totp_last_step AS last_step,
                password_hash, username, review_account FROM accounts WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(account)
    .fetch_optional(db)
    .await?
    .ok_or(EXPIRED)
}

#[derive(Deserialize)]
pub struct Password {
    password: String,
}

#[derive(Serialize)]
pub struct Setup {
    generation: Uuid,
    secret: String,
    uri: String,
}

pub async fn start(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Password>,
) -> Result<Json<Setup>> {
    let account = profile::completed(&app, &jar).await?.id;
    let password_hash = security::verify(&app, account, input.password).await?;
    let session = security::session(&jar)?;
    let mut tx = app.0.db.begin().await?;
    let state = lock_account(&mut tx, account).await?;
    if state.password_hash != password_hash {
        return Err(PASSWORD_CHANGED);
    }
    if state.generation.is_some() {
        return Err(ENABLED);
    }
    let mut bytes = [0; 20];
    OsRng.fill_bytes(&mut bytes);
    let secret = BASE32_NOPAD.encode(&bytes);
    let generation = Uuid::new_v4();
    let ciphertext = app.0.contacts.seal_totp(account, generation, &secret)?;
    let inserted = sqlx::query(
        "INSERT INTO totp_enrollments (account_id,session_id,generation,secret)
         SELECT account_id,id,$3,$4 FROM sessions WHERE account_id=$1 AND id=$2 AND expires_at>now()
         ON CONFLICT (account_id) DO UPDATE SET
            session_id=EXCLUDED.session_id,generation=EXCLUDED.generation,secret=EXCLUDED.secret,
            expires_at=EXCLUDED.expires_at",
    )
    .bind(account)
    .bind(session)
    .bind(generation)
    .bind(ciphertext)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted != 1 {
        return Err(EXPIRED);
    }
    let mut uri = reqwest::Url::parse("otpauth://totp/").map_err(|_| UNAVAILABLE)?;
    uri.path_segments_mut()
        .map_err(|_| UNAVAILABLE)?
        .pop_if_empty()
        .push(&format!("Killerwave:{}", state.username.ok_or(INVALID)?));
    uri.query_pairs_mut()
        .append_pair("secret", &secret)
        .append_pair("issuer", "Killerwave");
    tx.commit().await?;
    Ok(Json(Setup {
        generation,
        secret,
        uri: uri.into(),
    }))
}

#[derive(Deserialize)]
pub struct Enrollment {
    generation: Uuid,
}

pub async fn cancel(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Enrollment>,
) -> Result<StatusCode> {
    let account = profile::completed(&app, &jar).await?.id;
    sqlx::query(
        "DELETE FROM totp_enrollments WHERE account_id=$1 AND session_id=$2 AND generation=$3",
    )
    .bind(account)
    .bind(security::session(&jar)?)
    .bind(input.generation)
    .execute(&app.0.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct Confirmation {
    generation: Uuid,
    code: String,
}

#[derive(Serialize)]
pub struct Recovery {
    recovery_codes: Vec<String>,
}

pub async fn confirm(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Confirmation>,
) -> Result<Json<Recovery>> {
    let account = profile::completed(&app, &jar).await?.id;
    let session = security::session(&jar)?;
    auth::rate(&app, &format!("totp-enroll:{account}"), 10, 600).await?;
    let mut tx = app.0.db.begin().await?;
    if lock_account(&mut tx, account).await?.generation.is_some() {
        return Err(ENABLED);
    }
    let ciphertext: Vec<u8> = sqlx::query_scalar(
        "SELECT e.secret FROM totp_enrollments e JOIN sessions s ON s.id=e.session_id
         WHERE e.account_id=$1 AND e.session_id=$2 AND e.generation=$3
           AND e.expires_at>now() AND s.expires_at>now() FOR UPDATE OF e",
    )
    .bind(account)
    .bind(&session)
    .bind(input.generation)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(EXPIRED)?;
    let secret = app
        .0
        .contacts
        .open_totp(account, input.generation, ciphertext.clone())?;
    let step = verified_step(&secret, &input.code, None)?;
    let (codes, fingerprints): (Vec<_>, Vec<_>) = (0..10)
        .map(|_| {
            let mut bytes = [0; 16];
            OsRng.fill_bytes(&mut bytes);
            let plain = HEXUPPER.encode(&bytes);
            let formatted = plain
                .as_bytes()
                .chunks_exact(4)
                .map(|group| std::str::from_utf8(group).expect("hex is ASCII"))
                .collect::<Vec<_>>()
                .join("-");
            (formatted, recovery_fingerprint(&app, account, &plain))
        })
        .unzip();
    sqlx::query(
        "UPDATE accounts SET totp_generation=$2,totp_secret=$3,totp_last_step=$4 WHERE id=$1",
    )
    .bind(account)
    .bind(input.generation)
    .bind(ciphertext)
    .bind(step)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO totp_recovery_codes (account_id,fingerprint) SELECT $1,unnest($2::text[])",
    )
    .bind(account)
    .bind(&fingerprints)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM totp_enrollments WHERE account_id=$1")
        .bind(account)
        .execute(&mut *tx)
        .await?;
    revoke_other_sessions(&mut tx, account, Some(&session)).await?;
    tx.commit().await?;
    Ok(Json(Recovery {
        recovery_codes: codes,
    }))
}

#[derive(Deserialize)]
pub struct Proof {
    code: String,
    #[serde(default)]
    recovery: bool,
}

#[derive(Deserialize)]
pub struct Disable {
    password: String,
    #[serde(flatten)]
    proof: Proof,
}

pub async fn disable(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Disable>,
) -> Result<StatusCode> {
    let account = profile::completed(&app, &jar).await?.id;
    let session = security::session(&jar)?;
    let password_hash = security::verify(&app, account, input.password).await?;
    limit(&app, account).await?;
    let mut tx = app.0.db.begin().await?;
    let state = lock_account(&mut tx, account).await?;
    if state.password_hash != password_hash {
        return Err(PASSWORD_CHANGED);
    }
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions WHERE id=$1 AND account_id=$2 AND expires_at>now())",
    )
    .bind(&session)
    .bind(account)
    .fetch_one(&mut *tx)
    .await?;
    if !live {
        return Err(EXPIRED);
    }
    check(&app, &mut tx, account, state, input.proof).await?;
    disconnect(&mut tx, account, Some(&session)).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn limit(app: &App, account: Uuid) -> Result<()> {
    auth::rate(app, &format!("totp-proof:{account}"), 10, 300).await
}

// Call under the account row lock, in the transaction that consumes the proof.
pub async fn check(
    app: &App,
    db: &mut PgConnection,
    account: Uuid,
    state: Account,
    proof: Proof,
) -> Result<bool> {
    let generation = state.generation.ok_or(DISABLED)?;
    if proof.recovery {
        let code = normalize_recovery(&proof.code).ok_or(WRONG_RECOVERY)?;
        let used =
            sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id=$1 AND fingerprint=$2")
                .bind(account)
                .bind(recovery_fingerprint(app, account, &code))
                .execute(db)
                .await?
                .rows_affected();
        if used != 1 {
            return Err(WRONG_RECOVERY);
        }
        return Ok(true);
    }
    let secret = app
        .0
        .contacts
        .open_totp(account, generation, state.secret.ok_or(UNAVAILABLE)?)?;
    let step = verified_step(&secret, &proof.code, state.last_step)?;
    sqlx::query("UPDATE accounts SET totp_last_step=$2 WHERE id=$1")
        .bind(account)
        .bind(step)
        .execute(db)
        .await?;
    Ok(false)
}

pub async fn disconnect(db: &mut PgConnection, account: Uuid, keep: Option<&str>) -> Result<()> {
    sqlx::query(
        "UPDATE accounts SET totp_generation=NULL,totp_secret=NULL,totp_last_step=NULL WHERE id=$1",
    )
    .bind(account)
    .execute(&mut *db)
    .await?;
    sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id=$1")
        .bind(account)
        .execute(&mut *db)
        .await?;
    sqlx::query("DELETE FROM auth_flows WHERE account_id=$1 AND kind='login'")
        .bind(account)
        .execute(&mut *db)
        .await?;
    revoke_other_sessions(db, account, keep).await
}

async fn revoke_other_sessions(
    db: &mut PgConnection,
    account: Uuid,
    keep: Option<&str>,
) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE account_id=$1 AND ($2::text IS NULL OR id<>$2)")
        .bind(account)
        .bind(keep)
        .execute(db)
        .await?;
    Ok(())
}

fn recovery_fingerprint(app: &App, account: Uuid, code: &str) -> String {
    auth::key(app, &format!("totp recovery:{account}"), code)
}

fn normalize_recovery(value: &str) -> Option<String> {
    if value.len() > 80 || !value.is_ascii() {
        return None;
    }
    let normalized: String = value
        .chars()
        .filter(|c| *c != '-' && !c.is_ascii_whitespace())
        .collect();
    (normalized.len() == 32 && normalized.bytes().all(|c| c.is_ascii_hexdigit()))
        .then(|| normalized.to_ascii_uppercase())
}

fn verified_step(secret: &str, code: &str, last: Option<i64>) -> Result<i64> {
    if !auth::six_digits(code) {
        return Err(WRONG_CODE);
    }
    let secret = BASE32_NOPAD
        .decode(secret.as_bytes())
        .map_err(|_| UNAVAILABLE)?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp() / 30;
    // Check the current step first and allow a one-step clock difference.
    [now, now - 1, now + 1]
        .into_iter()
        .find(|&step| {
            step >= 0
                && last.is_none_or(|last| step > last)
                && auth::code_matches(&totp_code(&secret, step as u64), Some(code))
        })
        .ok_or(WRONG_CODE)
}

fn totp_code(secret: &[u8], counter: u64) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let digest = hmac::sign(&key, &counter.to_be_bytes());
    let digest = digest.as_ref();
    let offset = usize::from(digest[digest.len() - 1] & 15);
    let slice: [u8; 4] = digest[offset..offset + 4]
        .try_into()
        .expect("valid HMAC offset");
    let number = u32::from_be_bytes(slice) & 0x7fff_ffff;
    format!("{:06}", number % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_6238_sha1_vectors_with_six_digits() {
        for (time, expected) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(totp_code(b"12345678901234567890", time / 30), expected);
        }
    }
}

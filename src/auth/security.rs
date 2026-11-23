use crate::{
    ApiError, App, Result,
    auth::{self, EXPIRED, INVALID, Lang, RATE, SESSION, UNAVAILABLE},
    profile,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use rand::{Rng, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;
const CREDENTIALS: ApiError = ApiError(StatusCode::UNAUTHORIZED, "credentials");
pub const CONTACT_UNAVAILABLE: ApiError = ApiError(StatusCode::CONFLICT, "contact_unavailable");
pub fn session(jar: &CookieJar) -> Result<String> {
    Ok(auth::digest(jar.get(SESSION).ok_or(CREDENTIALS)?.value()))
}
pub fn device(agent: Option<&str>) -> Option<String> {
    let agent = agent?;
    let browser = if agent.contains("Edg/") {
        "edge"
    } else if agent.contains("Firefox/") || agent.contains("FxiOS/") {
        "firefox"
    } else if agent.contains("Chrome/") || agent.contains("CriOS/") {
        "chrome"
    } else if agent.contains("Safari/") {
        "safari"
    } else {
        return None;
    };
    let system = if agent.contains("iPhone") || agent.contains("iPad") {
        "ios"
    } else if agent.contains("Android") {
        "android"
    } else if agent.contains("Macintosh") {
        "macos"
    } else if agent.contains("Windows") {
        "windows"
    } else if agent.contains("Linux") {
        "linux"
    } else {
        return Some(browser.into());
    };
    Some(format!("{browser} · {system}"))
}
pub(crate) async fn verify(app: &App, id: Uuid, password: String) -> Result<String> {
    if password.is_empty() || password.len() > 512 {
        return Err(CREDENTIALS);
    }
    auth::rate(app, &format!("settings-password:{id}"), 10, 900).await?;
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM accounts WHERE id=$1")
        .bind(id)
        .fetch_one(&app.0.db)
        .await?;
    let permit = app
        .0
        .hash_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| RATE)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let valid = PasswordHash::new(&hash).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        });
        valid.then_some(hash).ok_or(CREDENTIALS)
    })
    .await
    .map_err(|_| UNAVAILABLE)?
}
#[derive(Serialize, sqlx::FromRow)]
struct Device {
    id: Uuid,
    device: Option<String>,
    last_seen: i64,
    current: bool,
}
#[derive(Serialize)]
pub struct Security {
    email: Option<String>,
    phone_tail: Option<String>,
    phone_linked: bool,
    telegram_linked: bool,
    totp_enabled: bool,
    sessions: Vec<Device>,
}
pub async fn summary(State(app): State<App>, jar: CookieJar) -> Result<Json<Security>> {
    let viewer = profile::completed(&app, &jar).await?;
    let (lookup, ciphertext, phone_key, phone_ciphertext, totp_enabled, telegram_linked):
        (Option<String>, Option<Vec<u8>>, Option<String>, Option<Vec<u8>>, bool, bool) =
        sqlx::query_as("SELECT email_lookup,email_ciphertext,phone_key,phone_tail_ciphertext,totp_generation IS NOT NULL,telegram_id IS NOT NULL FROM accounts WHERE id=$1")
        .bind(viewer.id)
        .fetch_one(&app.0.db)
        .await?;
    let sessions = sqlx::query_as(
        "SELECT public_id AS id,device,extract(epoch FROM last_seen)::bigint AS last_seen,id=$2 AS current
         FROM sessions WHERE account_id=$1 AND expires_at>now() ORDER BY current DESC,last_seen DESC",
    ).bind(viewer.id).bind(session(&jar)?).fetch_all(&app.0.db).await?;
    Ok(Json(Security {
        email: lookup
            .zip(ciphertext)
            .map(|(key, data)| app.0.contacts.open_email(&key, data))
            .transpose()?,
        phone_tail: phone_key
            .as_deref()
            .zip(phone_ciphertext)
            .map(|(key, data)| app.0.contacts.open_phone_tail(key, data))
            .transpose()?,
        phone_linked: phone_key.is_some(),
        telegram_linked,
        totp_enabled,
        sessions,
    }))
}
#[derive(Deserialize)]
pub struct Revoke {
    id: Option<Uuid>,
}
pub async fn revoke(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Revoke>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    sqlx::query("DELETE FROM sessions WHERE account_id=$1 AND id<>$2 AND ($3::uuid IS NULL OR public_id=$3)")
        .bind(viewer.id).bind(session(&jar)?).bind(input.id).execute(&app.0.db).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
pub struct PasswordChange {
    password: String,
    new_password: String,
    confirmation: String,
}
pub async fn change_password(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<PasswordChange>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    if input.new_password.chars().count() < 10 || input.new_password.len() > 512 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "password_length"));
    }
    if input.new_password != input.confirmation {
        return Err(ApiError(StatusCode::BAD_REQUEST, "password_mismatch"));
    }
    let previous = verify(&app, viewer.id, input.password).await?;
    let permit = app
        .0
        .hash_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| RATE)?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth::hash_password(input.new_password.as_bytes())
    })
    .await
    .map_err(|_| UNAVAILABLE)?
    .map_err(|_| UNAVAILABLE)?;
    let mut tx = app.0.db.begin().await?;
    let updated =
        sqlx::query("UPDATE accounts SET password_hash=$2 WHERE id=$1 AND password_hash=$3")
            .bind(viewer.id)
            .bind(hash)
            .bind(previous)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if updated != 1 {
        return Err(CREDENTIALS);
    }
    sqlx::query("DELETE FROM sessions WHERE account_id=$1 AND id<>$2")
        .bind(viewer.id)
        .bind(session(&jar)?)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM auth_flows WHERE account_id=$1 AND kind='login'")
        .bind(viewer.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM totp_enrollments WHERE account_id=$1")
        .bind(viewer.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
pub struct EmailStart {
    email: String,
    password: String,
    lang: Lang,
}
#[derive(Serialize)]
pub struct Ticket {
    id: Uuid,
}
pub async fn email_start(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<EmailStart>,
) -> Result<Json<Ticket>> {
    let viewer = profile::completed(&app, &jar).await?;
    let email = auth::checked_email(&input.email)?;
    let password_hash = verify(&app, viewer.id, input.password).await?;
    auth::rate(&app, &format!("change-email:{}", viewer.id), 1, 45).await?;
    auth::rate(&app, "change-email-send", 50, 60).await?;
    let id = Uuid::new_v4();
    let code = format!("{:06}", OsRng.gen_range(0..1_000_000));
    let lookup = app.0.contacts.email_lookup(&email);
    let ciphertext = app.0.contacts.seal_email(&email, &lookup)?;
    let inserted = sqlx::query(
        "INSERT INTO account_changes(id,account_id,session_id,kind,previous,destination_lookup,destination_ciphertext,code)
         SELECT $1,id,$3,'email',email_lookup,$4,$5,$6 FROM accounts WHERE id=$2 AND password_hash=$7
           AND NOT contact_retired('email',$4) AND NOT EXISTS (SELECT 1 FROM accounts WHERE email_lookup=$4)
         ON CONFLICT (account_id,kind) DO UPDATE SET id=EXCLUDED.id,session_id=EXCLUDED.session_id,
           previous=EXCLUDED.previous,destination_lookup=EXCLUDED.destination_lookup,
           destination_ciphertext=EXCLUDED.destination_ciphertext,code=EXCLUDED.code,
           attempts=0,result=NULL,expires_at=EXCLUDED.expires_at",
    ).bind(id).bind(viewer.id).bind(session(&jar)?).bind(lookup).bind(ciphertext)
        .bind(auth::key(&app,&id.to_string(),&code)).bind(password_hash).execute(&app.0.db).await?.rows_affected();
    if inserted != 1 {
        return Err(CONTACT_UNAVAILABLE);
    }
    if let Err(error) = auth::send_email(&app, &email, &code, input.lang).await {
        sqlx::query("DELETE FROM account_changes WHERE id=$1")
            .bind(id)
            .execute(&app.0.db)
            .await?;
        return Err(error);
    }
    Ok(Json(Ticket { id }))
}
#[derive(Deserialize)]
pub struct EmailVerify {
    id: Uuid,
    code: String,
}
pub async fn email_verify(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<EmailVerify>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    if !auth::six_digits(&input.code) {
        return Err(INVALID);
    }
    let session = session(&jar)?;
    let mut tx = app.0.db.begin().await?;
    let (expected, lookup, ciphertext, previous, attempts): (String,String,Vec<u8>,Option<String>,i16) = sqlx::query_as(
        "SELECT code,destination_lookup,destination_ciphertext,previous,attempts FROM account_changes
         WHERE id=$1 AND account_id=$2 AND session_id=$3 AND kind='email' AND expires_at>now() FOR UPDATE",
    ).bind(input.id).bind(viewer.id).bind(&session).fetch_optional(&mut *tx).await?.ok_or(EXPIRED)?;
    if attempts >= 5 {
        return Err(RATE);
    }
    if !auth::code_matches(
        &auth::key(&app, &input.id.to_string(), &input.code),
        Some(&expected),
    ) {
        sqlx::query("UPDATE account_changes SET attempts=attempts+1 WHERE id=$1")
            .bind(input.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(ApiError(StatusCode::BAD_REQUEST, "code_wrong"));
    }
    contact_lock(&mut tx).await?;
    let changed = sqlx::query(
        "UPDATE accounts SET email_lookup=$2,email_ciphertext=$3 WHERE id=$1 AND email_lookup IS NOT DISTINCT FROM $4
           AND NOT contact_retired('email',$2) AND NOT EXISTS(SELECT 1 FROM accounts WHERE email_lookup=$2)",
    )
    .bind(viewer.id)
    .bind(lookup)
    .bind(ciphertext)
    .bind(&previous)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    sqlx::query("DELETE FROM account_changes WHERE id=$1")
        .bind(input.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if !changed {
        return Err(CONTACT_UNAVAILABLE);
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn contact_lock(db: &mut PgConnection) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(73460650021401)")
        .execute(db)
        .await?;
    Ok(())
}
#[derive(Deserialize)]
pub struct Password {
    password: String,
}
#[derive(Serialize)]
pub struct PhoneLink {
    id: Uuid,
    url: String,
}
pub async fn phone_start(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Password>,
) -> Result<Json<PhoneLink>> {
    let viewer = profile::completed(&app, &jar).await?;
    let bot = app
        .0
        .bot
        .as_ref()
        .ok_or(ApiError(StatusCode::SERVICE_UNAVAILABLE, "bot_unavailable"))?;
    let password_hash = verify(&app, viewer.id, input.password).await?;
    let telegram_linked: bool =
        sqlx::query_scalar("SELECT telegram_id IS NOT NULL FROM accounts WHERE id=$1")
            .bind(viewer.id)
            .fetch_one(&app.0.db)
            .await?;
    if !telegram_linked {
        return Err(ApiError(StatusCode::FORBIDDEN, "phone_requires_telegram"));
    }
    auth::rate(&app, &format!("change-phone:{}", viewer.id), 3, 60).await?;
    let id = Uuid::new_v4();
    let token = auth::token();
    let inserted = sqlx::query(
        "INSERT INTO account_changes(id,account_id,session_id,kind,previous,bot_digest)
         SELECT $1,id,$3,'phone',phone_key,$4 FROM accounts WHERE id=$2 AND password_hash=$5 AND telegram_id IS NOT NULL
         ON CONFLICT(account_id,kind) DO UPDATE SET id=EXCLUDED.id,session_id=EXCLUDED.session_id,previous=EXCLUDED.previous,
           bot_digest=EXCLUDED.bot_digest,bot_opened=false,result=NULL,expires_at=EXCLUDED.expires_at",
    ).bind(id).bind(viewer.id).bind(session(&jar)?).bind(auth::digest(&token)).bind(password_hash)
        .execute(&app.0.db).await?.rows_affected();
    if inserted != 1 {
        return Err(CREDENTIALS);
    }
    Ok(Json(PhoneLink {
        id,
        url: format!("https://t.me/{}?start=phone_{token}", bot.username),
    }))
}
#[derive(Serialize)]
pub struct PhoneStatus {
    result: Option<String>,
}
pub async fn phone_status(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<Json<PhoneStatus>> {
    let viewer = profile::completed(&app, &jar).await?;
    let result = sqlx::query_scalar(
        "SELECT result FROM account_changes WHERE id=$1 AND account_id=$2 AND session_id=$3 AND kind='phone' AND expires_at>now()",
    ).bind(id).bind(viewer.id).bind(session(&jar)?).fetch_optional(&app.0.db).await?.ok_or(EXPIRED)?;
    Ok(Json(PhoneStatus { result }))
}
pub async fn cancel_change(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    sqlx::query("DELETE FROM account_changes WHERE id=$1 AND account_id=$2 AND session_id=$3")
        .bind(id)
        .bind(viewer.id)
        .bind(session(&jar)?)
        .execute(&app.0.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn open_phone(app: &App, sender: i64, token: &str) -> Result<bool> {
    let updated = sqlx::query(
        "UPDATE account_changes c SET bot_opened=true FROM accounts a, sessions s
         WHERE c.account_id=a.id AND a.telegram_id=$1 AND a.deleted_at IS NULL AND c.bot_digest=$2 AND c.kind='phone'
          AND c.result IS NULL AND c.expires_at>now() AND c.session_id=s.id AND s.expires_at>now()",
    )
    .bind(sender)
    .bind(auth::digest(token))
    .execute(&app.0.db)
    .await?
    .rows_affected();
    Ok(updated == 1)
}
pub async fn phone_change_pending(app: &App, sender: i64) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM account_changes c JOIN accounts a ON a.id=c.account_id
            JOIN sessions s ON s.id=c.session_id
            WHERE a.telegram_id=$1 AND a.deleted_at IS NULL AND c.kind='phone' AND c.bot_opened AND c.result IS NULL
                AND c.expires_at>now() AND s.expires_at>now()
        )",
    )
    .bind(sender)
    .fetch_one(&app.0.db)
    .await?)
}
pub async fn confirm_phone(app: &App, sender: i64, phone: &str) -> Result<Option<bool>> {
    let mut tx = app.0.db.begin().await?;
    let change: Option<(Uuid,Uuid,Option<String>)> = sqlx::query_as(
        "SELECT c.id,c.account_id,c.previous FROM account_changes c JOIN accounts a ON a.id=c.account_id
           JOIN sessions s ON s.id=c.session_id
         WHERE a.telegram_id=$1 AND a.deleted_at IS NULL AND c.kind='phone' AND c.bot_opened AND c.result IS NULL
           AND c.expires_at>now() AND s.expires_at>now() FOR UPDATE OF c",
    ).bind(sender).fetch_optional(&mut *tx).await?;
    let Some((id, account, previous)) = change else {
        return Ok(None);
    };
    let new_key = app.0.contacts.phone_lookup(&auth::key(app, "phone", phone));
    let tail = app
        .0
        .contacts
        .seal_phone_tail(&phone[phone.len() - 4..], &new_key)?;
    let encrypted = app.0.contacts.seal_phone(phone, &new_key)?;
    contact_lock(&mut tx).await?;
    let changed = sqlx::query(
        "UPDATE accounts SET phone_key=$2,phone_tail_ciphertext=$3,phone_ciphertext=$5
         WHERE id=$1 AND phone_key IS NOT DISTINCT FROM $4 AND (
             ($2=$4 AND phone_ciphertext IS NULL) OR
             ($2 IS DISTINCT FROM $4 AND NOT contact_retired('phone',$2) AND NOT EXISTS(SELECT 1 FROM accounts WHERE phone_key=$2))
         )",
    ).bind(account).bind(new_key).bind(tail).bind(previous).bind(encrypted)
        .execute(&mut *tx).await?.rows_affected() == 1;
    sqlx::query(
        "UPDATE account_changes SET result=$2,bot_digest=NULL,bot_opened=false WHERE id=$1",
    )
    .bind(id)
    .bind(if changed {
        "done"
    } else {
        "contact_unavailable"
    })
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(changed))
}
pub async fn delete_account(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Password>,
) -> Result<(CookieJar, StatusCode)> {
    let viewer = profile::completed(&app, &jar).await?;
    let hash = verify(&app, viewer.id, input.password).await?;
    let deleted = sqlx::query("UPDATE accounts SET deleted_at=now() WHERE id=$1 AND password_hash=$2 AND deleted_at IS NULL AND NOT EXISTS (SELECT 1 FROM admin_roles WHERE owner AND account_id=$1)")
        .bind(viewer.id)
        .bind(hash)
        .execute(&app.0.db)
        .await?
        .rows_affected();
    if deleted != 1 {
        return Err(CREDENTIALS);
    }
    auth::logout(State(app), jar).await
}

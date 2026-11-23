pub(crate) mod contacts;
pub(crate) mod security;
pub(crate) mod totp;
use crate::{ApiError, App, Result};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng as PasswordRng},
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use lettre::{AsyncTransport, Message, message::Mailbox};
use rand::{Rng, RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
pub const INVALID: ApiError = ApiError(StatusCode::BAD_REQUEST, "invalid");
pub const EXPIRED: ApiError = ApiError(StatusCode::GONE, "expired");
pub const UNAVAILABLE: ApiError = ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
pub const RATE: ApiError = ApiError(StatusCode::TOO_MANY_REQUESTS, "rate");
pub const SESSION: &str = "kw_session";
const FLOW: &str = "kw_flow";
pub const FLOW_MINUTES: i64 = 15;
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Ru,
    En,
}
impl Lang {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ru => "ru",
            Self::En => "en",
        }
    }
}
#[derive(Serialize)]
pub struct FlowView {
    kind: String,
    stage: String,
    email: Option<String>,
    bot_url: Option<String>,
    bot_code: Option<String>,
}
#[derive(sqlx::FromRow)]
struct FlowInfo {
    kind: String,
    stage: String,
    email_lookup: Option<String>,
    email_ciphertext: Option<Vec<u8>>,
    bot_ready: bool,
    bot_needs_code: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Login,
    Register,
}
#[derive(Deserialize)]
pub struct BotStart {
    mode: Mode,
    lang: Lang,
}
#[derive(Deserialize)]
pub struct Register {
    email: String,
    password: String,
    confirmation: String,
    lang: Lang,
}
#[derive(Deserialize)]
pub struct Login {
    login: String,
    password: String,
    lang: Lang,
}
#[derive(Deserialize)]
pub struct Code {
    code: String,
}
pub(crate) fn token() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn digest(data: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(data.as_bytes()))
}
pub fn keyed(app: &App, purpose: &str, value: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(app.0.secret.as_bytes()).expect("valid hmac key");
    mac.update(purpose.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().into()
}
pub fn key(app: &App, purpose: &str, value: &str) -> String {
    URL_SAFE_NO_PAD.encode(keyed(app, purpose, value))
}
pub fn code_matches(actual: &str, expected: Option<&str>) -> bool {
    expected.is_some_and(|value| bool::from(actual.as_bytes().ct_eq(value.as_bytes())))
}
pub fn six_digits(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit())
}
pub(crate) fn cookie(
    app: &App,
    name: &'static str,
    value: String,
    seconds: i64,
) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .secure(app.0.secure)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(seconds))
        .build()
}
pub(crate) fn clear(app: &App, jar: CookieJar, name: &'static str) -> CookieJar {
    jar.remove(cookie(app, name, String::new(), 0))
}
pub fn hash_password(password: &[u8]) -> std::result::Result<String, argon2::password_hash::Error> {
    Ok(Argon2::default()
        .hash_password(password, &SaltString::generate(&mut PasswordRng))?
        .to_string())
}
pub(crate) async fn rate(app: &App, id: &str, maximum: i32, seconds: i64) -> Result<()> {
    let hits: i32 = sqlx::query_scalar(
        "INSERT INTO rate_limits(id, hits, expires_at) VALUES($1, 1, now() + $2 * interval '1 second')
         ON CONFLICT (id) DO UPDATE SET hits = CASE WHEN rate_limits.expires_at <= now() THEN 1
           ELSE LEAST(rate_limits.hits + 1, $3 + 1) END,
           expires_at = CASE WHEN rate_limits.expires_at <= now() THEN EXCLUDED.expires_at ELSE rate_limits.expires_at END
         RETURNING hits",
    ).bind(key(app, "rate", id)).bind(seconds).bind(maximum).fetch_one(&app.0.db).await?;
    if hits > maximum {
        return Err(RATE);
    }
    Ok(())
}
pub(crate) fn checked_email(input: &str) -> Result<String> {
    let email = input.trim().to_ascii_lowercase();
    if email.len() > 254
        || !email.is_ascii()
        || !email.contains('.')
        || email.parse::<lettre::Address>().is_err()
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "email_invalid"));
    }
    Ok(email)
}
pub fn username(value: &str) -> Option<String> {
    let count = value.chars().count();
    if !(3..=54).contains(&count) || !value.chars().all(|ch| {
        matches!(
            ch, 'a'..='z' | 'A'..='Z' | 'а'..='я' | 'А'..='Я' | 'ё' | 'Ё' | '0'..='9' | '-' | '_'
        )
    }) {
        return None;
    }
    Some(value.to_lowercase())
}
pub async fn register(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Register>,
) -> Result<(CookieJar, Json<FlowView>)> {
    let email = checked_email(&input.email)?;
    if input.password.chars().count() < 10 || input.password.len() > 512 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "password_length"));
    }
    if input.password != input.confirmation {
        return Err(ApiError(StatusCode::BAD_REQUEST, "password_mismatch"));
    }
    rate(&app, "registration send budget", 50, 60).await?;
    rate(&app, &format!("register:{email}"), 1, 45).await?;
    let retired: bool = sqlx::query_scalar("SELECT contact_retired('email',$1)")
        .bind(app.0.contacts.email_lookup(&email))
        .fetch_one(&app.0.db)
        .await?;
    if retired {
        return Err(security::CONTACT_UNAVAILABLE);
    }
    let permit = app
        .0
        .hash_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| RATE)?;
    let password_hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(input.password.as_bytes())
    })
    .await
    .map_err(|_| UNAVAILABLE)?
    .map_err(|_| UNAVAILABLE)?;
    let attempt = EmailAttempt {
        kind: "register",
        email,
        lang: input.lang,
        password_hash: Some(password_hash),
        account_id: None,
    };
    begin_email(&app, jar, attempt).await
}
pub async fn login(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Login>,
) -> Result<(CookieJar, Json<FlowView>)> {
    let raw = input.login.trim();
    let (identity, email_login) = if let Some(handle) = raw.strip_prefix('@') {
        (username(handle).ok_or(INVALID)?, false)
    } else if raw.contains('@') {
        (app.0.contacts.email_lookup(&checked_email(raw)?), true)
    } else {
        (username(raw).ok_or(INVALID)?, false)
    };
    if input.password.is_empty() || input.password.len() > 512 {
        return Err(INVALID);
    }
    rate(&app, "login budget", 100, 60).await?;
    rate(&app, &format!("login:{identity}"), 12, 900).await?;
    let account: Option<(Uuid, Option<String>, Option<Vec<u8>>, String)> = sqlx::query_as(
        "SELECT id, email_lookup, email_ciphertext, password_hash FROM accounts
         WHERE deleted_at IS NULL AND (($2 AND email_lookup=$1) OR (NOT $2 AND username=$1))",
    )
    .bind(&identity)
    .bind(email_login)
    .fetch_optional(&app.0.db)
    .await?;
    let hash = account
        .as_ref()
        .map_or_else(|| app.0.dummy_hash.clone(), |row| row.3.clone());
    let checked_hash = hash.clone();
    let permit = app
        .0
        .hash_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| RATE)?;
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        PasswordHash::new(&hash).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(input.password.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await
    .map_err(|_| UNAVAILABLE)?;
    let (id, lookup, ciphertext, _) = account
        .filter(|_| valid)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "credentials"))?;
    let mut tx = app.0.db.begin().await?;
    let state = totp::lock_account(&mut tx, id).await?;
    if state.password_hash != checked_hash {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "credentials"));
    }
    if state.generation.is_some() || state.review_account {
        let (jar, flow) =
            begin_login_flow(&app, &mut tx, jar, id, state.generation, input.lang).await?;
        tx.commit().await?;
        return Ok((jar, Json(flow)));
    }
    tx.commit().await?;
    let email = app.0.contacts.open_email(
        lookup.as_deref().ok_or(UNAVAILABLE)?,
        ciphertext.ok_or(UNAVAILABLE)?,
    )?;
    rate(&app, &format!("login-send:{id}"), 1, 45).await?;
    let attempt = EmailAttempt {
        kind: "login",
        email,
        lang: input.lang,
        password_hash: None,
        account_id: Some(id),
    };
    begin_email(&app, jar, attempt).await
}
pub(crate) async fn begin_login_flow(
    app: &App,
    db: &mut sqlx::PgConnection,
    jar: CookieJar,
    account: Uuid,
    generation: Option<Uuid>,
    lang: Lang,
) -> Result<(CookieJar, FlowView)> {
    if let Some(old) = jar.get(FLOW) {
        sqlx::query("DELETE FROM auth_flows WHERE id=$1")
            .bind(digest(old.value()))
            .execute(&mut *db)
            .await?;
    }
    let ticket = token();
    let stage = if generation.is_some() {
        "totp"
    } else {
        "ready"
    };
    sqlx::query(
        "INSERT INTO auth_flows(id,kind,stage,lang,account_id,totp_generation,expires_at)
         VALUES($1,'login',$2,$3,$4,$5,now() + $6 * interval '1 minute')",
    )
    .bind(digest(&ticket))
    .bind(stage)
    .bind(lang.as_str())
    .bind(account)
    .bind(generation)
    .bind(FLOW_MINUTES)
    .execute(db)
    .await?;
    Ok((
        jar.add(cookie(app, FLOW, ticket, 60 * FLOW_MINUTES)),
        FlowView {
            kind: "login".into(),
            stage: stage.into(),
            email: None,
            bot_url: None,
            bot_code: None,
        },
    ))
}
pub async fn verify_totp(
    State(app): State<App>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(proof): Json<totp::Proof>,
) -> Result<(CookieJar, StatusCode)> {
    let id = digest(jar.get(FLOW).ok_or(EXPIRED)?.value());
    let account: Uuid = sqlx::query_scalar(
        "SELECT account_id FROM auth_flows WHERE id=$1 AND stage='totp' AND expires_at>now()",
    )
    .bind(&id)
    .fetch_optional(&app.0.db)
    .await?
    .ok_or(EXPIRED)?;
    totp::limit(&app, account).await?;
    let mut tx = app.0.db.begin().await?;
    let state = totp::lock_account(&mut tx, account).await?;
    let generation = state.generation.ok_or(EXPIRED)?;
    let active: Option<String> = sqlx::query_scalar(
        "SELECT id FROM auth_flows WHERE id=$1 AND account_id=$2 AND totp_generation=$3
         AND stage='totp' AND expires_at>now() FOR UPDATE",
    )
    .bind(id)
    .bind(account)
    .bind(generation)
    .fetch_optional(&mut *tx)
    .await?;
    if active.is_none() {
        return Err(EXPIRED);
    }
    if totp::check(&app, &mut tx, account, state, proof).await? {
        totp::disconnect(&mut tx, account, None).await?;
    }
    let jar = create_session(&app, &mut tx, jar, account, &headers).await?;
    tx.commit().await?;
    Ok((jar, StatusCode::NO_CONTENT))
}
struct EmailAttempt {
    kind: &'static str,
    email: String,
    lang: Lang,
    password_hash: Option<String>,
    account_id: Option<Uuid>,
}
async fn begin_email(
    app: &App,
    jar: CookieJar,
    attempt: EmailAttempt,
) -> Result<(CookieJar, Json<FlowView>)> {
    let ticket = token();
    let id = digest(&ticket);
    let code = format!("{:06}", OsRng.gen_range(0..1_000_000));
    let lookup = app.0.contacts.email_lookup(&attempt.email);
    let ciphertext = app.0.contacts.seal_email(&attempt.email, &lookup)?;
    sqlx::query(
        "INSERT INTO auth_flows(id,kind,stage,lang,email_lookup,email_ciphertext,password_hash,account_id,email_code,expires_at)
         VALUES ($1,$2,'email',$3,$4,$5,$6,$7,$8,now() + $9 * interval '1 minute')",
    ).bind(&id).bind(attempt.kind).bind(attempt.lang.as_str()).bind(&lookup).bind(&ciphertext)
        .bind(attempt.password_hash).bind(attempt.account_id)
        .bind(key(app, &id, &code)).bind(FLOW_MINUTES)
        .execute(&app.0.db).await?;
    if send_email(app, &attempt.email, &code, attempt.lang)
        .await
        .is_err()
    {
        sqlx::query("DELETE FROM auth_flows WHERE id=$1")
            .bind(&id)
            .execute(&app.0.db)
            .await?;
        return Err(UNAVAILABLE);
    }
    drop_old_flow(app, &jar).await?;
    let view = flow_view(
        app,
        &ticket,
        FlowInfo {
            kind: attempt.kind.into(),
            stage: "email".into(),
            email_lookup: Some(lookup),
            email_ciphertext: Some(ciphertext),
            bot_ready: false,
            bot_needs_code: false,
        },
    )?;
    Ok((
        jar.add(cookie(app, FLOW, ticket, 60 * FLOW_MINUTES)),
        Json(view),
    ))
}
pub(crate) async fn send_email(app: &App, email: &str, code: &str, lang: Lang) -> Result<()> {
    let copy = &app.0.translations.get(lang.as_str()).email;
    let body = copy
        .body
        .replace("{code}", code)
        .replace("{minutes}", &FLOW_MINUTES.to_string());
    let message = Message::builder()
        .from(app.0.sender.clone())
        .to(email.parse::<Mailbox>().map_err(|_| INVALID)?)
        .subject(&copy.subject)
        .body(body)
        .map_err(|_| UNAVAILABLE)?;
    app.0.mailer.send(message).await.map_err(|error| {
        eprintln!(
            "email delivery failed: smtp_status={:?} tls={} timeout={}",
            error.status(),
            error.is_tls(),
            error.is_timeout()
        );
        UNAVAILABLE
    })?;
    Ok(())
}
fn flow_view(app: &App, ticket: &str, flow: FlowInfo) -> Result<FlowView> {
    let bot = app
        .0
        .bot
        .as_ref()
        .filter(|_| flow.stage == "telegram" && flow.bot_ready);
    let email = match (flow.email_lookup, flow.email_ciphertext) {
        (Some(lookup), Some(ciphertext)) => {
            Some(mask_email(&app.0.contacts.open_email(&lookup, ciphertext)?))
        }
        (None, None) => None,
        _ => return Err(UNAVAILABLE),
    };
    Ok(FlowView {
        kind: flow.kind,
        stage: flow.stage,
        email,
        bot_code: bot
            .filter(|_| flow.bot_needs_code)
            .map(|_| bot_code(app, ticket)),
        bot_url: bot.map(|bot| {
            format!(
                "https://t.me/{}?start={}",
                bot.username,
                key(app, "telegram link", ticket)
            )
        }),
    })
}
fn mask_email(email: &str) -> String {
    let (name, domain) = email.rsplit_once('@').unwrap_or(("", ""));
    format!("{}•••@{domain}", name.chars().next().unwrap_or('•'))
}
pub async fn current_flow(app: &App, jar: &CookieJar) -> Result<Option<FlowView>> {
    let Some(ticket) = jar.get(FLOW).map(|cookie| cookie.value()) else {
        return Ok(None);
    };
    let flow = sqlx::query_as(
        "SELECT kind, stage, email_lookup, email_ciphertext, telegram_key IS NOT NULL AS bot_ready, telegram_code IS NOT NULL AS bot_needs_code FROM auth_flows WHERE id=$1 AND expires_at>now()",
    )
    .bind(digest(ticket))
    .fetch_optional(&app.0.db)
    .await?;
    flow.map(|flow| flow_view(app, ticket, flow)).transpose()
}
#[derive(sqlx::FromRow)]
struct EmailChallenge {
    #[sqlx(flatten)]
    flow: FlowInfo,
    email_code: Option<String>,
    email_attempts: i16,
}
pub async fn verify_email(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Code>,
) -> Result<Json<FlowView>> {
    if !six_digits(&input.code) {
        return Err(INVALID);
    }
    let ticket = jar.get(FLOW).ok_or(EXPIRED)?.value();
    let id = digest(ticket);
    let mut tx = app.0.db.begin().await?;
    let challenge: EmailChallenge =
        sqlx::query_as("SELECT kind, stage, email_lookup, email_ciphertext,
            email_code, email_attempts, telegram_key IS NOT NULL AS bot_ready,
            telegram_code IS NOT NULL AS bot_needs_code FROM auth_flows WHERE id=$1 AND expires_at>now() FOR UPDATE")
            .bind(&id).fetch_optional(&mut *tx).await?.ok_or(EXPIRED)?;
    let mut flow = challenge.flow;
    if flow.stage != "email" {
        return Ok(Json(flow_view(&app, ticket, flow)?));
    }
    if challenge.email_attempts >= 5 {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "code_locked"));
    }
    if !code_matches(
        &key(&app, &id, &input.code),
        challenge.email_code.as_deref(),
    ) {
        sqlx::query("UPDATE auth_flows SET email_attempts=email_attempts+1 WHERE id=$1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Err(ApiError(StatusCode::BAD_REQUEST, "code_wrong"));
    }
    let stage = if flow.kind == "register" {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE email_lookup=$1) OR contact_retired('email',$1)",
        )
        .bind(flow.email_lookup.as_deref().ok_or(UNAVAILABLE)?)
        .fetch_one(&mut *tx)
        .await?;
        if exists { "conflict" } else { "telegram" }
    } else {
        "ready"
    };
    sqlx::query("UPDATE auth_flows SET stage=$2, email_code=NULL WHERE id=$1")
        .bind(&id)
        .bind(stage)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    flow.stage = stage.into();
    flow.bot_ready = false;
    flow.bot_needs_code = false;
    Ok(Json(flow_view(&app, ticket, flow)?))
}
pub(crate) async fn pending_registration(app: &App, jar: &CookieJar) -> Result<String> {
    let id = digest(jar.get(FLOW).ok_or(EXPIRED)?.value());
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_flows WHERE id=$1 AND kind='register'
         AND stage='telegram' AND expires_at>now())",
    )
    .bind(&id)
    .fetch_one(&app.0.db)
    .await?;
    if !pending {
        return Err(EXPIRED);
    }
    Ok(id)
}
pub(crate) async fn confirm_telegram_registration(
    app: &App,
    jar: &CookieJar,
    registration: &str,
    telegram_id: i64,
) -> Result<FlowView> {
    let ticket = jar.get(FLOW).ok_or(EXPIRED)?.value();
    if digest(ticket) != registration {
        return Err(EXPIRED);
    }
    let link = key(app, "telegram link", ticket);
    let flow: FlowInfo = sqlx::query_as(
        "UPDATE auth_flows SET telegram_sender=$2, telegram_key=$3, paired=false, telegram_code=NULL,
           telegram_language_selected=false, telegram_attempts=0
         WHERE id=$1 AND kind='register' AND stage='telegram' AND expires_at>now()
         RETURNING kind, stage, email_lookup, email_ciphertext, true AS bot_ready, false AS bot_needs_code",
    )
    .bind(registration)
    .bind(telegram_id)
    .bind(digest(&link))
    .fetch_optional(&app.0.db)
    .await?
    .ok_or(EXPIRED)?;
    flow_view(app, ticket, flow)
}
fn bot_code(app: &App, ticket: &str) -> String {
    let hash = keyed(app, "telegram bot code", ticket);
    let number = u64::from_be_bytes(hash[..8].try_into().unwrap()) % 1_000_000;
    format!("{number:06}")
}
pub async fn start_telegram_fallback(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<BotStart>,
) -> Result<(CookieJar, Json<FlowView>)> {
    if app.0.bot.is_none() {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "bot_unavailable"));
    }
    rate(&app, "telegram bot budget", 100, 60).await?;
    let jar = crate::telegram::web::cancel(&app, jar).await?;
    let ticket = match input.mode {
        Mode::Register => jar.get(FLOW).ok_or(EXPIRED)?.value().to_owned(),
        Mode::Login => token(),
    };
    let browser_key = digest(&ticket);
    let link = digest(&key(&app, "telegram link", &ticket));
    let code = key(&app, &link, &bot_code(&app, &ticket));
    let flow = match input.mode {
        Mode::Register => {
            sqlx::query_as(
                "UPDATE auth_flows SET lang=$2, telegram_key=$3, telegram_code=$4,
                   telegram_sender=NULL, paired=false, telegram_language_selected=false, telegram_attempts=0
                 WHERE id=$1 AND kind='register' AND stage='telegram' AND expires_at>now()
                 RETURNING kind, stage, email_lookup, email_ciphertext, true AS bot_ready, true AS bot_needs_code",
            ).bind(browser_key).bind(input.lang.as_str()).bind(link).bind(code)
                .fetch_optional(&app.0.db).await?.ok_or(EXPIRED)?
        }
        Mode::Login => {
            drop_old_flow(&app, &jar).await?;
            sqlx::query_as(
                "INSERT INTO auth_flows(id, kind, stage, lang, telegram_key, telegram_code, expires_at)
                 VALUES($1, 'login', 'telegram', $2, $3, $4, now() + $5 * interval '1 minute')
                 RETURNING kind, stage, email_lookup, email_ciphertext, true AS bot_ready, true AS bot_needs_code",
            ).bind(browser_key).bind(input.lang.as_str()).bind(link).bind(code).bind(FLOW_MINUTES)
                .fetch_one(&app.0.db).await?
        }
    };
    let jar = match input.mode {
        Mode::Register => jar,
        Mode::Login => jar.add(cookie(&app, FLOW, ticket.clone(), 60 * FLOW_MINUTES)),
    };
    Ok((jar, Json(flow_view(&app, &ticket, flow)?)))
}
#[derive(Serialize)]
pub struct Completion {
    stage: String,
    bot_needs_code: bool,
}
pub async fn complete(
    State(app): State<App>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<(CookieJar, Json<Completion>)> {
    let ticket = jar.get(FLOW).ok_or(EXPIRED)?.value();
    let id = digest(ticket);
    let (stage, account_id, bot_needs_code): (String, Option<Uuid>, bool) = sqlx::query_as(
        "SELECT stage, account_id, telegram_code IS NOT NULL FROM auth_flows f
         WHERE f.id=$1 AND f.expires_at>now() AND (f.kind <> 'login' OR f.email_lookup IS NULL OR EXISTS (
            SELECT 1 FROM accounts a WHERE a.id=f.account_id AND a.email_lookup=f.email_lookup AND a.deleted_at IS NULL))",
    )
    .bind(&id)
    .fetch_optional(&app.0.db)
    .await?
    .ok_or(EXPIRED)?;
    if stage != "ready" {
        return Ok((
            jar,
            Json(Completion {
                stage,
                bot_needs_code,
            }),
        ));
    }
    let account = account_id.ok_or(UNAVAILABLE)?;
    let mut tx = app.0.db.begin().await?;
    let state = totp::lock_account(&mut tx, account).await?;
    let active: Option<String> = sqlx::query_scalar(
        "SELECT f.id FROM auth_flows f WHERE f.id=$1 AND f.account_id=$2 AND f.stage='ready'
         AND f.expires_at>now() AND (f.kind <> 'login' OR f.email_lookup IS NULL OR EXISTS (
            SELECT 1 FROM accounts a WHERE a.id=f.account_id AND a.email_lookup=f.email_lookup AND a.deleted_at IS NULL))
         FOR UPDATE",
    )
    .bind(&id)
    .bind(account)
    .fetch_optional(&mut *tx)
    .await?;
    if active.is_none() {
        return Err(EXPIRED);
    }
    if let Some(generation) = state.generation {
        sqlx::query(
            "UPDATE auth_flows SET kind='login',stage='totp',totp_generation=$2 WHERE id=$1",
        )
        .bind(&id)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok((
            jar,
            Json(Completion {
                stage: "totp".into(),
                bot_needs_code: false,
            }),
        ));
    }
    let jar = create_session(&app, &mut tx, jar, account, &headers).await?;
    tx.commit().await?;
    Ok((
        jar,
        Json(Completion {
            stage,
            bot_needs_code,
        }),
    ))
}
pub(crate) async fn create_session(
    app: &App,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    jar: CookieJar,
    account_id: Uuid,
    headers: &HeaderMap,
) -> Result<CookieJar> {
    let session = token();
    if let Some(old) = jar.get(SESSION) {
        sqlx::query("DELETE FROM sessions WHERE id=$1")
            .bind(digest(old.value()))
            .execute(&mut **tx)
            .await?;
    }
    let inserted=sqlx::query("INSERT INTO sessions(id,account_id,device) SELECT $1,id,$3 FROM accounts WHERE id=$2 AND deleted_at IS NULL")
        .bind(digest(&session))
        .bind(account_id)
        .bind(security::device(
            headers
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
        ))
        .execute(&mut **tx)
        .await?.rows_affected();
    if inserted == 0 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "credentials"));
    }
    if let Some(old_flow) = jar.get(FLOW) {
        sqlx::query("DELETE FROM auth_flows WHERE id=$1")
            .bind(digest(old_flow.value()))
            .execute(&mut **tx)
            .await?;
    }
    Ok(clear(app, jar, FLOW).add(cookie(app, SESSION, session, 30 * 86400)))
}
async fn drop_old_flow(app: &App, jar: &CookieJar) -> Result<()> {
    if let Some(ticket) = jar.get(FLOW) {
        sqlx::query("DELETE FROM auth_flows WHERE id=$1")
            .bind(digest(ticket.value()))
            .execute(&app.0.db)
            .await?;
    }
    Ok(())
}
pub async fn cancel(State(app): State<App>, jar: CookieJar) -> Result<(CookieJar, StatusCode)> {
    drop_old_flow(&app, &jar).await?;
    let jar = crate::telegram::web::cancel(&app, jar).await?;
    Ok((clear(&app, jar, FLOW), StatusCode::NO_CONTENT))
}
pub async fn logout(State(app): State<App>, jar: CookieJar) -> Result<(CookieJar, StatusCode)> {
    if let Some(session) = jar.get(SESSION) {
        sqlx::query("DELETE FROM sessions WHERE id=$1")
            .bind(digest(session.value()))
            .execute(&app.0.db)
            .await?;
    }
    cancel(State(app.clone()), clear(&app, jar, SESSION)).await
}

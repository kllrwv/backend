mod delivery;
use crate::{
    ApiError, App, Result,
    auth::{self, INVALID, security},
    profile,
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
pub(crate) use delivery::run;
use serde::{Deserialize, Serialize};
use std::{env, time::Duration};
use web_push_native::{
    Auth, WebPushBuilder,
    jwt_simple::algorithms::ES256KeyPair,
    p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint},
};
const DISABLED: ApiError = ApiError(StatusCode::SERVICE_UNAVAILABLE, "push_unavailable");
pub struct Service {
    key: ES256KeyPair,
    public_key: String,
    subject: String,
    http: reqwest::Client,
}
impl Service {
    pub fn from_env(origin: &str) -> anyhow::Result<Option<Self>> {
        let Some(value) = env::var("WEB_PUSH_PRIVATE_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };
        let bytes = URL_SAFE_NO_PAD.decode(value.trim())?;
        let secret = SecretKey::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid web push private key"))?;
        let key = ES256KeyPair::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid web push signing key"))?;
        let public_key =
            URL_SAFE_NO_PAD.encode(secret.public_key().to_encoded_point(false).as_bytes());
        let subject = if origin.starts_with("https://") {
            origin.to_owned()
        } else {
            let mailbox: lettre::message::Mailbox = env::var("SMTP_FROM")?.parse()?;
            format!("mailto:{}", mailbox.email)
        };
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(9))
            .build()?;
        Ok(Some(Self {
            key,
            public_key,
            subject,
            http,
        }))
    }
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/api/push", get(state))
        .route("/api/push/subscribe", post(subscribe))
        .route("/api/push/unsubscribe", post(unsubscribe))
        .route("/api/push/preferences", post(update_preference))
        .route("/api/push/test", post(test))
}
#[derive(Serialize, sqlx::FromRow)]
struct Preferences {
    activity: bool,
    following: bool,
    recommendations: bool,
    reminders: bool,
}
#[derive(Serialize)]
struct DeviceState {
    public_key: Option<String>,
    connected: bool,
    lang: Option<String>,
    preferences: Preferences,
}
async fn state(State(app): State<App>, jar: CookieJar) -> Result<Json<DeviceState>> {
    let viewer = profile::completed(&app, &jar).await?;
    let preferences = sqlx::query_as("SELECT activity,following,recommendations,reminders FROM web_push_preferences WHERE account_id=$1")
        .bind(viewer.id).fetch_optional(&app.0.db).await?
        .unwrap_or(Preferences { activity: true, following: true, recommendations: false, reminders: false });
    let lang: Option<String> = sqlx::query_scalar(
        "SELECT lang FROM web_push_subscriptions WHERE session_id=$1 AND account_id=$2",
    )
    .bind(security::session(&jar)?)
    .bind(viewer.id)
    .fetch_optional(&app.0.db)
    .await?;
    Ok(Json(DeviceState {
        public_key: app
            .0
            .push
            .as_ref()
            .map(|service| service.public_key.clone()),
        connected: lang.is_some(),
        lang,
        preferences,
    }))
}
#[derive(Deserialize)]
struct Keys {
    p256dh: String,
    auth: String,
}
#[derive(Deserialize)]
struct Subscription {
    endpoint: String,
    keys: Keys,
    lang: auth::Lang,
}
fn endpoint(value: &str) -> Option<reqwest::Url> {
    if value.len() > 2048 {
        return None;
    }
    let url = reqwest::Url::parse(value).ok()?;
    let host = url.host_str()?;
    let supported = matches!(
        host,
        "fcm.googleapis.com" | "android.googleapis.com" | "updates.push.services.mozilla.com"
    ) || host.ends_with(".push.apple.com")
        || host.ends_with(".notify.windows.com");
    (supported
        && url.scheme() == "https"
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.path().len() > 1)
        .then_some(url)
}
fn browser_keys(p256dh: &str, auth: &str) -> Option<(PublicKey, Auth)> {
    if p256dh.len() != 87 || auth.len() != 22 {
        return None;
    }
    let key = URL_SAFE_NO_PAD.decode(p256dh).ok()?;
    let authentication: [u8; 16] = URL_SAFE_NO_PAD.decode(auth).ok()?.try_into().ok()?;
    Some((
        PublicKey::from_sec1_bytes(&key).ok()?,
        authentication.into(),
    ))
}
async fn subscribe(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Subscription>,
) -> Result<StatusCode> {
    app.0.push.as_ref().ok_or(DISABLED)?;
    let viewer = profile::completed(&app, &jar).await?;
    let url = endpoint(&input.endpoint).ok_or(INVALID)?;
    browser_keys(&input.keys.p256dh, &input.keys.auth).ok_or(INVALID)?;
    auth::rate(&app, &format!("web-push-subscribe:{}", viewer.id), 12, 60).await?;
    let session = security::session(&jar)?;
    let mut tx = app.0.db.begin().await?;
    sqlx::query("INSERT INTO web_push_preferences(account_id) VALUES($1) ON CONFLICT DO NOTHING")
        .bind(viewer.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM web_push_subscriptions WHERE (session_id=$1 AND endpoint<>$2) OR (endpoint=$2 AND session_id<>$1)")
        .bind(&session).bind(url.as_str()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO web_push_subscriptions(session_id,account_id,endpoint,p256dh,auth,lang) VALUES($1,$2,$3,$4,$5,$6)
                 ON CONFLICT(session_id) DO UPDATE SET p256dh = EXCLUDED.p256dh,
                     auth = EXCLUDED.auth, lang = EXCLUDED.lang")
        .bind(session).bind(viewer.id).bind(url.as_str()).bind(input.keys.p256dh).bind(input.keys.auth).bind(input.lang.as_str())
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn unsubscribe(State(app): State<App>, jar: CookieJar) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    sqlx::query("DELETE FROM web_push_subscriptions WHERE session_id=$1 AND account_id=$2")
        .bind(security::session(&jar)?)
        .bind(viewer.id)
        .execute(&app.0.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PreferenceKind {
    Activity,
    Following,
    Recommendations,
    Reminders,
}
#[derive(Deserialize)]
struct Preference {
    kind: PreferenceKind,
    enabled: bool,
}
async fn update_preference(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Preference>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    let column = match input.kind {
        PreferenceKind::Activity => "activity",
        PreferenceKind::Following => "following",
        PreferenceKind::Recommendations => "recommendations",
        PreferenceKind::Reminders => "reminders",
    };
    sqlx::query(&format!("INSERT INTO web_push_preferences(account_id,{column}) VALUES($1,$2) ON CONFLICT(account_id) DO UPDATE SET {column}=$2"))
        .bind(viewer.id).bind(input.enabled).execute(&app.0.db).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn test(State(app): State<App>, jar: CookieJar) -> Result<StatusCode> {
    app.0.push.as_ref().ok_or(DISABLED)?;
    let viewer = profile::completed(&app, &jar).await?;
    let session = security::session(&jar)?;
    auth::rate(&app, &format!("web-push-test:{}", viewer.id), 1, 30).await?;
    let result = sqlx::query("INSERT INTO web_push_jobs(session_id,kind) SELECT session_id,'test' FROM web_push_subscriptions WHERE session_id=$1 AND account_id=$2")
        .bind(session).bind(viewer.id).execute(&app.0.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "push_disconnected"));
    }
    Ok(StatusCode::NO_CONTENT)
}

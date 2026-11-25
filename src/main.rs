mod admin;
mod auth;
mod locale;
mod media;
mod profile;
mod social;
mod status;
mod telegram;
use auth::{contacts, security, totp};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use lettre::{
    AsyncSmtpTransport, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use profile::community;
use serde_json::json;
use social::{discovery, poll};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{env, sync::Arc, time::Duration};
use telegram::{support, web};
use tokio::sync::Semaphore;
#[derive(Clone)]
struct App(Arc<Config>);
struct Config {
    db: PgPool,
    origin: String,
    secure: bool,
    secret: String,
    contacts: contacts::Store,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    sender: Mailbox,
    translations: locale::Translations,
    bot: Option<telegram::Bot>,
    support_chat: Option<i64>,
    telegram_web: Option<web::Provider>,
    hash_slots: Arc<Semaphore>,
    image_slots: Arc<Semaphore>,
    upload_slots: Semaphore,
    media: Option<media::Store>,
    dummy_hash: String,
    admin: admin::Settings,
}
#[derive(Debug)]
struct ApiError(StatusCode, &'static str);
type Result<T> = std::result::Result<T, ApiError>;
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        eprintln!(
            "database operation failed: {}",
            error
                .as_database_error()
                .and_then(|e| e.code())
                .as_deref()
                .unwrap_or("connection or query error")
        );
        Self(StatusCode::INTERNAL_SERVER_ERROR, "unavailable")
    }
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let origin = env::var("APP_ORIGIN")?;
    let parsed_origin = reqwest::Url::parse(&origin)?;
    let secure = parsed_origin.scheme() == "https";
    anyhow::ensure!(
        parsed_origin.origin().ascii_serialization() == origin
            && (secure
                || (parsed_origin.scheme() == "http"
                    && matches!(
                        parsed_origin.host_str(),
                        Some("localhost" | "127.0.0.1" | "[::1]")
                    ))),
        "APP_ORIGIN must be the exact https origin, or an http loopback origin for local development"
    );
    let secret = env::var("APP_SECRET")?;
    anyhow::ensure!(
        secret.len() == 64 && secret.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "set APP_SECRET using openssl rand -hex 32"
    );
    let contacts = contacts::Store::from_hex(&env::var("CONTACT_SECRET")?, &secret)?;
    let mut smtp = match env::var("SMTP_MODE")?.as_str() {
        "starttls" => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&env::var("SMTP_HOST")?)?
        }
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&env::var("SMTP_HOST")?)?,
        "plain" if !secure => {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(env::var("SMTP_HOST")?)
        }
        _ => anyhow::bail!("SMTP_MODE must be tls or starttls, or plain for local development"),
    };
    if let Ok(user) = env::var("SMTP_USER")
        && !user.is_empty()
    {
        smtp = smtp.credentials(Credentials::new(user, env::var("SMTP_PASSWORD")?));
    }
    let db = PgPoolOptions::new()
        .max_connections(12)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&env::var("DATABASE_URL")?)
        .await?;
    sqlx::migrate!().run(&db).await?;
    contacts.migrate(&db).await?;
    let bot = match env::var("TELEGRAM_BOT_TOKEN")
        .ok()
        .filter(|token| !token.is_empty())
    {
        Some(token) => Some(telegram::Bot::connect(token).await?),
        None if secure => anyhow::bail!("TELEGRAM_BOT_TOKEN is required with an https origin"),
        None => {
            eprintln!("telegram is disabled until TELEGRAM_BOT_TOKEN is configured");
            None
        }
    };
    let app = App(Arc::new(Config {
        db,
        origin,
        secure,
        secret,
        contacts,
        mailer: smtp
            .port(env::var("SMTP_PORT")?.parse()?)
            .timeout(Some(Duration::from_secs(8)))
            .build(),
        sender: env::var("SMTP_FROM")?.parse()?,
        translations: locale::Translations::load()?,
        bot,
        support_chat: support::chat_from_env()?,
        telegram_web: web::Provider::from_env()?,
        hash_slots: Arc::new(Semaphore::new(4)),
        image_slots: Arc::new(Semaphore::new(2)),
        upload_slots: Semaphore::new(2),
        media: media::Store::from_env(secure)?,
        dummy_hash: auth::hash_password(b"unused password")
            .map_err(|_| anyhow::anyhow!("password hashing initialization failed"))?,
        admin: admin::Settings::from_env(&parsed_origin)?,
    }));
    admin::bootstrap(&app).await?;
    if let Some(bot) = app.0.bot.clone() {
        tokio::spawn(telegram::poll(app.clone(), bot));
        tokio::spawn(admin::deliver_audit(app.clone()));
    }
    tokio::spawn(cleanup(app.clone()));
    tokio::spawn(status::monitor(app.clone()));
    tokio::spawn(media::collect(app.clone()));
    tokio::spawn(media::measure(app.clone()));
    tokio::spawn(admin::dispatch(app.clone()));
    let listener = tokio::net::TcpListener::bind(env::var("API_BIND")?).await?;
    println!("killerwave api on {}", listener.local_addr()?);
    axum::serve(listener, router(app)).await?;
    Ok(())
}
fn router(app: App) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/email", post(auth::verify_email))
        .route("/api/auth/totp", post(auth::verify_totp))
        .route(
            "/api/auth/telegram/bot",
            post(auth::start_telegram_fallback),
        )
        .route("/api/auth/telegram/web", post(web::start))
        .route("/api/auth/telegram/confirm", post(web::confirm))
        .route("/api/auth/complete", post(auth::complete))
        .route("/api/auth/cancel", post(auth::cancel))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/me", get(profile::me))
        .route(
            "/api/profile",
            post(profile::save).layer(DefaultBodyLimit::max(5 * 1024 * 1024 + 16 * 1024)),
        )
        .route("/api/profile/avatar", get(profile::avatar))
        .route("/api/profiles/{handle}", get(community::view))
        .route("/api/accounts/{id}/connections/{direction}", get(community::connections))
        .route("/api/accounts/{id}/banner", get(community::banner))
        .route("/api/accounts/{id}/block", post(community::block))
        .route(
            "/api/profile/banner",
            post(community::upload_banner)
                .layer(DefaultBodyLimit::max(media::IMAGE_LIMIT + 16 * 1024)),
        )
        .route("/api/profile/banner/remove", post(community::remove_banner))
        .route("/api/profile/presence", post(community::presence))
        .route("/api/notifications", get(community::notices))
        .route("/api/notifications/read", post(community::read_notices))
        .route(
            "/api/settings/preferences",
            get(community::preferences).post(community::set_preference),
        )
        .route("/api/settings/blocked", get(community::blocked))
        .route("/api/settings/usernames", get(profile::aliases::own).post(profile::aliases::toggle))
        .route("/api/settings/security", get(security::summary))
        .route("/api/settings/totp/start", post(totp::start))
        .route("/api/settings/totp/confirm", post(totp::confirm))
        .route("/api/settings/totp/cancel", post(totp::cancel))
        .route("/api/settings/totp/disable", post(totp::disable))
        .route("/api/settings/sessions/revoke", post(security::revoke))
        .route("/api/settings/password", post(security::change_password))
        .route("/api/settings/email", post(security::email_start))
        .route("/api/settings/email/verify", post(security::email_verify))
        .route("/api/settings/phone", post(security::phone_start))
        .route("/api/settings/phone/{id}", get(security::phone_status))
        .route(
            "/api/settings/contact/{id}/cancel",
            post(security::cancel_change),
        )
        .route(
            "/api/settings/account/delete",
            post(security::delete_account),
        )
        .route("/api/feed", get(social::feed))
        .route("/api/discover", get(discovery::search))
        .route(
            "/api/posts",
            post(social::publish).layer(DefaultBodyLimit::max(media::POST_LIMIT + 32 * 1024)),
        )
        .route("/api/posts/{id}", get(social::post))
        .route("/api/posts/{id}/like", post(social::like))
        .route("/api/posts/{id}/view", post(social::watch))
        .route("/api/posts/{id}/delete", post(social::delete_post))
        .route("/api/posts/{id}/image", get(social::image))
        .route("/api/posts/{id}/media/{position}", get(social::attachment))
        .route("/api/posts/{id}/vote", post(poll::vote))
        .route("/api/avatars/{id}", get(social::author_avatar))
        .route("/api/accounts/{id}/follow", post(social::follow))
        .route("/api/status", get(status::show))
        .merge(admin::routes())
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), browser_request))
        .with_state(app)
}
async fn health(State(app): State<App>) -> StatusCode {
    let ready = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query("SELECT 1").execute(&app.0.db),
    )
    .await;
    match ready {
        Ok(Ok(_)) => StatusCode::NO_CONTENT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
async fn browser_request(State(app): State<App>, request: Request, next: Next) -> Response {
    let admin_path = request.uri().path().starts_with("/api/admin/");
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    let expected = if admin_path {
        app.0.admin.origin.as_deref()
    } else {
        Some(app.0.origin.as_str())
    };
    if !matches!(*request.method(), Method::GET | Method::HEAD)
        && (origin.is_none() || origin != expected)
    {
        return ApiError(StatusCode::FORBIDDEN, "origin").into_response();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
}
async fn cleanup(app: App) {
    let mut interval = tokio::time::interval(Duration::from_secs(600));
    loop {
        interval.tick().await;
        for query in [
            "DELETE FROM auth_flows WHERE expires_at <= now()",
            "DELETE FROM totp_enrollments WHERE expires_at <= now()",
            "DELETE FROM account_changes WHERE expires_at <= now()",
            "DELETE FROM telegram_web_flows WHERE expires_at <= now()",
            "DELETE FROM sessions WHERE expires_at <= now()",
            "DELETE FROM rate_limits WHERE expires_at <= now()",
            "DELETE FROM telegram_support_deliveries WHERE delivered_at < now() - interval '3 days'",
            "DELETE FROM admin_logins WHERE expires_at <= now()",
            "DELETE FROM admin_sessions WHERE expires_at <= now()",
            "UPDATE admin_events SET undo=NULL WHERE undo IS NOT NULL AND created_at <= now()-interval '30 days'",
        ] {
            if sqlx::query(query).execute(&app.0.db).await.is_err() {
                eprintln!("expired authentication data cleanup failed");
            }
        }
    }
}

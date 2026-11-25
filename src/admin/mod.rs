mod accounts;
mod aliases;
mod audit;
mod audit_message;
mod moderation;
mod ops;
use crate::{ApiError, App, Result, auth, profile};
pub(crate) use audit::deliver_audit;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
};
use axum_extra::extract::CookieJar;
pub(crate) use ops::dispatch;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::{env, path::PathBuf};
use uuid::Uuid;
pub const PERMISSIONS: &[&str] = &[
    "accounts.read",
    "accounts.review.create",
    "accounts.contacts.read",
    "accounts.profile.write",
    aliases::PERMISSION,
    "accounts.badge",
    "accounts.contacts.write",
    "accounts.telegram.write",
    "accounts.password.reset",
    "accounts.sessions.revoke",
    "accounts.totp.reset",
    "accounts.lifecycle",
    "content.moderate",
    "reports.review",
    "admins.read",
    "admins.grant",
    "ops.read",
    "ops.env.write",
    "ops.restart",
    "audit.read",
    "audit.undo",
];
const ADMIN_COOKIE: &str = "kw_admin";
const DENIED: ApiError = ApiError(StatusCode::FORBIDDEN, "admin_denied");
const SIGN_IN: ApiError = ApiError(StatusCode::UNAUTHORIZED, "sign_in_required");
const CONFLICT: ApiError = ApiError(StatusCode::CONFLICT, "admin_conflict");
const MISSING: ApiError = ApiError(StatusCode::NOT_FOUND, "admin_missing");
#[derive(Default)]
pub struct Settings {
    pub origin: Option<String>,
    bootstrap: Option<Uuid>,
    audit_chat: Option<i64>,
    ops_dir: Option<PathBuf>,
}
impl Settings {
    #[cfg(test)]
    pub fn for_test() -> Self {
        Self {
            origin: Some("http://localhost:3001".into()),
            ..Self::default()
        }
    }
    pub fn from_env(site: &reqwest::Url) -> anyhow::Result<Self> {
        let read = |key| env::var(key).ok().filter(|s| !s.is_empty());
        let origin = read("ADMIN_ORIGIN");
        if let Some(origin) = &origin {
            let url = reqwest::Url::parse(origin)?;
            anyhow::ensure!(
                url.origin().ascii_serialization() == *origin
                    && url.scheme() == site.scheme()
                    && url.origin() != site.origin()
                    && (url.scheme() == "https"
                        || matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))),
                "ADMIN_ORIGIN must be a separate HTTPS origin or a separate loopback origin for development"
            );
        }
        let bootstrap = read("ADMIN_BOOTSTRAP_ACCOUNT_ID")
            .map(|v| v.parse())
            .transpose()?;
        let audit_chat = read("TELEGRAM_ADMIN_CHAT_ID")
            .map(|v| v.parse())
            .transpose()?;
        anyhow::ensure!(
            audit_chat.is_none_or(|v| v < 0),
            "TELEGRAM_ADMIN_CHAT_ID must be a negative supergroup ID"
        );
        Ok(Self {
            origin,
            bootstrap,
            audit_chat,
            ops_dir: read("ADMIN_OPS_DIR").map(PathBuf::from),
        })
    }
}
pub async fn bootstrap(app: &App) -> anyhow::Result<()> {
    if let Some(id) = app.0.admin.bootstrap {
        sqlx::query(
            "INSERT INTO admin_roles(account_id,owner,permissions)
             SELECT id,true,$2 FROM accounts WHERE id=$1 AND deleted_at IS NULL AND NOT review_account
               AND NOT EXISTS (SELECT 1 FROM admin_roles WHERE owner)
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(PERMISSIONS)
        .execute(&app.0.db)
        .await?;
    }
    Ok(())
}
#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct Actor {
    id: Uuid,
    name: String,
    owner: bool,
    permissions: Vec<String>,
}
impl Actor {
    pub fn allows(&self, permission: &str) -> bool {
        self.owner || self.permissions.iter().any(|v| v == permission)
    }
    fn require(&self, permission: &str) -> Result<()> {
        if self.allows(permission) {
            Ok(())
        } else {
            Err(DENIED)
        }
    }
}
async fn current_role(db: &mut PgConnection, id: Uuid) -> Result<Actor> {
    sqlx::query_as(
        "SELECT a.id,coalesce(a.username,a.id::text) AS name,r.owner,r.permissions
         FROM admin_roles r JOIN accounts a ON a.id=r.account_id
         WHERE r.account_id=$1 AND a.deleted_at IS NULL AND NOT a.review_account
           AND (r.owner OR cardinality(r.permissions)>0)",
    )
    .bind(id)
    .fetch_optional(db)
    .await?
    .ok_or(DENIED)
}
async fn allows_target(db: &mut PgConnection, actor: &Actor, target: Uuid) -> Result<()> {
    let privileges: Option<(bool, Vec<String>)> =
        sqlx::query_as("SELECT owner, permissions FROM admin_roles WHERE account_id=$1")
            .bind(target)
            .fetch_optional(db)
            .await?;
    if privileges.is_some_and(|(owner, perms)| {
        (owner && actor.id != target) || perms.iter().any(|p| !actor.allows(p))
    }) {
        return Err(DENIED);
    }
    Ok(())
}
async fn mutate(
    pool: &PgPool,
    actor: &Actor,
    permit: &str,
) -> Result<(Transaction<'static, Postgres>, Actor)> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(73460650021402)")
        .execute(&mut *tx)
        .await?;
    let actor = current_role(&mut tx, actor.id).await?;
    actor.require(permit)?;
    Ok((tx, actor))
}
async fn panel_actor(app: &App, jar: &CookieJar, permission: Option<&str>) -> Result<Actor> {
    let cookie = jar.get(ADMIN_COOKIE).ok_or(SIGN_IN)?;
    let mut db = app.0.db.acquire().await?;
    let id = sqlx::query_scalar(
        "SELECT s.account_id FROM admin_sessions x JOIN sessions s ON s.id=x.session_id
         WHERE x.digest=$1 AND x.expires_at>now() AND s.expires_at>now()",
    )
    .bind(auth::digest(cookie.value()))
    .fetch_optional(&mut *db)
    .await?
    .ok_or(SIGN_IN)?;
    let actor = current_role(&mut db, id).await?;
    if let Some(p) = permission {
        actor.require(p)?;
    }
    Ok(actor)
}
#[derive(Serialize)]
struct Access {
    origin: Option<String>,
    moderate: bool,
    manage_accounts: bool,
}
async fn access(State(app): State<App>, jar: CookieJar) -> Result<Json<Access>> {
    let viewer = profile::completed(&app, &jar).await?;
    let mut db = app.0.db.acquire().await?;
    let actor = current_role(&mut db, viewer.id).await;
    let role = match actor {
        Ok(role) => Some(role),
        Err(ApiError(StatusCode::FORBIDDEN, _)) => None,
        Err(error) => return Err(error),
    };
    Ok(Json(Access {
        origin: role.as_ref().and(app.0.admin.origin.clone()),
        moderate: role.as_ref().is_some_and(|a| a.allows("content.moderate")),
        manage_accounts: role
            .as_ref()
            .is_some_and(|a| a.allows("accounts.lifecycle")),
    }))
}
async fn start(State(app): State<App>, jar: CookieJar) -> Result<Redirect> {
    let origin = app.0.admin.origin.as_ref().ok_or(MISSING)?;
    let viewer = profile::completed(&app, &jar).await?;
    let session = auth::security::session(&jar)?;
    let mut tx = app.0.db.begin().await?;
    current_role(&mut tx, viewer.id).await?;
    let ticket = auth::token();
    sqlx::query("INSERT INTO admin_logins(digest,session_id) VALUES($1,$2)")
        .bind(auth::digest(&ticket))
        .bind(session)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let path = if origin.starts_with("http://") {
        "/control"
    } else {
        "/"
    };
    Ok(Redirect::to(&format!("{origin}{path}?ticket={ticket}")))
}
#[derive(Deserialize)]
struct Ticket {
    ticket: String,
}
async fn claim(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Ticket>,
) -> Result<(CookieJar, Json<Actor>)> {
    if input.ticket.len() != 43 {
        return Err(SIGN_IN);
    }
    let mut tx = app.0.db.begin().await?;
    let linked: (String, Uuid) = sqlx::query_as(
        "DELETE FROM admin_logins l USING sessions s WHERE l.digest=$1 AND s.id=l.session_id
         AND s.expires_at>now() AND l.expires_at>now() RETURNING s.id,s.account_id",
    )
    .bind(auth::digest(&input.ticket))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(SIGN_IN)?;
    let actor = current_role(&mut tx, linked.1).await?;
    let token = auth::token();
    sqlx::query("INSERT INTO admin_sessions(digest,session_id) VALUES($1,$2)")
        .bind(auth::digest(&token))
        .bind(linked.0)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((
        jar.add(auth::cookie(&app, ADMIN_COOKIE, token, 8 * 3600)),
        Json(actor),
    ))
}
async fn whoami(State(app): State<App>, jar: CookieJar) -> Result<Json<Actor>> {
    Ok(Json(panel_actor(&app, &jar, None).await?))
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/api/mod/access", get(access))
        .route(
            "/api/mod/{kind}/{id}/delete",
            post(moderation::social_delete),
        )
        .route("/api/reports", post(moderation::file))
        .route("/api/admin/session/start", get(start))
        .route("/api/admin/session/claim", post(claim))
        .route("/api/admin/session", get(whoami))
        .route(
            "/api/admin/accounts",
            get(accounts::list).post(accounts::create_review),
        )
        .route(
            "/api/admin/accounts/{id}",
            get(accounts::details).post(accounts::edit),
        )
        .route(
            "/api/admin/accounts/{id}/avatar",
            get(accounts::avatar)
                .post(accounts::upload_avatar)
                .layer(DefaultBodyLimit::max(crate::media::IMAGE_LIMIT + 16 * 1024)),
        )
        .route("/api/admin/roles", get(accounts::roles))
        .route("/api/admin/accounts/{id}/usernames", get(aliases::list).post(aliases::edit))
        .route("/api/admin/roles/{id}", post(accounts::assign))
        .route("/api/admin/reports", get(moderation::queue))
        .route("/api/admin/reports/{id}/review", post(moderation::review))
        .route(
            "/api/admin/targets/{kind}/{id}/delete",
            post(moderation::panel_delete),
        )
        .route(
            "/api/admin/reports/{id}/media/{part}",
            get(moderation::report_media),
        )
        .route("/api/admin/audit", get(audit::history))
        .route("/api/admin/audit/{id}/undo", post(audit::undo))
        .route("/api/admin/server", get(ops::status))
        .route("/api/admin/server/restart", post(ops::restart))
        .route("/api/admin/server/env", post(ops::environment))
}

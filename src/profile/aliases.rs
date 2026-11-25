use crate::{ApiError, App, Result, auth, profile};
use axum::{Json, extract::State, http::StatusCode};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use uuid::Uuid;
pub const MISSING: ApiError = ApiError(StatusCode::NOT_FOUND, "alias_missing");
pub const TAKEN: ApiError = ApiError(StatusCode::CONFLICT, "username_taken");
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, sqlx::FromRow)]
pub struct Alias {
    pub username: String,
    pub enabled: bool,
}
pub fn normalize(value: &str) -> Result<String> {
    let value = value.trim();
    auth::username(value.strip_prefix('@').unwrap_or(value))
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "username_invalid"))
}
pub fn assignable(value: &str) -> Result<String> {
    let username = normalize(value)?;
    if username.starts_with("control") || matches!(username.as_str(), "api" | "notifications" | "search" | "privacy" | "terms" | "status") {
        return Err(ApiError(StatusCode::BAD_REQUEST, "username_reserved"));
    }
    Ok(username)
}
pub async fn list(db: &mut PgConnection, id: Uuid) -> Result<Vec<Alias>> {
    Ok(sqlx::query_as("SELECT username,enabled FROM account_usernames WHERE account_id=$1 AND slot>0 ORDER BY slot")
        .bind(id).fetch_all(db).await?)
}
pub async fn own(State(app): State<App>, jar: CookieJar) -> Result<Json<Vec<Alias>>> {
    let viewer = profile::completed(&app, &jar).await?;
    Ok(Json(list(&mut *app.0.db.acquire().await?, viewer.id).await?))
}
#[derive(Deserialize)]
pub struct Toggle {
    username: String,
    enabled: bool,
}
pub async fn toggle(State(app): State<App>, jar: CookieJar, Json(input): Json<Toggle>) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    let affected = sqlx::query("UPDATE account_usernames SET enabled=$3 WHERE account_id=$1 AND username=$2 AND slot>0")
        .bind(viewer.id).bind(normalize(&input.username)?).bind(input.enabled).execute(&app.0.db).await?;
    if affected.rows_affected() == 0 {
        return Err(MISSING);
    }
    Ok(StatusCode::NO_CONTENT)
}
pub fn conflict(error: sqlx::Error) -> ApiError {
    if error.as_database_error().is_some_and(|e| e.is_unique_violation()) {
        TAKEN
    } else {
        error.into()
    }
}

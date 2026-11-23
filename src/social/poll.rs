use std::collections::HashSet;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{ApiError, App, Result, profile};

const INVALID_POLL: ApiError = ApiError(StatusCode::BAD_REQUEST, "poll_invalid");
const MISSING: ApiError = ApiError(StatusCode::NOT_FOUND, "poll_missing");
const CLOSED: ApiError = ApiError(StatusCode::CONFLICT, "poll_closed");

#[derive(Deserialize)]
pub struct Draft {
    question: String,
    options: Vec<String>,
    duration: Option<i32>,
}

impl Draft {
    pub fn parse(raw: &str) -> Result<Self> {
        let mut value: Self = serde_json::from_str(raw).map_err(|_| INVALID_POLL)?;
        value.question = value.question.trim().to_owned();
        if !valid_text(&value.question, 140)
            || !matches!(value.duration, None | Some(1 | 24 | 72 | 168))
            || !(2..=6).contains(&value.options.len())
        {
            return Err(INVALID_POLL);
        }
        let mut options = HashSet::new();
        for option in &mut value.options {
            *option = option.trim().to_owned();
            if !valid_text(option, 80) || !options.insert(option.to_lowercase()) {
                return Err(INVALID_POLL);
            }
        }
        Ok(value)
    }

    pub async fn insert(self, db: &mut PgConnection, id: Uuid) -> Result<()> {
        sqlx::query("INSERT INTO polls(post_id,question,ends_at) VALUES($1,$2,now() + make_interval(hours => $3))")
            .bind(id).bind(self.question).bind(self.duration).execute(&mut *db).await?;
        sqlx::query(
            "INSERT INTO poll_options(post_id,position,label)
             SELECT $1, (i - 1)::smallint, label FROM unnest($2::text[]) WITH ORDINALITY AS opt(label,i)",
        )
        .bind(id).bind(self.options).execute(&mut *db).await?;
        Ok(())
    }
}

fn valid_text(text: &str, limit: usize) -> bool {
    !text.is_empty() && text.chars().count() <= limit && !text.chars().any(char::is_control)
}

#[derive(Deserialize)]
pub struct Vote {
    option: i16,
}

pub async fn vote(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Json(input): Json<Vote>,
) -> Result<Json<Value>> {
    let viewer = profile::completed(&app, &jar).await?;
    let mut tx = app.0.db.begin().await?;
    let open: bool = sqlx::query_scalar(
        "SELECT ends_at IS NULL OR ends_at > clock_timestamp() FROM polls WHERE post_id=$1 AND deleted_at IS NULL AND visible_post(post_id,$2) FOR KEY SHARE",
    )
    .bind(id)
    .bind(viewer.id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(MISSING)?;
    if !open {
        return Err(CLOSED);
    }
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM poll_options WHERE post_id=$1 AND position=$2)",
    )
    .bind(id)
    .bind(input.option)
    .fetch_one(&mut *tx)
    .await?;
    if !valid {
        return Err(INVALID_POLL);
    }
    sqlx::query(
        "INSERT INTO poll_votes(post_id,voter_id,position) VALUES($1,$2,$3)
         ON CONFLICT (post_id,voter_id) DO NOTHING",
    )
    .bind(id)
    .bind(viewer.id)
    .bind(input.option)
    .execute(&mut *tx)
    .await?;
    let result = sqlx::query_scalar("SELECT poll_view($1,$2)")
        .bind(id)
        .bind(viewer.id)
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(result))
}

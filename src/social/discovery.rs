use crate::{App, Result, auth::INVALID, profile};
use axum::{
    Json,
    extract::{Query, State},
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
}
#[derive(Serialize, sqlx::FromRow)]
struct Tag {
    tag: String,
    posts: i64,
}
#[derive(Serialize, sqlx::FromRow)]
struct Person {
    id: Uuid,
    username: String,
    matched_username: Option<String>,
    name: String,
    avatar: bool,
    verified: bool,
    deleted: bool,
    followed: bool,
    mine: bool,
}
#[derive(Serialize)]
pub struct Discovery {
    tags: Vec<Tag>,
    people: Vec<Person>,
}
pub async fn search(
    State(app): State<App>,
    jar: CookieJar,
    Query(input): Query<SearchQuery>,
) -> Result<Json<Discovery>> {
    let viewer = profile::completed(&app, &jar).await?;
    let term = input.q.trim().to_lowercase();
    if term.chars().count() > 100 {
        return Err(INVALID);
    }
    let tags = if term.starts_with('@') {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT tag, count(*) AS posts FROM post_hashtags
             WHERE ($1 = '' OR strpos(tag, $1) > 0) AND visible_post(post_id,$2)
             GROUP BY tag ORDER BY (tag = $1) DESC, (strpos(tag, $1) = 1) DESC, posts DESC, tag
             LIMIT 10",
        )
        .bind(term.strip_prefix('#').unwrap_or(&term).trim())
        .bind(viewer.id)
        .fetch_all(&app.0.db)
        .await?
    };
    let people = if term.is_empty() || term.starts_with('#') || term == "@" {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT a.id, a.username, nullif(matched.username,a.username) AS matched_username, display_name AS name,
                    NOT avatar_hidden AND (avatar IS NOT NULL OR avatar_object_id IS NOT NULL) AS avatar, id = $2 AS mine,
                    verified, deleted_at IS NOT NULL AS deleted,
                    EXISTS(SELECT 1 FROM follows WHERE follower_id = $2 AND followed_id = a.id) AS followed
             FROM accounts a LEFT JOIN LATERAL (
                SELECT h.username FROM account_usernames h
                WHERE h.account_id=a.id AND h.enabled AND (h.slot=0 OR a.deleted_at IS NULL) AND strpos(h.username,$1)>0
                ORDER BY (h.username=$1) DESC, (strpos(h.username,$1)=1) DESC, h.slot LIMIT 1
             ) matched ON true WHERE a.username IS NOT NULL AND display_name IS NOT NULL
              AND NOT accounts_blocked(id,$2)
              AND (deleted_at IS NULL OR admin_can($2,'accounts.lifecycle') OR admin_can($2,'accounts.read'))
              AND (matched.username IS NOT NULL OR ($3 AND strpos(lower(display_name), $1) > 0))
             ORDER BY (matched.username=$1) DESC NULLS LAST, (lower(display_name)=$1) DESC,
                      (strpos(matched.username,$1)=1) DESC NULLS LAST, a.username, a.id LIMIT 20",
        )
        .bind(term.strip_prefix('@').unwrap_or(&term)).bind(viewer.id).bind(!term.starts_with('@'))
        .fetch_all(&app.0.db).await?
    };
    Ok(Json(Discovery { tags, people }))
}
pub fn normalized_tag(tag: &str) -> Result<String> {
    let tag = tag
        .trim()
        .strip_prefix('#')
        .unwrap_or(tag.trim())
        .to_lowercase();
    if tag.chars().count() > 54 || !tag.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(INVALID);
    }
    Ok(tag)
}

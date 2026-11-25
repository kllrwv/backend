use crate::{
    ApiError, App, Result,
    auth::{INVALID, security},
    media, profile,
    social::Enabled,
};
use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
const MISSING: ApiError = ApiError(StatusCode::NOT_FOUND, "profile_unavailable");
#[derive(Serialize, sqlx::FromRow)]
pub struct View {
    id: Uuid,
    username: String,
    name: String,
    bio: String,
    avatar: bool,
    verified: bool,
    deleted: bool,
    banner: Option<Uuid>,
    mine: bool,
    followed: bool,
    following: i64,
    followers: i64,
    joined: i64,
    last_seen: Option<i64>,
    can_write: bool,
    can_see_likes: bool,
    theme: Option<String>,
}
pub async fn view(
    State(app): State<App>,
    jar: CookieJar,
    Path(handle): Path<String>,
) -> Result<Json<View>> {
    let viewer = profile::completed(&app, &jar).await?;
    let target_id = Uuid::parse_str(&handle).ok();
    let handle = handle.strip_prefix('@').unwrap_or(&handle).to_lowercase();
    let view = sqlx::query_as(
        "SELECT a.id, a.username, a.display_name AS name, a.bio,
          NOT a.avatar_hidden AND (a.avatar IS NOT NULL OR a.avatar_object_id IS NOT NULL) AS avatar,
          a.verified,a.deleted_at IS NOT NULL AS deleted, CASE WHEN NOT a.banner_hidden THEN a.banner_object_id END AS banner,
          a.id=v.id AS mine,
          EXISTS (SELECT 1 FROM follows WHERE follower_id=v.id AND followed_id=a.id) AS followed,
          (SELECT count(*) FROM follows WHERE follower_id=a.id) AS following,
          (SELECT count(*) FROM follows WHERE followed_id=a.id) AS followers,
          extract(epoch FROM a.created_at)::bigint AS joined,
          CASE WHEN a.show_online AND v.show_online THEN extract(epoch FROM a.last_seen)::bigint END AS last_seen,
          audience_allows(a.id,v.id,a.wall_access) AS can_write,
          audience_allows(a.id,v.id,a.like_access) AS can_see_likes,
          CASE WHEN a.id=v.id THEN a.theme END AS theme
         FROM accounts a JOIN accounts v ON v.id=$1 WHERE a.username IS NOT NULL
          AND ($2='me' AND a.id=v.id OR $2<>'me' AND (a.id=$3 OR a.username=$2))
          AND NOT accounts_blocked(a.id,v.id)
          AND (a.deleted_at IS NULL OR admin_can(v.id,'accounts.lifecycle') OR admin_can(v.id,'accounts.read') OR admin_can(v.id,'content.moderate'))
         ORDER BY (a.id=$3) DESC NULLS LAST LIMIT 1",
    ).bind(viewer.id).bind(handle).bind(target_id).fetch_optional(&app.0.db).await?.ok_or(MISSING)?;
    Ok(Json(view))
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionDirection {
    Followers,
    Following,
}
#[derive(Deserialize)]
pub struct ConnectionQuery {
    after: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct Connection {
    id: Uuid,
    username: String,
    name: String,
    avatar: bool,
    verified: bool,
    mine: bool,
    followed: bool,
    followers: i64,
}
#[derive(Serialize)]
pub struct ConnectionPage {
    accounts: Vec<Connection>,
    next: Option<String>,
}
pub async fn connections(
    State(app): State<App>,
    jar: CookieJar,
    Path((id, direction)): Path<(Uuid, ConnectionDirection)>,
    Query(input): Query<ConnectionQuery>,
) -> Result<Json<ConnectionPage>> {
    const PAGE_SIZE: usize = 30;
    let viewer = profile::completed(&app, &jar).await?;
    let (after_count, after_id) = match input.after {
        Some(cursor) => {
            let (count, id) = cursor.split_once(':').ok_or(INVALID)?;
            let count = count.parse::<i64>().ok().filter(|count| *count >= 0).ok_or(INVALID)?;
            let id = Uuid::parse_str(id).map_err(|_| INVALID)?;
            (Some(count), Some(id))
        }
        None => (None, None),
    };
    let sqlx::types::Json(mut accounts): sqlx::types::Json<Vec<Connection>> =
        sqlx::query_scalar(include_str!("connections.sql"))
            .bind(id)
            .bind(viewer.id)
            .bind(matches!(direction, ConnectionDirection::Followers))
            .bind(after_count)
            .bind(after_id)
            .bind((PAGE_SIZE + 1) as i64)
            .fetch_optional(&app.0.db)
            .await?
            .ok_or(MISSING)?;
    let has_more = accounts.len() > PAGE_SIZE;
    accounts.truncate(PAGE_SIZE);
    let next = accounts.last().filter(|_| has_more).map(|last| format!("{}:{}", last.followers, last.id));
    Ok(Json(ConnectionPage { accounts, next }))
}
pub async fn block(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Json(input): Json<Enabled>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    if id == viewer.id {
        return Err(INVALID);
    }
    let mut tx = app.0.db.begin().await?;
    if input.enabled {
        sqlx::query(
            "INSERT INTO account_blocks(blocker,blocked)
             SELECT $1,id FROM accounts WHERE id=$2 AND username IS NOT NULL ON CONFLICT DO NOTHING",
        ).bind(viewer.id).bind(id).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM follows WHERE (follower_id,followed_id) IN (($1,$2),($2,$1))")
            .bind(viewer.id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM notifications WHERE (recipient,actor) IN (($1,$2),($2,$1))")
            .bind(viewer.id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("DELETE FROM account_blocks WHERE blocker=$1 AND blocked=$2")
            .bind(viewer.id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Serialize, sqlx::FromRow)]
pub struct Blocked {
    id: Uuid,
    username: String,
    name: String,
}
pub async fn blocked(State(app): State<App>, jar: CookieJar) -> Result<Json<Vec<Blocked>>> {
    let viewer = profile::completed(&app, &jar).await?;
    let list = sqlx::query_as(
        "SELECT a.id,a.username,a.display_name AS name
         FROM account_blocks b JOIN accounts a ON a.id=b.blocked
         WHERE b.blocker=$1 ORDER BY a.username",
    )
    .bind(viewer.id)
    .fetch_all(&app.0.db)
    .await?;
    Ok(Json(list))
}
pub async fn banner(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response> {
    let viewer = profile::completed(&app, &jar).await?;
    let object = sqlx::query_scalar(
        "SELECT banner_object_id FROM accounts WHERE id=$1 AND username IS NOT NULL
         AND banner_object_id IS NOT NULL AND NOT accounts_blocked(id,$2)
         AND ((deleted_at IS NULL AND NOT banner_hidden) OR admin_can($2,'content.moderate'))",
    )
    .bind(id)
    .bind(viewer.id)
    .fetch_optional(&app.0.db)
    .await?
    .ok_or(MISSING)?;
    media::serve(&app, object, "image/webp", &headers).await
}
pub async fn upload_banner(
    State(app): State<App>,
    jar: CookieJar,
    mut multipart: Multipart,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    let part = multipart
        .next_field()
        .await
        .map_err(|_| INVALID)?
        .ok_or(INVALID)?;
    if part.name() != Some("banner") {
        return Err(INVALID);
    }
    let bytes = media::read(part, media::IMAGE_LIMIT, media::INVALID_MEDIA).await?;
    if multipart.next_field().await.map_err(|_| INVALID)?.is_some() {
        return Err(INVALID);
    }
    let upload = media::photo(&app, bytes, false, media::INVALID_MEDIA).await?;
    let object = media::stage(&app, &upload).await?;
    let mut tx = app.0.db.begin().await?;
    media::retain(&mut tx, object).await?;
    sqlx::query("UPDATE accounts SET banner_object_id=$2 WHERE id=$1")
        .bind(viewer.id)
        .bind(object)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn remove_banner(State(app): State<App>, jar: CookieJar) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    sqlx::query(
        "UPDATE accounts SET banner_object_id=NULL WHERE id=$1 AND banner_object_id IS NOT NULL",
    )
    .bind(viewer.id)
    .execute(&app.0.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Serialize, sqlx::FromRow)]
pub struct Preferences {
    theme: String,
    wall_access: String,
    like_access: String,
    message_access: String,
    show_online: bool,
    notice_preferences: Value,
}
pub async fn preferences(State(app): State<App>, jar: CookieJar) -> Result<Json<Preferences>> {
    let viewer = profile::completed(&app, &jar).await?;
    let value = sqlx::query_as(
        "SELECT theme,wall_access,like_access,message_access,show_online,notice_preferences FROM accounts WHERE id=$1",
    ).bind(viewer.id).fetch_one(&app.0.db).await?;
    Ok(Json(value))
}
#[derive(Deserialize)]
#[serde(tag = "key", content = "value", rename_all = "snake_case")]
pub enum Preference {
    Theme(String),
    WallAccess(String),
    LikeAccess(String),
    MessageAccess(String),
    ShowOnline(bool),
    Notice { kind: String, enabled: bool },
}
pub async fn set_preference(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Preference>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    let (column, value) = match input {
        Preference::ShowOnline(value) => {
            sqlx::query("UPDATE accounts SET show_online=$2 WHERE id=$1")
                .bind(viewer.id)
                .bind(value)
                .execute(&app.0.db)
                .await?;
            return Ok(StatusCode::NO_CONTENT);
        }
        Preference::Notice { kind, enabled } => {
            if !matches!(
                kind.as_str(),
                "all" | "sound" | "messages" | "follow" | "wall" | "like" | "reply" | "mention"
            ) {
                return Err(INVALID);
            }
            sqlx::query("UPDATE accounts SET notice_preferences=notice_preferences || jsonb_build_object($2::text,$3::boolean) WHERE id=$1")
                .bind(viewer.id).bind(kind).bind(enabled).execute(&app.0.db).await?;
            return Ok(StatusCode::NO_CONTENT);
        }
        Preference::Theme(value) if matches!(value.as_str(), "dark" | "light" | "system") => {
            ("theme", value)
        }
        Preference::Theme(_) => return Err(INVALID),
        Preference::WallAccess(value) => ("wall_access", value),
        Preference::LikeAccess(value) => ("like_access", value),
        Preference::MessageAccess(value) => ("message_access", value),
    };
    if column != "theme" && !matches!(value.as_str(), "everyone" | "followers" | "nobody") {
        return Err(INVALID);
    }
    sqlx::query(&format!("UPDATE accounts SET {column}=$2 WHERE id=$1"))
        .bind(viewer.id)
        .bind(value)
        .execute(&app.0.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn presence(
    State(app): State<App>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    sqlx::query(
        "WITH active AS (
           UPDATE sessions SET last_seen=now(), device=coalesce(device,$3)
           WHERE id=$1 AND account_id=$2 AND (device IS NULL OR last_seen<now()-interval '45 seconds') RETURNING account_id
         )
         UPDATE accounts SET last_seen=now() WHERE id IN (SELECT account_id FROM active)
           AND (last_seen IS NULL OR last_seen<now()-interval '45 seconds')",
    ).bind(security::session(&jar)?).bind(viewer.id)
        .bind(security::device(headers.get(header::USER_AGENT).and_then(|value| value.to_str().ok())))
        .execute(&app.0.db).await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
pub struct NoticeQuery {
    before: Option<i64>,
    #[serde(default)]
    summary: bool,
}
#[derive(Serialize, sqlx::FromRow)]
struct Notice {
    id: i64,
    kind: String,
    actor: Uuid,
    name: String,
    username: String,
    avatar: bool,
    target: Uuid,
    post_id: Option<Uuid>,
    post_username: Option<String>,
    profile_mention: bool,
    created: i64,
    unread: bool,
}
#[derive(Serialize)]
pub struct Inbox {
    items: Vec<Notice>,
    more: bool,
    unread: i64,
    latest: Option<i64>,
    sound: bool,
}
pub async fn notices(
    State(app): State<App>,
    jar: CookieJar,
    Query(input): Query<NoticeQuery>,
) -> Result<Json<Inbox>> {
    let viewer = profile::completed(&app, &jar).await?;
    let (unread, latest, sound): (i64, Option<i64>, bool) = sqlx::query_as(
        "SELECT count(n.id),max(n.id),coalesce((a.notice_preferences->>'sound')::boolean,false)
         FROM accounts a LEFT JOIN notifications n ON n.recipient=a.id AND n.read_at IS NULL
          AND NOT accounts_blocked(a.id,n.actor) AND EXISTS (SELECT 1 FROM accounts actor WHERE actor.id=n.actor AND actor.deleted_at IS NULL) AND (n.post_id IS NULL OR visible_post(n.post_id,a.id))
         WHERE a.id=$1 GROUP BY a.id",
    ).bind(viewer.id).fetch_one(&app.0.db).await?;
    let mut items: Vec<Notice> = if input.summary {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT n.id,n.kind,a.id AS actor,a.display_name AS name,a.username,
                NOT a.avatar_hidden AND (a.avatar IS NOT NULL OR a.avatar_object_id IS NOT NULL) AS avatar,
                coalesce(p.wall_owner_id,parent.wall_owner_id,p.author_id,a.id) AS target,
                coalesce(parent.id,p.id) AS post_id, post_author.username AS post_username,
                n.kind = 'mention' AND n.post_id IS NULL AS profile_mention,
                extract(epoch FROM n.created_at)::bigint AS created,n.read_at IS NULL AS unread
             FROM notifications n JOIN accounts a ON a.id=n.actor
             LEFT JOIN posts p ON p.id=n.post_id LEFT JOIN posts parent ON parent.id=p.reply_to
             LEFT JOIN accounts post_author ON post_author.id=coalesce(parent.author_id,p.author_id)
             WHERE n.recipient=$1 AND ($2::bigint IS NULL OR n.id<$2) AND NOT accounts_blocked(a.id,$1) AND a.deleted_at IS NULL
             AND (n.post_id IS NULL OR visible_post(n.post_id,$1))
             ORDER BY n.id DESC LIMIT 41",
        ).bind(viewer.id).bind(input.before).fetch_all(&app.0.db).await?
    };
    let more = items.len() > 40;
    items.truncate(40);
    Ok(Json(Inbox {
        items,
        more,
        unread,
        latest,
        sound,
    }))
}
#[derive(Deserialize)]
pub struct ReadNotices {
    through: i64,
}
pub async fn read_notices(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<ReadNotices>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    sqlx::query(
        "UPDATE notifications SET read_at=now() WHERE recipient=$1 AND read_at IS NULL AND id<=$2",
    )
    .bind(viewer.id)
    .bind(input.through)
    .execute(&app.0.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) mod discovery;
pub(crate) mod poll;

use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    ApiError, App, Result,
    auth::{INVALID, RATE},
    media, profile,
};

const MISSING: ApiError = ApiError(StatusCode::NOT_FOUND, "post_missing");

#[derive(Default, Deserialize)]
pub struct FeedQuery {
    #[serde(default)]
    mode: FeedMode,
    #[serde(default)]
    q: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    offset: i64,
    thread: Option<Uuid>,
    profile: Option<Uuid>,
    #[serde(default)]
    likes: bool,
    #[serde(default)]
    order: CommentOrder,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FeedMode {
    #[default]
    Recommended,
    Following,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CommentOrder {
    #[default]
    Oldest,
    Popular,
    Recent,
}

#[derive(Serialize)]
pub struct FeedPage {
    posts: Vec<Value>,
    more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_following_posts: Option<bool>,
}

pub async fn feed(
    State(app): State<App>,
    jar: CookieJar,
    Query(query): Query<FeedQuery>,
) -> Result<Json<FeedPage>> {
    let viewer = profile::completed(&app, &jar).await?;
    if query.offset < 0
        || (query.thread.is_none() && query.offset >= 400)
        || query.q.chars().count() > 100
    {
        return Err(INVALID);
    }
    if let Some(owner) = query.profile {
        let allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND username IS NOT NULL
               AND NOT accounts_blocked(id,$2) AND (NOT $3 OR audience_allows(id,$2,like_access))
               AND (deleted_at IS NULL OR admin_can($2,'content.moderate') OR admin_can($2,'accounts.lifecycle') OR admin_can($2,'accounts.read')))",
        )
        .bind(owner)
        .bind(viewer.id)
        .bind(query.likes)
        .fetch_one(&app.0.db)
        .await?;
        if !allowed {
            return Err(ApiError(StatusCode::NOT_FOUND, "profile_unavailable"));
        }
    }
    let (mut posts, has_following_posts) = select_posts(&app, viewer.id, &query, None).await?;
    let more = posts.len() > 20 && (query.thread.is_some() || query.offset < 380);
    posts.truncate(20);
    Ok(Json(FeedPage {
        posts,
        more,
        has_following_posts,
    }))
}

pub async fn post(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    let viewer = profile::completed(&app, &jar).await?;
    let (mut posts, _) = select_posts(&app, viewer.id, &FeedQuery::default(), Some(id)).await?;
    Ok(Json(posts.pop().ok_or(MISSING)?))
}

async fn select_posts(
    app: &App,
    viewer: Uuid,
    query: &FeedQuery,
    post: Option<Uuid>,
) -> Result<(Vec<Value>, Option<bool>)> {
    Ok(sqlx::query_as(include_str!("feed.sql"))
        .bind(viewer)
        .bind(match query.mode {
            FeedMode::Recommended => "recommended",
            FeedMode::Following => "following",
        })
        .bind(query.thread)
        .bind(query.q.trim())
        .bind(query.offset)
        .bind(discovery::normalized_tag(&query.tag)?)
        .bind(query.profile)
        .bind(query.likes)
        .bind(post)
        .bind(match query.order {
            CommentOrder::Oldest => "oldest",
            CommentOrder::Popular => "popular",
            CommentOrder::Recent => "recent",
        })
        .fetch_one(&app.0.db)
        .await?)
}

pub async fn publish(
    State(app): State<App>,
    jar: CookieJar,
    mut fields: Multipart,
) -> Result<(StatusCode, Json<Uuid>)> {
    let viewer = profile::completed(&app, &jar).await?;
    let mut body = None;
    let mut attachments = Vec::new();
    let mut upload_slot = None;
    let mut poll = None;
    let mut reply = None;
    let mut repost = None;
    let mut id = None;
    let mut wall = None;
    while let Some(field) = fields.next_field().await.map_err(|_| INVALID)? {
        match field.name() {
            Some("body") if body.is_none() => body = Some(field.text().await.map_err(|_| INVALID)?),
            Some("id") if id.is_none() => {
                id = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| INVALID)?
                        .parse::<Uuid>()
                        .map_err(|_| INVALID)?,
                )
            }
            Some("wall") if wall.is_none() => {
                wall = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| INVALID)?
                        .parse::<Uuid>()
                        .map_err(|_| INVALID)?,
                );
            }
            Some("reply_to") if reply.is_none() => {
                reply = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| INVALID)?
                        .parse::<Uuid>()
                        .map_err(|_| INVALID)?,
                )
            }
            Some("repost_of") if repost.is_none() => {
                repost = Some(
                    field
                        .text()
                        .await
                        .map_err(|_| INVALID)?
                        .parse::<Uuid>()
                        .map_err(|_| INVALID)?,
                )
            }
            Some(name @ ("image" | "media")) => {
                let legacy_image = name == "image";
                if attachments.len() == media::MAX_ATTACHMENTS {
                    return Err(media::INVALID_MEDIA);
                }
                if upload_slot.is_none() {
                    upload_slot = Some(app.0.upload_slots.try_acquire().map_err(|_| RATE)?);
                }
                attachments.push(media::attachment(&app, field, legacy_image).await?);
            }
            Some("poll") if poll.is_none() => {
                let bytes = media::read(field, 4096, INVALID).await?;
                poll = Some(poll::Draft::parse(
                    std::str::from_utf8(&bytes).map_err(|_| INVALID)?,
                )?);
            }
            _ => return Err(INVALID),
        }
    }

    let body = body.as_deref().unwrap_or_default().trim();
    if body.chars().count() > 1000 || body.contains('\0') || (reply.is_some() && repost.is_some()) {
        return Err(INVALID);
    }
    if body.is_empty() && attachments.is_empty() && poll.is_none() && repost.is_none() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "post_empty"));
    }

    if (poll.is_some() || wall.is_some()) && (reply.is_some() || repost.is_some()) {
        return Err(INVALID);
    }
    let mut staged = Vec::with_capacity(attachments.len());
    for upload in attachments {
        staged.push((
            media::stage(&app, &upload).await?,
            upload.kind,
            upload.mime,
            upload.title,
        ));
    }
    drop(upload_slot);

    let mut tx = app.0.db.begin().await?;
    if let Some(owner) = wall {
        let allowed: bool = sqlx::query_scalar(
            "SELECT audience_allows(id,$2,wall_access) FROM accounts
             WHERE id=$1 AND username IS NOT NULL FOR SHARE",
        )
        .bind(owner)
        .bind(viewer.id)
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(false);
        if owner == viewer.id || !allowed {
            return Err(ApiError(StatusCode::FORBIDDEN, "wall_unavailable"));
        }
    }
    if let Some(parent) = reply.or(repost) {
        let target: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM posts WHERE id=$1 AND reply_to IS NULL AND visible_post(id,$2)
               AND (NOT $3 OR wall_owner_id IS NULL) FOR KEY SHARE",
        )
        .bind(parent)
        .bind(viewer.id)
        .bind(repost.is_some())
        .fetch_optional(&mut *tx)
        .await?;
        if target.is_none() {
            return Err(MISSING);
        }
    }
    let id = id.unwrap_or_else(Uuid::new_v4);
    let result = sqlx::query(
        "INSERT INTO posts(id, author_id, body, is_repost, repost_of, reply_to, wall_owner_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(viewer.id)
    .bind(body)
    .bind(repost.is_some())
    .bind(repost)
    .bind(reply)
    .bind(wall)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|err| err.is_unique_violation())
        {
            ApiError(StatusCode::CONFLICT, "post_already_reposted")
        } else {
            error.into()
        }
    })?;

    if result.rows_affected() > 0 {
        for (position, (object_id, kind, mime, title)) in staged.into_iter().enumerate() {
            media::retain(&mut tx, object_id).await?;
            sqlx::query("INSERT INTO post_media(post_id,position,object_id,kind,mime,title) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(id).bind(position as i16).bind(object_id).bind(kind).bind(mime).bind(title)
                .execute(&mut *tx).await?;
        }
        if let Some(poll) = poll {
            poll.insert(&mut tx, id).await?;
        }
    } else {
        let author: Uuid = sqlx::query_scalar("SELECT author_id FROM posts WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
        if author != viewer.id {
            return Err(INVALID);
        }
    }
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(id)))
}

#[derive(Deserialize)]
pub struct Enabled {
    pub(crate) enabled: bool,
}

pub async fn like(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Json(input): Json<Enabled>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    let sql = if input.enabled {
        "INSERT INTO post_likes(post_id, account_id) SELECT id,$2 FROM posts WHERE id=$1 AND visible_post(id,$2) ON CONFLICT DO NOTHING"
    } else {
        "DELETE FROM post_likes WHERE post_id=$1 AND account_id=$2"
    };
    sqlx::query(sql)
        .bind(id)
        .bind(viewer.id)
        .execute(&app.0.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn watch(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<Json<i64>> {
    let viewer = profile::completed(&app, &jar).await?;
    sqlx::query("INSERT INTO post_views(post_id, account_id) SELECT id,$2 FROM posts WHERE id=$1 AND visible_post(id,$2) ON CONFLICT DO NOTHING")
        .bind(id).bind(viewer.id).execute(&app.0.db).await?;
    let count = sqlx::query_scalar(
        "SELECT count(*) FROM post_views WHERE post_id=$1 AND readable_post(post_id,$2)",
    )
    .bind(id)
    .bind(viewer.id)
    .fetch_one(&app.0.db)
    .await?;
    Ok(Json(count))
}

pub async fn follow(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Json(input): Json<Enabled>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    if viewer.id == id {
        return Err(INVALID);
    }
    let sql = if input.enabled {
        "INSERT INTO follows(follower_id, followed_id) SELECT $1,id FROM accounts WHERE id=$2 AND deleted_at IS NULL AND username IS NOT NULL AND NOT accounts_blocked($1,id) ON CONFLICT DO NOTHING"
    } else {
        "DELETE FROM follows WHERE follower_id=$1 AND followed_id=$2"
    };
    sqlx::query(sql)
        .bind(viewer.id)
        .bind(id)
        .execute(&app.0.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_post(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    let removed =
        sqlx::query("UPDATE posts SET deleted_at=now() WHERE id=$1 AND deleted_at IS NULL AND (author_id=$2 OR wall_owner_id=$2)")
            .bind(id)
            .bind(viewer.id)
            .execute(&app.0.db)
            .await?;
    if removed.rows_affected() == 0 {
        return Err(MISSING);
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn image(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    let viewer = profile::completed(&app, &jar).await?;
    let bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT data FROM post_images WHERE post_id=$1 AND readable_post(post_id,$2)",
    )
    .bind(id)
    .bind(viewer.id)
    .fetch_optional(&app.0.db)
    .await?
    .ok_or(MISSING)?;
    Ok(media::legacy_image(bytes))
}

pub async fn attachment(
    State(app): State<App>,
    jar: CookieJar,
    Path((id, position)): Path<(Uuid, i16)>,
    headers: HeaderMap,
) -> Result<Response> {
    let viewer = profile::completed(&app, &jar).await?;
    let (object_id, mime): (Uuid, String) =
        sqlx::query_as("SELECT object_id,mime FROM post_media WHERE post_id=$1 AND position=$2 AND readable_post(post_id,$3) AND (deleted_at IS NULL OR admin_can($3,'content.moderate'))")
            .bind(id)
            .bind(position).bind(viewer.id)
            .fetch_optional(&app.0.db)
            .await?
            .ok_or(MISSING)?;
    media::serve(&app, object_id, &mime, &headers).await
}

pub async fn author_avatar(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response> {
    let viewer = profile::completed(&app, &jar).await?;
    if sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM accounts a WHERE a.id=$2 AND NOT accounts_blocked($1,$2) AND ((a.deleted_at IS NULL AND NOT a.avatar_hidden) OR admin_can($1,'content.moderate'))) ")
        .bind(viewer.id)
        .bind(id)
        .fetch_one(&app.0.db)
        .await?
    {
        return Err(MISSING);
    }
    profile::serve_avatar(&app, id, &headers).await
}

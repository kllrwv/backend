use super::{
    Actor, CONFLICT, DENIED, MISSING, allows_target,
    audit::{self, Change, Entity, Undo},
    current_role, mutate, panel_actor,
};
use crate::{
    ApiError, App, Result,
    auth::{self, INVALID},
    media, profile,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    Account,
    Post,
    Comment,
    Attachment,
    Avatar,
    Banner,
    Poll,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Post => "post",
            Self::Comment => "comment",
            Self::Attachment => "attachment",
            Self::Avatar => "avatar",
            Self::Banner => "banner",
            Self::Poll => "poll",
        }
    }
    fn permission(self) -> &'static str {
        if matches!(self, Self::Account) {
            "accounts.lifecycle"
        } else {
            "content.moderate"
        }
    }
}
#[derive(Deserialize)]
pub struct Draft {
    kind: Kind,
    id: Uuid,
    part: Option<i16>,
    reason: String,
    description: String,
}
pub async fn file(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Draft>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    let description = input.description.trim();
    if description.chars().count() > 1000
        || description.contains('\0')
        || !matches!(
            input.reason.as_str(),
            "spam" | "abuse" | "privacy" | "illegal" | "other"
        )
    {
        return Err(INVALID);
    }
    let part = input.part.unwrap_or(-1);
    if matches!(input.kind, Kind::Attachment) != (0..4).contains(&part) {
        return Err(INVALID);
    }
    let mut tx = app.0.db.begin().await?;
    let author: Uuid = sqlx::query_scalar(
        "SELECT a.id FROM accounts a
         WHERE a.id=$1 AND a.deleted_at IS NULL AND NOT accounts_blocked(a.id,$2)
           AND CASE $3
                WHEN 'account' THEN true
                WHEN 'avatar' THEN NOT a.avatar_hidden AND (a.avatar IS NOT NULL OR a.avatar_object_id IS NOT NULL)
                WHEN 'banner' THEN NOT a.banner_hidden AND a.banner_object_id IS NOT NULL
                ELSE false END
         UNION ALL
         SELECT p.author_id FROM posts p
         WHERE p.id=$1 AND visible_post(p.id,$2)
           AND CASE $3
                WHEN 'post' THEN p.reply_to IS NULL
                WHEN 'comment' THEN p.reply_to IS NOT NULL
                WHEN 'attachment' THEN EXISTS(SELECT 1 FROM post_media m WHERE m.post_id=p.id AND m.position=$4 AND m.deleted_at IS NULL)
                WHEN 'poll' THEN EXISTS(SELECT 1 FROM polls WHERE post_id=p.id AND deleted_at IS NULL)
                ELSE false END",
    ).bind(input.id).bind(viewer.id).bind(input.kind.name()).bind(part).fetch_optional(&mut *tx).await?.ok_or(MISSING)?;
    if author == viewer.id {
        return Err(ApiError(StatusCode::FORBIDDEN, "report_own_content"));
    }
    auth::rate(&app, &format!("reports:{}", viewer.id), 20, 3600).await?;
    sqlx::query(
        "INSERT INTO reports(reporter_id,target_kind,target_id,part,reason,description) VALUES($1,$2,$3,$4,$5,$6)
            ON CONFLICT DO NOTHING",
    ).bind(viewer.id).bind(input.kind.name()).bind(input.id).bind(part).bind(input.reason).bind(description)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
pub struct Queue {
    state: Option<String>,
    offset: Option<i64>,
}
pub async fn queue(
    State(app): State<App>,
    jar: CookieJar,
    Query(input): Query<Queue>,
) -> Result<Json<Vec<Value>>> {
    panel_actor(&app, &jar, Some("reports.review")).await?;
    let state = input.state.as_deref().unwrap_or("pending");
    if !matches!(state, "pending" | "accepted" | "dismissed") {
        return Err(INVALID);
    }
    let items=sqlx::query_scalar(
        "SELECT jsonb_build_object('id',r.id,'target',target_id,'kind',target_kind,'part',r.part,
           'reason',reason,'description',description,'state',state,'note',note,'reporter',reporter_id,
           'created',extract(epoch FROM r.created_at)::bigint,
           'author',coalesce(a.username,pa.username),'body',coalesce(p.body,a.bio),
           'target_deleted',coalesce(p.deleted_at IS NOT NULL OR pa.deleted_at IS NOT NULL,false) OR a.deleted_at IS NOT NULL,
           'media', coalesce((SELECT jsonb_agg(jsonb_build_object('part',m.position,'kind',m.kind,'title',m.title) ORDER BY m.position)
                FROM post_media m WHERE m.post_id=p.id AND (r.target_kind<>'attachment' OR r.part=m.position)),'[]'),
           'poll',CASE WHEN r.target_kind='poll' THEN (SELECT jsonb_build_object('question',question,
               'options',(SELECT jsonb_agg(label ORDER BY position) FROM poll_options WHERE post_id=p.id)) FROM polls WHERE post_id=p.id) END,
           'avatar',coalesce(a.avatar IS NOT NULL OR a.avatar_object_id IS NOT NULL,false),
           'banner',a.banner_object_id IS NOT NULL,
           'legacy_image',EXISTS (SELECT 1 FROM post_images WHERE post_id=p.id))
         FROM reports r
         LEFT JOIN accounts a ON r.target_kind IN ('account','avatar','banner') AND a.id=r.target_id
         LEFT JOIN posts p ON r.target_kind IN ('post','comment','attachment','poll') AND p.id=r.target_id
         LEFT JOIN accounts pa ON pa.id=p.author_id
         WHERE state=$1 ORDER BY r.created_at,r.id LIMIT 25 OFFSET $2",
    ).bind(state).bind(input.offset.unwrap_or(0).clamp(0,1_000_000)).fetch_all(&app.0.db).await?;
    Ok(Json(items))
}
pub async fn report_media(
    State(app): State<App>,
    jar: CookieJar,
    Path((id, part)): Path<(Uuid, i16)>,
    headers: HeaderMap,
) -> Result<Response> {
    panel_actor(&app, &jar, Some("reports.review")).await?;
    let (kind, target, only): (String, Uuid, i16) =
        sqlx::query_as("SELECT target_kind,target_id,part FROM reports WHERE id=$1")
            .bind(id)
            .fetch_optional(&app.0.db)
            .await?
            .ok_or(MISSING)?;
    let response = match (kind.as_str(), part) {
        ("account" | "avatar", -1) => profile::serve_avatar(&app, target, &headers).await?,
        ("account" | "banner", -2) => {
            let object = sqlx::query_scalar::<_, Option<Uuid>>(
                "SELECT banner_object_id FROM accounts WHERE id=$1",
            )
            .bind(target)
            .fetch_optional(&app.0.db)
            .await?
            .flatten()
            .ok_or(MISSING)?;
            media::serve(&app, object, "image/webp", &headers).await?
        }
        ("post" | "comment", -1) => {
            let legacy = sqlx::query_scalar("SELECT data FROM post_images WHERE post_id=$1")
                .bind(target)
                .fetch_optional(&app.0.db)
                .await?
                .ok_or(MISSING)?;
            media::legacy_image(legacy)
        }
        (kind, part)
            if matches!(kind, "post" | "comment") || kind == "attachment" && part == only =>
        {
            let (object, mime): (Uuid, String) = sqlx::query_as(
                "SELECT object_id,mime FROM post_media WHERE post_id=$1 AND position=$2",
            )
            .bind(target)
            .bind(part)
            .fetch_optional(&app.0.db)
            .await?
            .ok_or(MISSING)?;
            media::serve(&app, object, &mime, &headers).await?
        }
        _ => return Err(MISSING),
    };
    Ok(response)
}
#[derive(Deserialize)]
pub struct Decision {
    accept: bool,
    #[serde(default)]
    remove: bool,
    #[serde(default)]
    note: String,
}
pub async fn review(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Json(input): Json<Decision>,
) -> Result<StatusCode> {
    let actor = panel_actor(&app, &jar, Some("reports.review")).await?;
    let (mut tx, actor) = mutate(&app.0.db, &actor, "reports.review").await?;
    if input.note.chars().count() > 1000
        || input.note.contains('\0')
        || input.remove && !input.accept
    {
        return Err(INVALID);
    }
    let (kind, target, part): (String, Uuid, i16) = sqlx::query_as(
        "SELECT target_kind,target_id,part FROM reports WHERE id=$1 AND state='pending' FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(MISSING)?;
    let kind: Kind = serde_json::from_value(json!(kind)).map_err(|_| INVALID)?;
    let mut changes = Vec::with_capacity(2);
    if input.remove {
        changes.push(remove(&mut tx, &actor, kind, target, part).await?);
    }
    let state = if input.accept {
        "accepted"
    } else {
        "dismissed"
    };
    let values:Value=sqlx::query_scalar("SELECT jsonb_build_object('state',$1::text,'reviewed_at',now(),'reviewed_by',$2::uuid,'note',$3::text)")
        .bind(state).bind(actor.id).bind(input.note.trim()).fetch_one(&mut *tx).await?;
    changes.push(audit::change(&mut tx, Entity::Report, id, -1, "reports.review", values).await?);
    audit::append(
        &mut tx,
        &app,
        &actor,
        "report_review",
        Some(id),
        json!({"state":state,"kind":kind.name(),"remove":input.remove}),
        Some(Undo::Changes(changes)),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn remove(
    db: &mut PgConnection,
    actor: &Actor,
    kind: Kind,
    id: Uuid,
    part: i16,
) -> Result<Change> {
    let permit = kind.permission();
    actor.require(permit)?;
    if matches!(kind, Kind::Account) && actor.id == id {
        return Err(DENIED);
    }
    if matches!(kind, Kind::Account | Kind::Avatar | Kind::Banner) {
        allows_target(db, actor, id).await?;
    }
    let entity = match kind {
        Kind::Account | Kind::Avatar | Kind::Banner => Entity::Account,
        Kind::Attachment => Entity::Attachment,
        Kind::Poll => Entity::Poll,
        Kind::Post | Kind::Comment => {
            let comment: bool =
                sqlx::query_scalar("SELECT reply_to IS NOT NULL FROM posts WHERE id=$1")
                    .bind(id)
                    .fetch_optional(&mut *db)
                    .await?
                    .ok_or(MISSING)?;
            if comment != matches!(kind, Kind::Comment) {
                return Err(MISSING);
            }
            Entity::Post
        }
    };
    let values = match kind {
        Kind::Avatar => json!({"avatar_hidden":true}),
        Kind::Banner => json!({"banner_hidden":true}),
        _ => {
            sqlx::query_scalar("SELECT jsonb_build_object('deleted_at',now())")
                .fetch_one(&mut *db)
                .await?
        }
    };
    let change = audit::change(db, entity, id, part, permit, values).await?;
    if !change.before["deleted_at"].is_null() || change.before == change.after {
        return Err(CONFLICT);
    }
    Ok(change)
}
#[derive(Deserialize)]
pub struct Delete {
    part: Option<i16>,
}
async fn delete(app: &App, actor: Actor, kind: Kind, id: Uuid, part: i16) -> Result<StatusCode> {
    let (mut tx, actor) = mutate(&app.0.db, &actor, kind.permission()).await?;
    let change = remove(&mut tx, &actor, kind, id, part).await?;
    audit::append(
        &mut tx,
        app,
        &actor,
        "remove",
        Some(id),
        json!({"kind":kind.name(),"part":part}),
        Some(Undo::Changes(vec![change])),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn social_delete(
    State(app): State<App>,
    jar: CookieJar,
    Path((kind, id)): Path<(Kind, Uuid)>,
    Json(input): Json<Delete>,
) -> Result<StatusCode> {
    let viewer = profile::completed(&app, &jar).await?;
    let mut db = app.0.db.acquire().await?;
    let actor = current_role(&mut db, viewer.id).await?;
    drop(db);
    delete(&app, actor, kind, id, input.part.unwrap_or(-1)).await
}
pub async fn panel_delete(
    State(app): State<App>,
    jar: CookieJar,
    Path((kind, id)): Path<(Kind, Uuid)>,
    Json(input): Json<Delete>,
) -> Result<StatusCode> {
    let actor = panel_actor(&app, &jar, Some(kind.permission())).await?;
    delete(&app, actor, kind, id, input.part.unwrap_or(-1)).await
}

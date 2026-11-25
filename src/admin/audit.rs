use super::{
    Actor, CONFLICT, DENIED, MISSING, accounts, aliases, allows_target, audit_message, mutate, ops,
    panel_actor,
};
use crate::{
    App, Result,
    auth::{INVALID, UNAVAILABLE},
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Entity {
    Account,
    Post,
    Attachment,
    Poll,
    Report,
    Role,
}
impl Entity {
    fn table(self) -> &'static str {
        match self {
            Self::Account => "accounts",
            Self::Post => "posts",
            Self::Attachment => "post_media",
            Self::Poll => "polls",
            Self::Report => "reports",
            Self::Role => "admin_roles",
        }
    }
    fn matching(self) -> &'static str {
        match self {
            Self::Attachment => "t.post_id=$1 AND t.position=$2",
            Self::Poll => "t.post_id=$1 AND $2::smallint=-1",
            Self::Role => "t.account_id=$1 AND $2::smallint=-1",
            _ => "t.id=$1 AND $2::smallint=-1",
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Change {
    pub entity: Entity,
    pub id: Uuid,
    pub part: i16,
    pub permission: String,
    pub before: Value,
    pub after: Value,
}
#[derive(Serialize, Deserialize)]
pub enum Undo {
    Changes(Vec<Change>),
    Alias(aliases::AliasChange),
    Environment { before: Value, after: Value },
}
pub async fn snapshot(
    db: &mut PgConnection,
    entity: Entity,
    id: Uuid,
    part: i16,
    keys: &[&str],
) -> Result<Value> {
    let query = format!(
        "SELECT (SELECT jsonb_object_agg(key,value) FROM jsonb_each(to_jsonb(t)) WHERE key=ANY($3::text[]))
         FROM {} t WHERE {} FOR UPDATE", entity.table(), entity.matching()
    );
    sqlx::query_scalar(&query)
        .bind(id)
        .bind(part)
        .bind(keys)
        .fetch_optional(db)
        .await?
        .ok_or(MISSING)
}
pub async fn change(
    db: &mut PgConnection,
    entity: Entity,
    id: Uuid,
    part: i16,
    permission: &str,
    values: Value,
) -> Result<Change> {
    let keys: Vec<&str> = values
        .as_object()
        .ok_or(INVALID)?
        .keys()
        .map(String::as_str)
        .collect();
    let before = snapshot(db, entity, id, part, &keys).await?;
    write_values(db, entity, id, part, &values).await?;
    let after = snapshot(db, entity, id, part, &keys).await?;
    Ok(Change {
        entity,
        id,
        part,
        permission: permission.into(),
        before,
        after,
    })
}
async fn write_values(
    db: &mut PgConnection,
    entity: Entity,
    id: Uuid,
    part: i16,
    values: &Value,
) -> Result<()> {
    let table = entity.table();
    let keys = values.as_object().ok_or(INVALID)?;
    if keys.is_empty()
        || keys
            .keys()
            .any(|k| !k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
    {
        return Err(INVALID);
    }
    let columns = keys
        .keys()
        .map(|k| format!("{k}=v.{k}"))
        .collect::<Vec<_>>()
        .join(",");
    let query = format!(
        "UPDATE {table} t SET {columns} FROM jsonb_populate_record(NULL::{table},$3::jsonb) v WHERE {}",
        entity.matching()
    );
    sqlx::query(&query)
        .bind(id)
        .bind(part)
        .bind(values)
        .execute(db)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(|e| e.is_unique_violation() || e.is_check_violation())
            {
                CONFLICT
            } else {
                error.into()
            }
        })?;
    Ok(())
}
const CHANGES: &[&str] = &[
    "review_account_create",
    "profile",
    "alias_add",
    "alias_rename",
    "alias_remove",
    "email",
    "phone",
    "telegram",
    "password",
    "sessions",
    "totp",
    "badge",
    "avatar",
    "banner",
    "roles",
    "report_review",
    "remove",
    "undo",
    "restart",
    "env",
];
pub async fn append(
    db: &mut PgConnection,
    app: &App,
    actor: &Actor,
    action: &str,
    target: Option<Uuid>,
    mut details: Value,
    undo: Option<Undo>,
) -> Result<Uuid> {
    if !CHANGES.contains(&action) {
        return Err(INVALID);
    }
    details["_telegram"] = json!(
        audit_message::describe(db, app, action, target, &details, undo.as_ref(), false).await?
    );
    insert(db, app, actor, action, target, details, undo).await
}
async fn insert(
    db: &mut PgConnection,
    app: &App,
    actor: &Actor,
    action: &str,
    target: Option<Uuid>,
    details: Value,
    undo: Option<Undo>,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let encrypted = undo
        .map(|undo| {
            let data = serde_json::to_string(&undo).map_err(|_| UNAVAILABLE)?;
            app.0.contacts.seal_admin_event(id, &data)
        })
        .transpose()?;
    sqlx::query(
        "INSERT INTO admin_events(id,actor_id,actor_name,action,target_id,details,undo) VALUES($1,$2,$3,$4,$5,$6,$7)",
    ).bind(id).bind(actor.id).bind(&actor.name).bind(action).bind(target).bind(details).bind(encrypted)
        .execute(db).await?;
    Ok(id)
}
#[derive(Deserialize)]
pub struct Page {
    pub offset: Option<i64>,
}
pub async fn history(
    State(app): State<App>,
    jar: CookieJar,
    Query(page): Query<Page>,
) -> Result<Json<Vec<Value>>> {
    panel_actor(&app, &jar, Some("audit.read")).await?;
    let events = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'actor',actor_name,'actor_id',actor_id,'action',action,'target',target_id,
           'details',details - '_telegram','at',extract(epoch FROM created_at)::bigint,'undone',undone_by IS NOT NULL,
           'can_undo',undo IS NOT NULL AND undone_by IS NULL AND created_at>now()-interval '30 days',
           'delivered',delivered_at IS NOT NULL)
         FROM admin_events WHERE action=ANY($2) ORDER BY created_at DESC,id DESC LIMIT 50 OFFSET $1",
    ).bind(page.offset.unwrap_or(0).clamp(0,1_000_000)).bind(CHANGES).fetch_all(&app.0.db).await?;
    Ok(Json(events))
}
pub async fn undo(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let actor = panel_actor(&app, &jar, Some("audit.undo")).await?;
    let (mut tx, actor) = mutate(&app.0.db, &actor, "audit.undo").await?;
    let (data, action, target, details): (Vec<u8>, String, Option<Uuid>, Value) = sqlx::query_as(
        "SELECT undo,action,target_id,details FROM admin_events WHERE id=$1 AND undone_by IS NULL AND undo IS NOT NULL
          AND created_at>now()-interval '30 days' FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(MISSING)?;
    let data = app.0.contacts.open_admin_event(id, data)?;
    let undo: Undo = serde_json::from_str(&data).map_err(|_| UNAVAILABLE)?;
    match &undo {
        Undo::Changes(changes) => {
            for change in changes.iter().rev() {
                actor.require(&change.permission)?;
                let keys: Vec<&str> = change
                    .before
                    .as_object()
                    .ok_or(UNAVAILABLE)?
                    .keys()
                    .map(String::as_str)
                    .collect();
                let current =
                    snapshot(&mut tx, change.entity, change.id, change.part, &keys).await?;
                if current != change.after {
                    return Err(CONFLICT);
                }
                match change.entity {
                    Entity::Role => {
                        allows_target(&mut tx, &actor, change.id).await?;
                        let desired = change.before["permissions"].as_array().ok_or(UNAVAILABLE)?;
                        if desired
                            .iter()
                            .any(|v| !v.as_str().is_some_and(|p| actor.allows(p)))
                        {
                            return Err(DENIED);
                        }
                    }
                    Entity::Account => {
                        allows_target(&mut tx, &actor, change.id).await?;
                        accounts::prepare_restore(&mut tx, &change.before, &change.after).await?;
                    }
                    _ => {}
                }
                write_values(
                    &mut tx,
                    change.entity,
                    change.id,
                    change.part,
                    &change.before,
                )
                .await?;
                if matches!(change.entity, Entity::Account) {
                    accounts::finish_restore(&mut tx, &change.before, &change.after).await?;
                }
            }
        }
        Undo::Environment { before, after } => {
            actor.require("ops.env.write")?;
            ops::queue_env_undo(&app, &mut tx, before.clone(), after.clone()).await?;
        }
        Undo::Alias(change) => aliases::restore(&mut tx, &actor, change).await?,
    }
    let summary =
        audit_message::describe(&mut tx, &app, &action, target, &details, Some(&undo), true)
            .await?;
    let t = &app.0.translations.admin_bot().audit;
    let original = audit_message::label(&t.fields, "original_event", &t.target);
    let event = insert(
        &mut tx,
        &app,
        &actor,
        "undo",
        Some(id),
        json!({"_telegram":format!("{original}: {id}\n{summary}")}),
        None,
    )
    .await?;
    sqlx::query("UPDATE admin_events SET undone_by=$2,undo=NULL WHERE id=$1")
        .bind(id)
        .bind(event)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn deliver_audit(app: App) {
    let Some(bot) = app.0.bot.as_ref() else {
        return;
    };
    let Some(group) = app.0.admin.audit_chat.or(app.0.support_chat) else {
        return;
    };
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(4));
    loop {
        interval.tick().await;
        let result = sqlx::query_as::<_,(Uuid,Uuid,String,String,Option<Uuid>,Value,String)>(
            "SELECT id,actor_id,actor_name,action,target_id,details,to_char(created_at AT TIME ZONE 'Europe/Moscow','DD.MM.YYYY HH24:MI:SS')
             FROM admin_events WHERE delivered_at IS NULL AND action=ANY($1) ORDER BY created_at,id LIMIT 1",
        ).bind(CHANGES).fetch_optional(&app.0.db).await;
        let Ok(Some((id, actor, name, action, target, details, at))) = result else {
            continue;
        };
        if crate::telegram::support::private_group(bot, group)
            .await
            .is_err()
        {
            continue;
        }
        let t = &app.0.translations.admin_bot().audit;
        let summary = match details["_telegram"].as_str() {
            Some(summary) => summary.to_owned(),
            None => {
                let Ok(mut db) = app.0.db.acquire().await else {
                    continue;
                };
                let Ok(summary) =
                    audit_message::describe(&mut db, &app, &action, target, &details, None, false)
                        .await
                else {
                    continue;
                };
                summary
            }
        };
        let message = format!(
            "{} · {}\n{}: @{name} ({actor})\n{}: {at} {}\n{}: {id}\n\n{summary}",
            t.title,
            audit_message::action_label(t, &action),
            t.actor,
            t.time,
            audit_message::label(&t.messages, "timezone", "utc+3"),
            t.id
        );
        let message = audit_message::limit_message(&message);
        let sent = bot.call::<Value>("sendMessage",json!({
            "chat_id":group,"message_thread_id":6,"text":message,
            "protect_content":true,"disable_notification":true,"link_preview_options":{"is_disabled":true},
        })).await;
        if sent.is_ok() {
            let _ = sqlx::query("UPDATE admin_events SET delivered_at=now() WHERE id=$1")
                .bind(id)
                .execute(&app.0.db)
                .await;
        }
    }
}

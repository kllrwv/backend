use axum::{Json, extract::State};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{
    App, Result,
    auth::{INVALID, UNAVAILABLE},
};

use super::{
    CONFLICT, DENIED,
    audit::{self, Undo},
    mutate, panel_actor,
};

const ENV_KEYS: &[&str] = &[
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_MODE",
    "SMTP_FROM",
    "SMTP_USER",
    "SMTP_PASSWORD",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_LOGIN_CLIENT_ID",
    "TELEGRAM_LOGIN_CLIENT_SECRET",
    "TELEGRAM_SUPPORT_CHAT_ID",
    "TELEGRAM_ADMIN_CHAT_ID",
    "S3_ENDPOINT",
    "S3_REGION",
    "S3_BUCKET",
    "S3_ACCESS_KEY_ID",
    "S3_SECRET_ACCESS_KEY",
    "S3_SESSION_TOKEN",
];

const SERVICES: &[&str] = &["all", "gateway", "web", "admin", "api", "postgres"];

fn state(app: &App) -> Option<Value> {
    let path = app.0.admin.ops_dir.as_ref()?.join("state.json");
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 256_000 {
        return None;
    }
    let state: Value = serde_json::from_slice(&bytes).ok()?;
    let generated = state["generated"].as_i64()?;
    let age = (time::OffsetDateTime::now_utc().unix_timestamp() - generated).abs();
    (age < 240).then_some(state)
}

pub async fn status(State(app): State<App>, jar: CookieJar) -> Result<Json<Value>> {
    let actor = panel_actor(&app, &jar, None).await?;
    let can_read = actor.allows("ops.read");
    let can_restart = actor.allows("ops.restart");
    let can_env = actor.allows("ops.env.write");
    if !can_read && !can_restart && !can_env {
        return Err(DENIED);
    }
    let host = state(&app);
    let (summary, countries, storage) = if can_read {
        account_metrics(&app).await?
    } else {
        (Value::Null, Value::Null, Value::Null)
    };
    let env=can_env.then(|| ENV_KEYS.iter().map(|key| {
        json!({"key":key,"set":host.as_ref().and_then(|state| state["env"][key].as_str()).is_some_and(|v|!v.is_empty())})
    }).collect::<Vec<_>>());
    let jobs:Vec<Value>=sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'at',extract(epoch FROM created_at)::bigint,'dispatched',dispatched_at IS NOT NULL)
         FROM admin_ops_jobs ORDER BY created_at DESC LIMIT 10",
    ).fetch_all(&app.0.db).await?;
    let services = if can_read {
        host.as_ref().map(|v| v["services"].clone())
    } else if can_restart && host.is_some() {
        Some(json!(
            SERVICES
                .iter()
                .filter(|name| **name != "all")
                .map(|name| json!({"name":name}))
                .collect::<Vec<_>>()
        ))
    } else {
        None
    };
    Ok(Json(
        json!({"accounts":summary,"countries":countries,"s3":storage,"s3_configured":app.0.media.is_some(),
        "telegram_configured":app.0.bot.is_some(),"audit_configured":app.0.admin.audit_chat.or(app.0.support_chat).is_some(),
        "managed":host.is_some(), "host":host.as_ref().filter(|_|can_read).map(|v|&v["host"]), "services":services,
        "results":host.as_ref().map(|v| &v["results"]),"env":env,"jobs":jobs}),
    ))
}

async fn account_metrics(app: &App) -> Result<(Value, Value, Value)> {
    let summary:Value=sqlx::query_scalar(
        "SELECT jsonb_build_object('total',count(*) FILTER(WHERE deleted_at IS NULL),
               'deleted',count(*) FILTER(WHERE deleted_at IS NOT NULL),
               'online',count(*) FILTER(WHERE deleted_at IS NULL AND last_seen>now()-interval '2 minutes'))
         FROM accounts",
    ).fetch_one(&app.0.db).await?;
    let contacts: Vec<(Option<String>, Option<Vec<u8>>)> =
        sqlx::query_as("SELECT phone_key,phone_ciphertext FROM accounts WHERE deleted_at IS NULL")
            .fetch_all(&app.0.db)
            .await?;
    let mut countries = std::collections::BTreeMap::<String, u64>::new();
    for (lookup, data) in contacts {
        let number = lookup
            .zip(data)
            .and_then(|(key, data)| app.0.contacts.open_phone(&key, data).ok());
        let country = number
            .and_then(|number| {
                let number = phonenumber::parse(None, format!("+{number}")).ok()?;
                number.country().id().map(|id| format!("{id:?}"))
            })
            .unwrap_or_else(|| "unknown".into());
        *countries.entry(country).or_default() += 1;
    }
    let storage:Value=sqlx::query_scalar(
        "WITH files AS (
           SELECT object_id FROM post_media UNION SELECT avatar_object_id FROM accounts WHERE avatar_object_id IS NOT NULL
           UNION SELECT banner_object_id FROM accounts WHERE banner_object_id IS NOT NULL
         ) SELECT jsonb_build_object('objects',count(*),'measured',count(s.bytes),'bytes',coalesce(sum(s.bytes),0))
         FROM files LEFT JOIN media_sizes s USING (object_id)",
    ).fetch_one(&app.0.db).await?;
    Ok((summary, json!(countries), storage))
}

#[derive(Deserialize)]
pub struct Restart {
    service: String,
}
pub async fn restart(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Restart>,
) -> Result<Json<Uuid>> {
    let actor = panel_actor(&app, &jar, Some("ops.restart")).await?;
    let (mut tx, actor) = mutate(&app.0.db, &actor, "ops.restart").await?;
    if !SERVICES.contains(&input.service.as_str()) {
        return Err(INVALID);
    }
    if state(&app).is_none() {
        return Err(UNAVAILABLE);
    }
    let job = queue(
        &app,
        &mut tx,
        json!({"op":"restart","service":input.service}),
    )
    .await?;
    audit::append(
        &mut tx,
        &app,
        &actor,
        "restart",
        Some(job),
        json!({"service":input.service}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(job))
}

#[derive(Deserialize)]
pub struct Environment {
    key: String,
    value: String,
}
pub async fn environment(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<Environment>,
) -> Result<Json<Uuid>> {
    let actor = panel_actor(&app, &jar, Some("ops.env.write")).await?;
    let (mut tx, actor) = mutate(&app.0.db, &actor, "ops.env.write").await?;
    if !ENV_KEYS.contains(&input.key.as_str())
        || input.value.len() > 4096
        || input.value.contains(['\r', '\n', '\0'])
    {
        return Err(INVALID);
    }
    let host = state(&app).ok_or(UNAVAILABLE)?;
    let before = json!({input.key.clone(): host["env"][&input.key]});
    let after = json!({input.key.clone():input.value});
    if before == after {
        return Err(CONFLICT);
    }
    let job = queue(
        &app,
        &mut tx,
        json!({"op":"env","expected":before,"values":after}),
    )
    .await?;
    audit::append(
        &mut tx,
        &app,
        &actor,
        "env",
        Some(job),
        json!({"key":input.key,"cleared":input.value.is_empty()}),
        Some(Undo::Environment { before, after }),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(job))
}

pub async fn queue_env_undo(
    app: &App,
    db: &mut PgConnection,
    before: Value,
    after: Value,
) -> Result<()> {
    let host = state(app).ok_or(UNAVAILABLE)?;
    for (k, v) in after.as_object().ok_or(INVALID)? {
        if host["env"][k] != *v {
            return Err(CONFLICT);
        }
    }
    queue(
        app,
        db,
        json!({"op":"env","expected":after,"values":before}),
    )
    .await?;
    Ok(())
}

async fn queue(app: &App, db: &mut PgConnection, payload: Value) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let payload = app.0.contacts.seal_admin_event(id, &payload.to_string())?;
    sqlx::query("INSERT INTO admin_ops_jobs(id,payload) VALUES($1,$2)")
        .bind(id)
        .bind(payload)
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn dispatch(app: App) {
    let Some(folder) = app.0.admin.ops_dir.as_ref().map(|p| p.join("inbox")) else {
        return;
    };
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
    loop {
        interval.tick().await;
        let tasks=sqlx::query_as::<_,(Uuid,Vec<u8>)>(
            "SELECT id,payload FROM admin_ops_jobs WHERE dispatched_at IS NULL ORDER BY created_at LIMIT 20"
        ).fetch_all(&app.0.db).await;
        let Ok(tasks) = tasks else {
            continue;
        };
        for (id, data) in tasks {
            let Ok(payload) = app.0.contacts.open_admin_event(id, data) else {
                continue;
            };
            let tmp = folder.join(format!(".{id}.tmp"));
            let dest = folder.join(format!("{id}.json"));
            let result = (|| -> std::io::Result<()> {
                use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
                let mut file = OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .mode(0o600)
                    .open(&tmp)?;
                file.write_all(payload.as_bytes())?;
                file.sync_all()?;
                std::fs::rename(tmp, dest)
            })();
            if result.is_err() {
                break;
            }
            let _ = sqlx::query("UPDATE admin_ops_jobs SET dispatched_at=now() WHERE id=$1")
                .bind(id)
                .execute(&app.0.db)
                .await;
        }
    }
}

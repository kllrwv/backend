use super::{Actor, DENIED, MISSING, allows_target, audit::{self, Undo}, mutate, panel_actor};
use crate::{ApiError, App, Result, profile::aliases::{self, Alias}};
use axum::{Json, extract::{Path, State}, http::StatusCode};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;
pub const PERMISSION: &str = "accounts.aliases.write";
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Edit {
    Add { username: String },
    Rename { existing: String, username: String },
    Remove { username: String },
}
#[derive(Deserialize, Serialize)]
pub struct AliasChange {
    pub account: Uuid,
    pub slot: i16,
    pub before: Option<Alias>,
    pub after: Option<Alias>,
}
pub async fn list(State(app): State<App>, jar: CookieJar, Path(id): Path<Uuid>) -> Result<Json<Vec<Alias>>> {
    let actor = panel_actor(&app, &jar, Some(PERMISSION)).await?;
    let mut db = app.0.db.acquire().await?;
    allows_target(&mut db, &actor, id).await?;
    Ok(Json(aliases::list(&mut db, id).await?))
}
pub async fn edit(State(app): State<App>, jar: CookieJar, Path(id): Path<Uuid>, Json(input): Json<Edit>) -> Result<StatusCode> {
    let actor = panel_actor(&app, &jar, Some(PERMISSION)).await?;
    let (mut tx, actor) = mutate(&app.0.db, &actor, PERMISSION).await?;
    lock_target(&mut tx, &actor, id).await?;
    let (slot, before, after, action) = match input {
        Edit::Add { username } => {
            let username = aliases::assignable(&username)?;
            let slot = sqlx::query_scalar("SELECT candidate::smallint FROM generate_series(1,72) AS slots(candidate) WHERE NOT EXISTS (SELECT 1 FROM account_usernames h WHERE account_id=$1 AND h.slot=candidate) ORDER BY candidate LIMIT 1")
                .bind(id).fetch_optional(&mut *tx).await?.ok_or(ApiError(StatusCode::CONFLICT, "aliases_limit"))?;
            (slot, None, Some(Alias { username, enabled: true }), "alias_add")
        }
        Edit::Rename { existing, username } => {
            let (slot, before) = find(&mut tx, id, &existing).await?;
            let after = Alias { username: aliases::assignable(&username)?, enabled: before.enabled };
            (slot, Some(before), Some(after), "alias_rename")
        }
        Edit::Remove { username } => {
            let (slot, before) = find(&mut tx, id, &username).await?;
            (slot, Some(before), None, "alias_remove")
        }
    };
    if before != after {
        write(&mut tx, id, slot, after.as_ref()).await?;
        let mut details = json!({});
        if let Some(alias) = &before { details["previous_username"] = json!(format!("@{}", alias.username)); }
        if let Some(alias) = &after { details["new_username"] = json!(format!("@{}", alias.username)); }
        let undo = Undo::Alias(AliasChange { account: id, slot, before, after });
        audit::append(&mut tx, &app, &actor, action, Some(id), details, Some(undo)).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn lock_target(db: &mut PgConnection, actor: &Actor, id: Uuid) -> Result<()> {
    allows_target(db, actor, id).await?;
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM accounts WHERE id=$1 AND username IS NOT NULL AND deleted_at IS NULL FOR UPDATE")
        .bind(id).fetch_optional(db).await?.ok_or(MISSING)?;
    Ok(())
}
async fn find(db: &mut PgConnection, id: Uuid, username: &str) -> Result<(i16, Alias)> {
    let (slot, username, enabled) = sqlx::query_as("SELECT slot,username,enabled FROM account_usernames WHERE account_id=$1 AND username=$2 AND slot>0 FOR UPDATE")
        .bind(id).bind(aliases::normalize(username)?).fetch_optional(db).await?.ok_or(aliases::MISSING)?;
    Ok((slot, Alias { username, enabled }))
}
async fn write(db: &mut PgConnection, id: Uuid, slot: i16, value: Option<&Alias>) -> Result<()> {
    if !(1..=72).contains(&slot) { return Err(DENIED); }
    if let Some(alias) = value {
        sqlx::query("INSERT INTO account_usernames(account_id,slot,username,enabled) VALUES($1,$2,$3,$4) ON CONFLICT (account_id,slot) DO UPDATE SET username=EXCLUDED.username,enabled=EXCLUDED.enabled")
            .bind(id).bind(slot).bind(&alias.username).bind(alias.enabled).execute(db).await.map_err(aliases::conflict)?;
    } else {
        sqlx::query("DELETE FROM account_usernames WHERE account_id=$1 AND slot=$2")
            .bind(id).bind(slot).execute(db).await?;
    }
    Ok(())
}
pub async fn restore(db: &mut PgConnection, actor: &Actor, change: &AliasChange) -> Result<()> {
    actor.require(PERMISSION)?;
    lock_target(db, actor, change.account).await?;
    let current = sqlx::query_as("SELECT username,enabled FROM account_usernames WHERE account_id=$1 AND slot=$2 AND slot>0 FOR UPDATE")
        .bind(change.account).bind(change.slot).fetch_optional(&mut *db).await?;
    if current != change.after { return Err(super::CONFLICT); }
    write(db, change.account, change.slot, change.before.as_ref()).await
}

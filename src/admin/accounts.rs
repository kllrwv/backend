use super::{
    CONFLICT, DENIED, MISSING, PERMISSIONS, allows_target,
    audit::{self, Entity, Undo},
    mutate, panel_actor,
};
use crate::{
    ApiError, App, Result,
    auth::{self, INVALID, RATE, UNAVAILABLE},
    media, profile,
};
use axum::{
    Json,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;
#[derive(Deserialize)]
pub struct Search {
    q: Option<String>,
    offset: Option<i64>,
}
#[derive(Deserialize)]
pub struct ReviewAccountDraft {
    name: String,
    username: String,
    password: String,
}
pub async fn create_review(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<ReviewAccountDraft>,
) -> Result<(StatusCode, Json<Value>)> {
    let permit = "accounts.review.create";
    let actor = panel_actor(&app, &jar, Some(permit)).await?;
    let name = input.name.trim().to_lowercase();
    let handle = input.username.trim();
    let username = auth::username(handle.strip_prefix('@').unwrap_or(handle)).ok_or(INVALID)?;
    if !(1..=80).contains(&name.chars().count()) || name.contains('\0') {
        return Err(INVALID);
    }
    if input.password.chars().count() < 10 || input.password.len() > 512 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "password_length"));
    }
    let slot = app
        .0
        .hash_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| RATE)?;
    let hash = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        auth::hash_password(input.password.as_bytes())
    })
    .await
    .map_err(|_| UNAVAILABLE)?
    .map_err(|_| UNAVAILABLE)?;
    let (mut tx, actor) = mutate(&app.0.db, &actor, permit).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO accounts(id,username,display_name,password_hash,review_account)
         VALUES(gen_random_uuid(),$1,$2,$3,true) ON CONFLICT(username) DO NOTHING RETURNING id",
    )
    .bind(&username)
    .bind(name)
    .bind(hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(CONFLICT)?;
    audit::append(
        &mut tx,
        &app,
        &actor,
        "review_account_create",
        Some(id),
        json!({}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"username":username})),
    ))
}
pub async fn list(
    State(app): State<App>,
    jar: CookieJar,
    Query(input): Query<Search>,
) -> Result<Json<Vec<Value>>> {
    let actor = panel_actor(&app, &jar, Some("accounts.read")).await?;
    let q = input.q.as_deref().unwrap_or("").trim().to_lowercase();
    if q.chars().count() > 120 {
        return Err(INVALID);
    }
    let lookup = actor
        .allows("accounts.contacts.read")
        .then(|| auth::checked_email(&q).ok())
        .flatten()
        .map(|email| app.0.contacts.email_lookup(&email));
    let phone = actor
        .allows("accounts.contacts.read")
        .then(|| crate::telegram::phone_number(&q))
        .flatten()
        .map(|phone| {
            app.0
                .contacts
                .phone_lookup(&auth::key(&app, "phone", &phone))
        });
    let accounts = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'username',username,'name',display_name,'verified',verified,
              'deleted',deleted_at IS NOT NULL,'avatar',avatar IS NOT NULL OR avatar_object_id IS NOT NULL,
              'review_account',review_account)
         FROM accounts WHERE $1='' OR strpos(coalesce(username,''),$1)>0 OR strpos(coalesce(display_name,''),$1)>0
            OR id::text=$1 OR (telegram_id::text=$1 AND $2)
            OR email_lookup=$3 OR phone_key=$4
         ORDER BY created_at DESC,id DESC LIMIT 50 OFFSET $5",
    ).bind(q.trim_start_matches('@')).bind(actor.allows("accounts.contacts.read")).bind(lookup).bind(phone)
        .bind(input.offset.unwrap_or(0).clamp(0,1_000_000)).fetch_all(&app.0.db).await?;
    Ok(Json(accounts))
}
pub async fn details(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>> {
    let actor = panel_actor(&app, &jar, Some("accounts.read")).await?;
    let mut db = app.0.db.acquire().await?;
    let mut account: Value = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',id,'username',username,'name',display_name,'bio',bio,
            'verified',verified,'deleted',deleted_at IS NOT NULL,'created',extract(epoch FROM created_at)::bigint,
            'last_seen',extract(epoch FROM last_seen)::bigint,'avatar',avatar IS NOT NULL OR avatar_object_id IS NOT NULL,
            'banner',banner_object_id IS NOT NULL,'avatar_hidden',avatar_hidden,'banner_hidden',banner_hidden,
            'totp',totp_generation IS NOT NULL,'review_account',review_account,'theme',theme,'wall_access',wall_access,'like_access',like_access,
            'message_access',message_access,'show_online',show_online,'notice_preferences',notice_preferences,
            'followers',(SELECT count(*) FROM follows WHERE followed_id=a.id),
            'following',(SELECT count(*) FROM follows WHERE follower_id=a.id),
            'posts',(SELECT count(*) FROM posts WHERE author_id=a.id AND reply_to IS NULL AND deleted_at IS NULL),
            'comments',(SELECT count(*) FROM posts WHERE author_id=a.id AND reply_to IS NOT NULL AND deleted_at IS NULL))
         FROM accounts a WHERE id=$1",
    ).bind(id).fetch_optional(&mut *db).await?.ok_or(MISSING)?;
    if actor.allows("accounts.contacts.read") {
        let (lookup, email, key, number, tail, telegram): (Option<String>,Option<Vec<u8>>,Option<String>,Option<Vec<u8>>,Option<Vec<u8>>,Option<i64>) =
            sqlx::query_as("SELECT email_lookup,email_ciphertext,phone_key,phone_ciphertext,phone_tail_ciphertext,telegram_id FROM accounts WHERE id=$1")
                .bind(id).fetch_one(&mut *db).await?;
        account["email"] = json!(
            lookup
                .as_deref()
                .zip(email)
                .map(|(key, data)| app.0.contacts.open_email(key, data))
                .transpose()?
        );
        account["telegram"] = json!(telegram.map(|id| id.to_string()));
        account["phone"] = json!(
            key.as_deref()
                .zip(number)
                .map(|(key, data)| app.0.contacts.open_phone(key, data))
                .transpose()?
                .map(|n| format!("+{n}"))
        );
        account["phone_tail"] = json!(
            key.as_deref()
                .zip(tail)
                .map(|(key, data)| app.0.contacts.open_phone_tail(key, data))
                .transpose()?
        );
    }
    if actor.allows("accounts.sessions.revoke") {
        let sessions: Vec<Value> = sqlx::query_scalar(
            "SELECT jsonb_build_object('id',public_id,'device',device,'seen',extract(epoch FROM last_seen)::bigint,
                       'expires',extract(epoch FROM expires_at)::bigint)
             FROM sessions WHERE account_id=$1 AND expires_at>now() ORDER BY last_seen DESC",
        ).bind(id).fetch_all(&mut *db).await?;
        account["sessions"] = json!(sessions);
    }
    if actor.allows("admins.read") || actor.allows("admins.grant") {
        let role: Option<(bool, Vec<String>)> =
            sqlx::query_as("SELECT owner,permissions FROM admin_roles WHERE account_id=$1")
                .bind(id)
                .fetch_optional(&mut *db)
                .await?;
        let (owner, permissions) = role.unwrap_or_default();
        account["owner"] = json!(owner);
        account["permissions"] = json!(permissions);
    }
    Ok(Json(account))
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Edit {
    Profile {
        name: String,
        username: String,
        bio: String,
        theme: String,
        wall_access: String,
        like_access: String,
        message_access: String,
        show_online: bool,
        notice_preferences: Value,
    },
    Email {
        value: String,
    },
    Phone {
        value: String,
    },
    Telegram {
        value: String,
    },
    Password {
        value: String,
    },
    RevokeSessions {
        session: Option<Uuid>,
    },
    ResetTotp,
    Badge {
        value: bool,
    },
    RemoveAvatar,
    RemoveBanner,
}
impl Edit {
    fn permit(&self) -> &'static str {
        match self {
            Self::Profile { .. } | Self::RemoveAvatar | Self::RemoveBanner => {
                "accounts.profile.write"
            }
            Self::Email { .. } | Self::Phone { .. } => "accounts.contacts.write",
            Self::Telegram { .. } => "accounts.telegram.write",
            Self::Password { .. } => "accounts.password.reset",
            Self::RevokeSessions { .. } => "accounts.sessions.revoke",
            Self::ResetTotp => "accounts.totp.reset",
            Self::Badge { .. } => "accounts.badge",
        }
    }
}
pub async fn edit(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Json(input): Json<Edit>,
) -> Result<StatusCode> {
    let permit = input.permit();
    let actor = panel_actor(&app, &jar, Some(permit)).await?;
    let hash = if let Edit::Password { value } = &input {
        if value.chars().count() < 10 || value.len() > 512 {
            return Err(INVALID);
        }
        let pass = value.clone();
        let slot = app
            .0
            .hash_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| RATE)?;
        Some(
            tokio::task::spawn_blocking(move || {
                let _slot = slot;
                auth::hash_password(pass.as_bytes())
            })
            .await
            .map_err(|_| UNAVAILABLE)?
            .map_err(|_| UNAVAILABLE)?,
        )
    } else {
        None
    };
    let (mut tx, actor) = mutate(&app.0.db, &actor, permit).await?;
    allows_target(&mut tx, &actor, id).await?;
    let mut details = json!({});
    let (action, values, revoke) = match input {
        Edit::Profile {
            name,
            username,
            bio,
            theme,
            wall_access,
            like_access,
            message_access,
            show_online,
            notice_preferences,
        } => {
            let set = notice_preferences.as_object().ok_or(INVALID)?;
            if set.iter().any(|(k, v)| {
                !matches!(
                    k.as_str(),
                    "all" | "sound" | "messages" | "follow" | "wall" | "like" | "reply" | "mention"
                ) || !v.is_boolean()
            }) || !matches!(theme.as_str(), "light" | "dark" | "system")
                || [
                    wall_access.as_str(),
                    like_access.as_str(),
                    message_access.as_str(),
                ]
                .into_iter()
                .any(|a| !matches!(a, "everyone" | "followers" | "nobody"))
            {
                return Err(INVALID);
            }
            let name = name.trim().to_lowercase();
            let bio = bio.trim();
            if !(1..=80).contains(&name.chars().count())
                || bio.chars().count() > 500
                || name.contains('\0')
                || bio.contains('\0')
            {
                return Err(INVALID);
            }
            (
                "profile",
                json!({"display_name":name,"username":auth::username(&username).ok_or(INVALID)?,"bio":bio,
              "theme":theme,"wall_access":wall_access,"like_access":like_access,"message_access":message_access,
              "show_online":show_online,"notice_preferences":notice_preferences}),
                false,
            )
        }
        Edit::Email { value } => {
            let email = auth::checked_email(&value)?;
            let key = app.0.contacts.email_lookup(&email);
            let encrypted = app.0.contacts.seal_email(&email, &key)?;
            contact_lock(&mut tx).await?;
            (
                "email",
                json!({"email_lookup":key,"email_ciphertext":bytea(&encrypted)}),
                true,
            )
        }
        Edit::Phone { value } => {
            let phone = crate::telegram::phone_number(&value).ok_or(INVALID)?;
            let key = app
                .0
                .contacts
                .phone_lookup(&auth::key(&app, "phone", &phone));
            let encrypted = app.0.contacts.seal_phone(&phone, &key)?;
            let tail = app
                .0
                .contacts
                .seal_phone_tail(&phone[phone.len() - 4..], &key)?;
            contact_lock(&mut tx).await?;
            (
                "phone",
                json!({"phone_key":key,"phone_ciphertext":bytea(&encrypted),"phone_tail_ciphertext":bytea(&tail)}),
                true,
            )
        }
        Edit::Telegram { value } => {
            let id: i64 = value.trim().parse().map_err(|_| INVALID)?;
            if id <= 0 || id >= (1_i64 << 52) {
                return Err(INVALID);
            }
            ("telegram", json!({"telegram_id":id}), true)
        }
        Edit::Password { .. } => (
            "password",
            json!({"password_hash":hash.ok_or(UNAVAILABLE)?}),
            true,
        ),
        Edit::RevokeSessions { session } => {
            let removed = sqlx::query(
                "DELETE FROM sessions WHERE account_id=$1 AND ($2::uuid IS NULL OR public_id=$2)",
            )
            .bind(id)
            .bind(session)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if removed > 0 {
                audit::append(
                    &mut tx,
                    &app,
                    &actor,
                    "sessions",
                    Some(id),
                    json!({"count":removed,"session":session}),
                    None,
                )
                .await?;
            }
            tx.commit().await?;
            return Ok(StatusCode::NO_CONTENT);
        }
        Edit::ResetTotp => {
            let removed = sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            details["recovery_count"] = json!(removed);
            (
                "totp",
                json!({"totp_generation":null,"totp_secret":null,"totp_last_step":null}),
                true,
            )
        }
        Edit::Badge { value } => ("badge", json!({"verified":value}), false),
        Edit::RemoveAvatar => ("avatar", json!({"avatar_hidden":true}), false),
        Edit::RemoveBanner => ("banner", json!({"banner_hidden":true}), false),
    };
    let change = audit::change(&mut tx, Entity::Account, id, -1, permit, values).await?;
    if revoke {
        details["count"] = json!(revoke_security(&mut tx, id, action).await?);
    }
    if revoke || change.before != change.after {
        if let Some(key) = match action {
            "email" => Some("email_lookup"),
            "phone" => Some("phone_key"),
            "telegram" => Some("telegram_id"),
            "totp" => Some("totp_secret"),
            _ => None,
        } {
            details["same_value"] = json!(change.before[key] == change.after[key]);
        }
        let undo = (action != "totp").then_some(Undo::Changes(vec![change]));
        audit::append(&mut tx, &app, &actor, action, Some(id), details, undo).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
fn bytea(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::from("\\x");
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
async fn contact_lock(db: &mut PgConnection) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(73460650021401)")
        .execute(db)
        .await?;
    Ok(())
}
async fn revoke_security(db: &mut PgConnection, id: Uuid, action: &str) -> Result<u64> {
    let removed = sqlx::query("DELETE FROM sessions WHERE account_id=$1")
        .bind(id)
        .execute(&mut *db)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM auth_flows WHERE account_id=$1")
        .bind(id)
        .execute(&mut *db)
        .await?;
    if action == "telegram" {
        sqlx::query(
            "DELETE FROM telegram_support_chats WHERE user_id=(SELECT telegram_id FROM accounts WHERE id=$1)"
        ).bind(id).execute(&mut *db).await?;
    }
    Ok(removed)
}
pub async fn prepare_restore(db: &mut PgConnection, before: &Value, after: &Value) -> Result<()> {
    if before.get("email_lookup").is_some() || before.get("phone_key").is_some() {
        contact_lock(db).await?;
        for (kind, key) in [("email", "email_lookup"), ("phone", "phone_key")] {
            if let Some(value) = before[key].as_str()
                && before[key] != after[key]
            {
                sqlx::query("DELETE FROM retired_contacts WHERE kind=$1 AND fingerprint=$2")
                    .bind(kind)
                    .bind(value)
                    .execute(&mut *db)
                    .await?;
            }
        }
    }
    Ok(())
}
pub async fn finish_restore(db: &mut PgConnection, before: &Value, after: &Value) -> Result<()> {
    if let Some(old) = before["avatar_object_id"]
        .as_str()
        .and_then(|s| s.parse::<Uuid>().ok())
    {
        sqlx::query("DELETE FROM media_gc WHERE object_id=$1")
            .bind(old)
            .execute(&mut *db)
            .await?;
    }
    reschedule_avatar(db, after).await
}
async fn reschedule_avatar(db: &mut PgConnection, previous: &Value) -> Result<()> {
    if let Some(id) = previous["avatar_object_id"]
        .as_str()
        .and_then(|s| s.parse::<Uuid>().ok())
    {
        sqlx::query("UPDATE media_gc SET delete_after=now()+interval '31 days' WHERE object_id=$1")
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(())
}
pub async fn upload_avatar(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    mut form: Multipart,
) -> Result<StatusCode> {
    let actor = panel_actor(&app, &jar, Some("accounts.profile.write")).await?;
    let Some(field) = form.next_field().await.map_err(|_| INVALID)? else {
        return Err(INVALID);
    };
    if field.name() != Some("avatar") {
        return Err(INVALID);
    }
    const INVALID_AVATAR: ApiError = ApiError(StatusCode::BAD_REQUEST, "avatar_invalid");
    let bytes = media::read(field, media::IMAGE_LIMIT, INVALID_AVATAR).await?;
    if form.next_field().await.map_err(|_| INVALID)?.is_some() {
        return Err(INVALID);
    }
    let object = media::stage(
        &app,
        &media::photo(&app, bytes, true, INVALID_AVATAR).await?,
    )
    .await?;
    let (mut tx, actor) = mutate(&app.0.db, &actor, "accounts.profile.write").await?;
    allows_target(&mut tx, &actor, id).await?;
    media::retain(&mut tx, object).await?;
    let change = audit::change(
        &mut tx,
        Entity::Account,
        id,
        -1,
        "accounts.profile.write",
        json!({"avatar_object_id":object,"avatar_hidden":false}),
    )
    .await?;
    reschedule_avatar(&mut tx, &change.before).await?;
    audit::append(
        &mut tx,
        &app,
        &actor,
        "avatar",
        Some(id),
        json!({}),
        Some(Undo::Changes(vec![change])),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn avatar(
    State(app): State<App>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response> {
    panel_actor(&app, &jar, Some("accounts.read")).await?;
    profile::serve_avatar(&app, id, &headers).await
}
#[derive(Deserialize)]
pub struct Assign {
    permissions: Vec<String>,
}
pub async fn roles(State(app): State<App>, jar: CookieJar) -> Result<Json<Vec<Value>>> {
    let actor = panel_actor(&app, &jar, None).await?;
    if !actor.allows("admins.read") && !actor.allows("admins.grant") {
        return Err(DENIED);
    }
    let roles = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',a.id,'name',a.display_name,'username',a.username,'owner',r.owner,'permissions',r.permissions)
         FROM admin_roles r JOIN accounts a ON a.id=r.account_id
         WHERE r.owner OR cardinality(r.permissions)>0 ORDER BY r.owner DESC,a.username LIMIT 500",
    ).fetch_all(&app.0.db).await?;
    Ok(Json(roles))
}
pub async fn assign(
    State(app): State<App>,
    jar: CookieJar,
    Path(handle): Path<String>,
    Json(mut input): Json<Assign>,
) -> Result<StatusCode> {
    let actor = panel_actor(&app, &jar, Some("admins.grant")).await?;
    let (mut tx, actor) = mutate(&app.0.db, &actor, "admins.grant").await?;
    let id: Uuid = if let Ok(id) = Uuid::parse_str(&handle) {
        id
    } else {
        let handle = auth::username(&handle).ok_or(INVALID)?;
        sqlx::query_scalar("SELECT id FROM accounts WHERE username=$1 AND deleted_at IS NULL")
            .bind(handle)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(MISSING)?
    };
    if actor.id == id
        || input
            .permissions
            .iter()
            .any(|p| !PERMISSIONS.contains(&p.as_str()) || !actor.allows(p))
    {
        return Err(DENIED);
    }
    allows_target(&mut tx, &actor, id).await?;
    input.permissions.sort();
    input.permissions.dedup();
    let review_account: bool = sqlx::query_scalar(
        "SELECT review_account FROM accounts WHERE id=$1 AND deleted_at IS NULL AND username IS NOT NULL",
    ).bind(id).fetch_optional(&mut *tx).await?.ok_or(MISSING)?;
    if review_account {
        return Err(DENIED);
    }
    sqlx::query(
        "INSERT INTO admin_roles(account_id,permissions) VALUES($1,'{}') ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let change = audit::change(
        &mut tx,
        Entity::Role,
        id,
        -1,
        "admins.grant",
        json!({"permissions":input.permissions}),
    )
    .await?;
    if change.before == change.after {
        return Err(CONFLICT);
    }
    audit::append(
        &mut tx,
        &app,
        &actor,
        "roles",
        Some(id),
        json!({"permissions":input.permissions}),
        Some(Undo::Changes(vec![change])),
    )
    .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

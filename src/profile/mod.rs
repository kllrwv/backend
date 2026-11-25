pub(crate) mod aliases;
pub(crate) mod community;
use crate::{
    ApiError, App, Result,
    auth::{self, FlowView, INVALID, SESSION},
    media,
};
use axum::{
    Json,
    extract::{Multipart, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use axum_extra::extract::CookieJar;
use image::{ImageFormat, ImageReader, Limits};
use serde::Serialize;
use std::io::Cursor;
use uuid::Uuid;
#[derive(Serialize, sqlx::FromRow)]
pub struct Profile {
    #[serde(skip)]
    pub(crate) id: Uuid,
    username: Option<String>,
    display_name: Option<String>,
    bio: String,
    has_avatar: bool,
}
#[derive(Serialize)]
pub struct BrowserState {
    profile: Option<Profile>,
    flow: Option<FlowView>,
}
async fn account(app: &App, jar: &CookieJar) -> Result<Option<Profile>> {
    let Some(session) = jar.get(SESSION) else {
        return Ok(None);
    };
    let result = sqlx::query_as(
        "SELECT a.id, username, display_name, bio, NOT avatar_hidden AND (avatar IS NOT NULL OR avatar_object_id IS NOT NULL) AS has_avatar
         FROM accounts a JOIN sessions s ON s.account_id=a.id WHERE s.id=$1 AND s.expires_at>now() AND a.deleted_at IS NULL",
    )
    .bind(auth::digest(session.value()))
    .fetch_optional(&app.0.db)
    .await?;
    Ok(result)
}
async fn required(app: &App, jar: &CookieJar) -> Result<Profile> {
    account(app, jar)
        .await?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "sign_in_required"))
}
pub async fn me(State(app): State<App>, jar: CookieJar) -> Result<Json<BrowserState>> {
    let profile = account(&app, &jar).await?;
    let flow = if profile.is_none() {
        auth::current_flow(&app, &jar).await?
    } else {
        None
    };
    Ok(Json(BrowserState { profile, flow }))
}
pub async fn save(
    State(app): State<App>,
    jar: CookieJar,
    mut fields: Multipart,
) -> Result<Json<Profile>> {
    let profile = required(&app, &jar).await?;
    let mut name = None;
    let mut username = None;
    let mut bio = None;
    let mut avatar = None;
    let mut remove_avatar = false;
    while let Some(part) = fields.next_field().await.map_err(|_| INVALID)? {
        match part.name() {
            Some("name") if name.is_none() => name = Some(part.text().await.map_err(|_| INVALID)?),
            Some("username") if username.is_none() => {
                username = Some(part.text().await.map_err(|_| INVALID)?)
            }
            Some("bio") if bio.is_none() => bio = Some(part.text().await.map_err(|_| INVALID)?),
            Some("avatar") if avatar.is_none() => {
                let invalid = ApiError(StatusCode::BAD_REQUEST, "avatar_invalid");
                let bytes = media::read(part, media::IMAGE_LIMIT, invalid).await?;
                avatar = Some(
                    media::photo(
                        &app,
                        bytes,
                        true,
                        ApiError(StatusCode::BAD_REQUEST, "avatar_invalid"),
                    )
                    .await?,
                );
            }
            Some("remove_avatar") if !remove_avatar => {
                remove_avatar = part.text().await.map_err(|_| INVALID)? == "true";
            }
            _ => return Err(INVALID),
        }
    }
    let name = name.as_deref().unwrap_or("").trim();
    if !(1..=80).contains(&name.chars().count()) || name.chars().any(char::is_control) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "name_invalid"));
    }
    let username = auth::username(username.as_deref().unwrap_or(""))
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "username_invalid"))?;
    let bio = bio.as_deref().unwrap_or("").trim();
    if bio.chars().count() > 500 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "bio_invalid"));
    }
    if remove_avatar && avatar.is_some() {
        return Err(INVALID);
    }
    let avatar_id = match avatar {
        Some(avatar) => Some(media::stage(&app, &avatar).await?),
        None => None,
    };
    let mut tx = app.0.db.begin().await?;
    if let Some(id) = avatar_id {
        media::retain(&mut tx, id).await?;
    }
    let updated = sqlx::query_as(
        "UPDATE accounts SET display_name=$2, username=$3, bio=$4,
          avatar=CASE WHEN $5::uuid IS NULL AND NOT $6 THEN avatar ELSE NULL END,
          avatar_object_id=CASE WHEN $6 THEN NULL ELSE COALESCE($5,avatar_object_id) END
         WHERE id=$1 RETURNING id, username, display_name, bio,
          NOT avatar_hidden AND (avatar IS NOT NULL OR avatar_object_id IS NOT NULL) AS has_avatar",
    )
    .bind(profile.id)
    .bind(name.to_lowercase())
    .bind(username)
    .bind(bio.to_lowercase())
    .bind(avatar_id)
    .bind(remove_avatar)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| match error.as_database_error() {
        Some(db_error) if db_error.is_unique_violation() => {
            ApiError(StatusCode::CONFLICT, "username_taken")
        }
        _ => error.into(),
    })?;
    tx.commit().await?;
    Ok(Json(updated))
}
pub(crate) fn encode_image(bytes: &[u8], square: bool) -> Option<Vec<u8>> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    if !matches!(
        reader.format(),
        Some(ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::WebP)
    ) {
        return None;
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(96 * 1024 * 1024);
    reader.limits(limits);
    let img = reader.decode().ok()?;
    let img = if square {
        let side = img.width().min(img.height());
        img.crop_imm(
            (img.width() - side) / 2,
            (img.height() - side) / 2,
            side,
            side,
        )
        .thumbnail(512, 512)
    } else {
        img.thumbnail(1600, 1600)
    };
    let mut buffer = Cursor::new(Vec::new());
    img.write_to(&mut buffer, ImageFormat::WebP).ok()?;
    Some(buffer.into_inner())
}
pub async fn avatar(
    State(app): State<App>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response> {
    let profile = required(&app, &jar).await?;
    let hidden: bool = sqlx::query_scalar("SELECT avatar_hidden FROM accounts WHERE id=$1")
        .bind(profile.id)
        .fetch_one(&app.0.db)
        .await?;
    if hidden {
        return Err(ApiError(StatusCode::NOT_FOUND, "avatar_missing"));
    }
    serve_avatar(&app, profile.id, &headers).await
}
pub async fn serve_avatar(app: &App, account: Uuid, headers: &HeaderMap) -> Result<Response> {
    let (object_id, legacy): (Option<Uuid>, Option<Vec<u8>>) =
        sqlx::query_as("SELECT avatar_object_id, avatar FROM accounts WHERE id=$1")
            .bind(account)
            .fetch_optional(&app.0.db)
            .await?
            .ok_or(ApiError(StatusCode::NOT_FOUND, "avatar_missing"))?;
    match object_id {
        Some(id) => media::serve(app, id, "image/webp", headers).await,
        None => legacy
            .map(media::legacy_image)
            .ok_or(ApiError(StatusCode::NOT_FOUND, "avatar_missing")),
    }
}
pub(crate) async fn completed(app: &App, jar: &CookieJar) -> Result<Profile> {
    let profile = required(app, jar).await?;
    if profile.username.is_none() {
        return Err(ApiError(StatusCode::FORBIDDEN, "profile_required"));
    }
    Ok(profile)
}

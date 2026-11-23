use std::{
    env,
    time::{Duration, SystemTime},
};

use aws_credential_types::Credentials;
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        UriPathNormalizationMode, sign,
    },
    sign::v4,
};
use axum::{
    body::{Body, Bytes},
    extract::multipart::Field,
    http::{HeaderMap, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use reqwest::{Client, Url};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::{
    ApiError, App, Result,
    auth::{RATE, UNAVAILABLE},
    profile,
};

const MIB: usize = 1024 * 1024;
pub const IMAGE_LIMIT: usize = 5 * MIB;
pub const POST_LIMIT: usize = 96 * MIB;
pub const MAX_ATTACHMENTS: usize = 4;
pub const INVALID_MEDIA: ApiError = ApiError(StatusCode::BAD_REQUEST, "post_media_invalid");
const STORAGE_UNAVAILABLE: ApiError =
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "media_unavailable");
const IMAGE_MIME: &str = "image/webp";

pub struct Store {
    client: Client,
    bucket: Url,
    region: String,
    credentials: Credentials,
}

impl Store {
    pub fn from_env(secure: bool) -> anyhow::Result<Option<Self>> {
        let read = |name| env::var(name).ok().filter(|value| !value.is_empty());
        let Some(endpoint) = read("S3_ENDPOINT") else {
            anyhow::ensure!(
                ["S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"]
                    .iter()
                    .all(|name| read(*name).is_none()),
                "S3_ENDPOINT is required when S3 credentials or a bucket are configured"
            );
            return Ok(None);
        };
        let mut bucket = Url::parse(&endpoint)?;
        anyhow::ensure!(
            (bucket.scheme() == "https" || (!secure && bucket.scheme() == "http"))
                && bucket.host_str().is_some()
                && bucket.username().is_empty()
                && bucket.password().is_none()
                && bucket.query().is_none()
                && bucket.fragment().is_none(),
            "S3_ENDPOINT must be an HTTP(S) endpoint without credentials, query or fragment"
        );
        let bucket_name = env::var("S3_BUCKET")?;
        anyhow::ensure!(
            !bucket_name.is_empty()
                && bucket_name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b)),
            "S3_BUCKET must be an S3 bucket name"
        );
        bucket
            .path_segments_mut()
            .map_err(|()| anyhow::anyhow!("invalid S3 endpoint"))?
            .pop_if_empty()
            .push(&bucket_name);
        let access_key = read("S3_ACCESS_KEY_ID")
            .ok_or_else(|| anyhow::anyhow!("S3_ACCESS_KEY_ID is required"))?;
        let secret_key = read("S3_SECRET_ACCESS_KEY")
            .ok_or_else(|| anyhow::anyhow!("S3_SECRET_ACCESS_KEY is required"))?;
        Ok(Some(Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .read_timeout(Duration::from_secs(30))
                .build()?,
            bucket,
            region: read("S3_REGION").unwrap_or_else(|| "us-east-1".into()),
            credentials: Credentials::new(
                access_key,
                secret_key,
                read("S3_SESSION_TOKEN"),
                None,
                "killerwave",
            ),
        }))
    }

    async fn send(
        &self,
        method: Method,
        id: Uuid,
        mime: Option<&str>,
        range: Option<&str>,
        data: Bytes,
    ) -> Result<reqwest::Response> {
        let mut url = self.bucket.clone();
        url.path_segments_mut()
            .map_err(|()| STORAGE_UNAVAILABLE)?
            .push("media")
            .push(&id.to_string());
        let mut headers = Vec::new();
        if let Some(mime) = mime {
            headers.push(("content-type", mime));
        }
        if let Some(range) = range {
            headers.push(("range", range));
        }
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        let identity = self.credentials.clone().into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("s3")
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|_| STORAGE_UNAVAILABLE)?
            .into();
        let request = SignableRequest::new(
            method.as_str(),
            url.as_str(),
            headers.iter().copied(),
            SignableBody::Bytes(&data),
        )
        .map_err(|_| STORAGE_UNAVAILABLE)?;
        let (signature, _) = sign(request, &params)
            .map_err(|_| STORAGE_UNAVAILABLE)?
            .into_parts();
        let upload = method == Method::PUT;
        let mut request = self.client.request(method, url);
        for (name, value) in headers.into_iter().chain(signature.headers()) {
            request = request.header(name, value);
        }
        if upload {
            request = request.body(data).timeout(Duration::from_secs(120));
        }
        request.send().await.map_err(|_| STORAGE_UNAVAILABLE)
    }
}

pub struct Upload {
    pub mime: &'static str,
    pub kind: &'static str,
    pub title: String,
    pub bytes: Bytes,
}

pub async fn read(mut field: Field<'_>, limit: usize, invalid: ApiError) -> Result<Bytes> {
    let mut data = Vec::new();
    let error = || ApiError(invalid.0, invalid.1);
    while let Some(chunk) = field.chunk().await.map_err(|_| error())? {
        if data.len() + chunk.len() > limit {
            return Err(error());
        }
        data.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(data))
}

pub async fn photo(app: &App, bytes: Bytes, avatar: bool, invalid: ApiError) -> Result<Upload> {
    let permit = app
        .0
        .image_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| RATE)?;
    let bytes = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        profile::encode_image(&bytes, avatar)
    })
    .await
    .map_err(|_| UNAVAILABLE)?
    .ok_or(invalid)?;
    Ok(Upload {
        mime: IMAGE_MIME,
        kind: "image",
        title: String::new(),
        bytes: Bytes::from(bytes),
    })
}

pub async fn attachment(app: &App, field: Field<'_>, legacy_image: bool) -> Result<Upload> {
    let mime = field.content_type().unwrap_or_default().to_owned();
    let title = field
        .file_name()
        .unwrap_or_default()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect::<String>();
    let title = title
        .rsplit_once('.')
        .map_or(title.as_str(), |(name, _)| name)
        .trim()
        .to_owned();
    if legacy_image || matches!(mime.as_str(), "image/jpeg" | "image/png" | "image/webp") {
        let bytes = read(field, IMAGE_LIMIT, INVALID_MEDIA).await?;
        return photo(app, bytes, false, INVALID_MEDIA).await;
    }
    let (kind, mime, limit) = match mime.as_str() {
        "video/mp4" => ("video", "video/mp4", 64 * MIB),
        "video/webm" => ("video", "video/webm", 64 * MIB),
        "audio/mpeg" | "audio/mp3" => ("audio", "audio/mpeg", 16 * MIB),
        "audio/mp4" | "audio/x-m4a" => ("audio", "audio/mp4", 16 * MIB),
        "audio/ogg" => ("audio", "audio/ogg", 16 * MIB),
        "audio/wav" | "audio/x-wav" | "audio/vnd.wave" => ("audio", "audio/wav", 16 * MIB),
        _ => return Err(INVALID_MEDIA),
    };
    let bytes = read(field, limit, INVALID_MEDIA).await?;
    let valid = match mime {
        "video/mp4" | "audio/mp4" => bytes.get(4..8) == Some(b"ftyp"),
        "video/webm" => bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]),
        "audio/mpeg" => {
            bytes.starts_with(b"ID3")
                || bytes
                    .get(0..2)
                    .is_some_and(|head| head[0] == 0xff && head[1] & 0xe0 == 0xe0)
        }
        "audio/ogg" => bytes.starts_with(b"OggS"),
        "audio/wav" => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WAVE"),
        _ => false,
    };
    if !valid {
        return Err(INVALID_MEDIA);
    }
    Ok(Upload {
        mime,
        kind,
        title,
        bytes,
    })
}

pub async fn stage(app: &App, upload: &Upload) -> Result<Uuid> {
    let store = app.0.media.as_ref().ok_or(STORAGE_UNAVAILABLE)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO media_gc VALUES ($1, now() + interval '1 hour')")
        .bind(id)
        .execute(&app.0.db)
        .await?;
    let response = store
        .send(
            Method::PUT,
            id,
            Some(upload.mime),
            None,
            upload.bytes.clone(),
        )
        .await?;
    if !response.status().is_success() {
        return Err(STORAGE_UNAVAILABLE);
    }
    sqlx::query("INSERT INTO media_sizes(object_id,bytes) VALUES ($1,$2)")
        .bind(id)
        .bind(upload.bytes.len() as i64)
        .execute(&app.0.db)
        .await?;
    Ok(id)
}

pub async fn retain(db: &mut PgConnection, id: Uuid) -> Result<()> {
    let deleted = sqlx::query("DELETE FROM media_gc WHERE object_id=$1 AND delete_after > now()")
        .bind(id)
        .execute(db)
        .await?
        .rows_affected();
    if deleted != 1 {
        return Err(STORAGE_UNAVAILABLE);
    }
    Ok(())
}

pub async fn serve(app: &App, id: Uuid, mime: &str, headers: &HeaderMap) -> Result<Response> {
    let store = app.0.media.as_ref().ok_or(STORAGE_UNAVAILABLE)?;
    let range = headers
        .get(header::RANGE)
        .and_then(|range| range.to_str().ok());
    let response = store
        .send(Method::GET, id, None, range, Bytes::new())
        .await?;
    let status = response.status();
    match status {
        StatusCode::OK | StatusCode::PARTIAL_CONTENT | StatusCode::RANGE_NOT_SATISFIABLE => {}
        StatusCode::NOT_FOUND => return Err(ApiError(StatusCode::NOT_FOUND, "media_missing")),
        _ => return Err(STORAGE_UNAVAILABLE),
    }
    let mut result = Response::builder()
        .status(status)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_TYPE, mime)
        .header("cross-origin-resource-policy", "same-origin");
    for name in [header::CONTENT_LENGTH, header::CONTENT_RANGE] {
        if status != StatusCode::RANGE_NOT_SATISFIABLE || name == header::CONTENT_RANGE {
            if let Some(value) = response.headers().get(&name) {
                result = result.header(name, value);
            }
        }
    }
    let body = if status == StatusCode::RANGE_NOT_SATISFIABLE {
        Body::empty()
    } else {
        Body::from_stream(response.bytes_stream())
    };
    result.body(body).map_err(|_| STORAGE_UNAVAILABLE)
}

pub fn legacy_image(data: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE.as_str(), IMAGE_MIME),
            ("cross-origin-resource-policy", "same-origin"),
        ],
        data,
    )
        .into_response()
}

pub async fn collect(app: App) {
    let Some(store) = app.0.media.as_ref() else {
        return;
    };
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if collect_due(store, &app.0.db).await.is_err() {
            eprintln!("private media cleanup failed");
        }
    }
}

async fn collect_due(store: &Store, db: &PgPool) -> Result<()> {
    for _ in 0..20 {
        let mut tx = db.begin().await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT object_id FROM media_gc WHERE delete_after <= now()
             ORDER BY delete_after LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(id) = id else {
            break;
        };
        let response = store
            .send(Method::DELETE, id, None, None, Bytes::new())
            .await;
        let sql = if response
            .is_ok_and(|r| r.status().is_success() || r.status() == StatusCode::NOT_FOUND)
        {
            sqlx::query("DELETE FROM media_sizes WHERE object_id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            "DELETE FROM media_gc WHERE object_id=$1"
        } else {
            "UPDATE media_gc SET delete_after=now() + interval '5 minutes' WHERE object_id=$1"
        };
        sqlx::query(sql).bind(id).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    Ok(())
}

pub async fn measure(app: App) {
    let Some(store) = app.0.media.as_ref() else {
        return;
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cursor = None::<Uuid>;
    loop {
        ticker.tick().await;
        let rows = sqlx::query_scalar::<_,Uuid>(
            "WITH files AS (
                SELECT object_id FROM post_media UNION SELECT avatar_object_id FROM accounts WHERE avatar_object_id IS NOT NULL
                UNION SELECT banner_object_id FROM accounts WHERE banner_object_id IS NOT NULL
             ) SELECT object_id FROM files WHERE ($1::uuid IS NULL OR object_id>$1)
               AND NOT EXISTS (SELECT 1 FROM media_sizes s WHERE s.object_id=files.object_id)
             ORDER BY object_id LIMIT 20"
        ).bind(cursor).fetch_all(&app.0.db).await;
        let Ok(rows) = rows else {
            continue;
        };
        cursor = rows.last().copied();
        for id in rows {
            let Ok(response) = store.send(Method::HEAD, id, None, None, Bytes::new()).await else {
                continue;
            };
            if !response.status().is_success() {
                continue;
            }
            if let Some(bytes) = response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<i64>().ok())
            {
                let _ = sqlx::query("INSERT INTO media_sizes(object_id,bytes) VALUES ($1,$2) ON CONFLICT DO NOTHING")
                    .bind(id).bind(bytes).execute(&app.0.db).await;
            }
        }
    }
}

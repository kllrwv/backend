use std::{env, io::Read, time::Duration};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::CookieJar;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flate2::read::GzDecoder;
use reqwest::{Client, header::CONTENT_ENCODING};
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents, UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ApiError, App, Result,
    auth::{
        EXPIRED, FlowView, Lang, Mode, UNAVAILABLE, begin_login_flow, clear, code_matches,
        confirm_telegram_registration, cookie, create_session, digest, key, pending_registration,
        rate, token,
    },
};

const ISSUER: &str = "https://oauth.telegram.org";
const JWKS_URL: &str = "https://oauth.telegram.org/.well-known/jwks.json";
const FLOW_COOKIE: &str = "kw_telegram_popup";
const FLOW_SECONDS: i64 = 600;
const NOT_CONFIGURED: ApiError = ApiError(StatusCode::SERVICE_UNAVAILABLE, "bot_unavailable");
const FAILED: ApiError = ApiError(StatusCode::UNAUTHORIZED, "telegram_failed");

pub struct Provider {
    client_id: u64,
    http: Client,
}

impl Provider {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let client_id = env::var("TELEGRAM_LOGIN_CLIENT_ID").unwrap_or_default();
        let client_id = client_id.trim();
        if client_id.is_empty() {
            return Ok(None);
        }
        let client_id = client_id
            .parse::<u64>()
            .ok()
            .filter(|id| (1..=9_007_199_254_740_991).contains(id))
            .ok_or_else(|| anyhow::anyhow!("invalid TELEGRAM_LOGIN_CLIENT_ID from BotFather"))?;
        let http = Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Some(Self { client_id, http }))
    }

    async fn telegram_id(&self, id_token: &str, nonce: &str) -> Result<i64> {
        let response = self
            .http
            .get(JWKS_URL)
            .send()
            .await
            .map_err(log_key_request_error)?
            .error_for_status()
            .map_err(log_key_request_error)?;
        let gzip = response
            .headers()
            .get(CONTENT_ENCODING)
            .is_some_and(|encoding| encoding.as_bytes().eq_ignore_ascii_case(b"gzip"));
        let body = response.bytes().await.map_err(log_key_request_error)?;
        let keys = decode_keys(&body, gzip).map_err(|error| {
            eprintln!("telegram public key response could not be decoded: {error}");
            UNAVAILABLE
        })?;
        telegram_id_from_token(
            id_token,
            keys,
            self.client_id,
            nonce,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|reason| {
            eprintln!("telegram popup token rejected: {reason:?}");
            FAILED
        })
    }
}

fn decode_keys(body: &[u8], gzip: bool) -> serde_json::Result<KeySet> {
    if gzip {
        serde_json::from_reader(GzDecoder::new(body).take(64 * 1024))
    } else {
        serde_json::from_slice(body)
    }
}

fn log_key_request_error(error: reqwest::Error) -> ApiError {
    // This request uses the public JWKS URL and carries no login credentials.
    eprintln!("telegram public key request failed: {error:?}");
    UNAVAILABLE
}

#[derive(Deserialize)]
pub struct StartRequest {
    mode: Mode,
}

#[derive(Serialize)]
pub struct Start {
    client_id: u64,
    nonce: String,
}

pub async fn start(
    State(app): State<App>,
    jar: CookieJar,
    Json(input): Json<StartRequest>,
) -> Result<(CookieJar, Json<Start>)> {
    let provider = app.0.telegram_web.as_ref().ok_or(NOT_CONFIGURED)?;
    let registration = match input.mode {
        Mode::Login => None,
        Mode::Register => {
            if app.0.bot.is_none() {
                return Err(NOT_CONFIGURED);
            }
            Some(pending_registration(&app, &jar).await?)
        }
    };
    rate(&app, "telegram web budget", 120, 60).await?;
    let jar = cancel(&app, jar).await?;
    let ticket = token();
    let nonce = key(&app, "telegram popup nonce", &ticket);
    sqlx::query("INSERT INTO telegram_web_flows(browser_key, registration_key) VALUES($1,$2)")
        .bind(digest(&ticket))
        .bind(registration)
        .execute(&app.0.db)
        .await?;
    Ok((
        jar.add(cookie(&app, FLOW_COOKIE, ticket, FLOW_SECONDS)),
        Json(Start {
            client_id: provider.client_id,
            nonce,
        }),
    ))
}

pub async fn cancel(app: &App, jar: CookieJar) -> Result<CookieJar> {
    if let Some(flow) = jar.get(FLOW_COOKIE) {
        sqlx::query("DELETE FROM telegram_web_flows WHERE browser_key=$1")
            .bind(digest(flow.value()))
            .execute(&app.0.db)
            .await?;
    }
    Ok(clear(app, jar, FLOW_COOKIE))
}

#[derive(Deserialize)]
pub struct Confirmation {
    id_token: String,
    lang: Option<Lang>,
}

#[derive(Serialize)]
pub struct Confirmed {
    flow: Option<FlowView>,
}

pub async fn confirm(
    State(app): State<App>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(input): Json<Confirmation>,
) -> Result<(CookieJar, Json<Confirmed>)> {
    let provider = app.0.telegram_web.as_ref().ok_or(NOT_CONFIGURED)?;
    let ticket = jar.get(FLOW_COOKIE).ok_or(EXPIRED)?.value();
    let nonce = key(&app, "telegram popup nonce", ticket);
    let registration: Option<String> = sqlx::query_scalar(
        "DELETE FROM telegram_web_flows WHERE browser_key=$1 AND expires_at>now()
         RETURNING registration_key",
    )
    .bind(digest(ticket))
    .fetch_optional(&app.0.db)
    .await?
    .ok_or(EXPIRED)?;
    let id = provider.telegram_id(&input.id_token, &nonce).await?;
    let jar = clear(&app, jar, FLOW_COOKIE);

    if let Some(registration) = registration {
        let flow = confirm_telegram_registration(&app, &jar, &registration, id).await?;
        return Ok((jar, Json(Confirmed { flow: Some(flow) })));
    }
    let account: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM accounts WHERE telegram_id=$1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&app.0.db)
            .await?;
    let account = account.ok_or(ApiError(StatusCode::UNAUTHORIZED, "unlinked"))?;
    let mut tx = app.0.db.begin().await?;
    if let Some(generation) = crate::auth::totp::lock_account(&mut tx, account)
        .await?
        .generation
    {
        let (jar, flow) = begin_login_flow(
            &app,
            &mut tx,
            jar,
            account,
            Some(generation),
            input.lang.unwrap_or(Lang::Ru),
        )
        .await?;
        tx.commit().await?;
        return Ok((jar, Json(Confirmed { flow: Some(flow) })));
    }
    let session = create_session(&app, &mut tx, jar, account, &headers).await?;
    tx.commit().await?;
    Ok((session, Json(Confirmed { flow: None })))
}

#[derive(Deserialize)]
struct KeySet {
    keys: Vec<SigningKey>,
}

#[derive(Deserialize)]
struct SigningKey {
    kid: Option<String>,
    kty: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

#[derive(Deserialize)]
struct TokenHeader {
    alg: String,
    kid: String,
    crit: Option<serde_json::Value>,
    b64: Option<bool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(Identifier),
    List(Vec<Identifier>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Identifier {
    Text(String),
    Number(u64),
}

impl Identifier {
    fn number(&self) -> Option<u64> {
        match self {
            Self::Number(number) => Some(*number),
            Self::Text(text) if text.bytes().all(|byte| byte.is_ascii_digit()) => text.parse().ok(),
            Self::Text(_) => None,
        }
    }

    fn matches(&self, expected: u64) -> bool {
        match self {
            Self::Text(text) => text == &expected.to_string(),
            Self::Number(number) => *number == expected,
        }
    }
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    sub: String,
    nonce: Option<String>,
    id: Option<Identifier>,
    iat: i64,
    exp: i64,
    nbf: Option<i64>,
    azp: Option<Identifier>,
}

#[derive(Debug, PartialEq, Eq)]
enum TokenRejection {
    Encoding,
    Algorithm,
    Key,
    Signature,
    Claims,
    Issuer,
    Audience,
    Nonce,
    Subject,
    TelegramId,
    Time,
}

fn verify_signature(
    header: &TokenHeader,
    keys: KeySet,
    signed: &[u8],
    signature: &[u8],
) -> std::result::Result<(), TokenRejection> {
    use TokenRejection::{Algorithm, Key, Signature};
    if header.crit.is_some()
        || header.b64 == Some(false)
        || !matches!(header.alg.as_str(), "RS256" | "ES256")
    {
        return Err(Algorithm);
    }
    let key = keys
        .keys
        .into_iter()
        .find(|key| {
            key.kid.as_deref() == Some(&header.kid)
                && key.alg.as_deref().is_none_or(|alg| alg == header.alg)
                && matches!(key.usage.as_deref(), Some("sig") | None)
        })
        .ok_or(Key)?;
    let decode = |part: Option<String>| URL_SAFE_NO_PAD.decode(part.ok_or(Key)?).map_err(|_| Key);
    match (header.alg.as_str(), key.kty.as_str()) {
        ("RS256", "RSA") => RsaPublicKeyComponents {
            n: decode(key.n)?,
            e: decode(key.e)?,
        }
        .verify(&RSA_PKCS1_2048_8192_SHA256, signed, signature),
        ("ES256", "EC") if key.crv.as_deref() == Some("P-256") => {
            let x = decode(key.x)?;
            let y = decode(key.y)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(Key);
            }
            let mut point = [0x04; 65];
            point[1..33].copy_from_slice(&x);
            point[33..].copy_from_slice(&y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point).verify(signed, signature)
        }
        _ => return Err(Key),
    }
    .map_err(|_| Signature)
}

fn telegram_id_from_token(
    token: &str,
    keys: KeySet,
    client_id: u64,
    nonce: &str,
    now: i64,
) -> std::result::Result<i64, TokenRejection> {
    use TokenRejection::Encoding;
    let (signed, signature) = token.rsplit_once('.').ok_or(Encoding)?;
    let (header, payload) = signed.split_once('.').ok_or(Encoding)?;
    let decode = |part| URL_SAFE_NO_PAD.decode(part).map_err(|_| Encoding);
    let header: TokenHeader = serde_json::from_slice(&decode(header)?).map_err(|_| Encoding)?;
    verify_signature(&header, keys, signed.as_bytes(), &decode(signature)?)?;
    let claims: Claims =
        serde_json::from_slice(&decode(payload)?).map_err(|_| TokenRejection::Claims)?;
    if claims.iss != ISSUER {
        return Err(TokenRejection::Issuer);
    }
    let matches_audience = match &claims.aud {
        Audience::One(audience) => audience.matches(client_id),
        Audience::List(audiences) => {
            matches!(audiences.as_slice(), [audience] if audience.matches(client_id))
        }
    };
    if !matches_audience || claims.azp.is_some_and(|azp| !azp.matches(client_id)) {
        return Err(TokenRejection::Audience);
    }
    if !code_matches(nonce, claims.nonce.as_deref()) {
        return Err(TokenRejection::Nonce);
    }
    if claims.sub.is_empty() {
        return Err(TokenRejection::Subject);
    }
    if !(now - FLOW_SECONDS..=now + 30).contains(&claims.iat)
        || claims.exp <= now
        || claims.exp < claims.iat
        || claims.nbf.is_some_and(|nbf| nbf > now)
    {
        return Err(TokenRejection::Time);
    }
    claims
        .id
        .and_then(|id| id.number())
        .filter(|id| (1..(1 << 52)).contains(id))
        .map(|id| id as i64)
        .ok_or(TokenRejection::TelegramId)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signed with a disposable test key; only its public component is used here.
    const SAMPLE_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUifQ.eyJpc3MiOiJodHRwczovL29hdXRoLnRlbGVncmFtLm9yZyIsImF1ZCI6IjEyMzQ1Iiwic3ViIjoib3BhcXVlLWZpeHR1cmUiLCJub25jZSI6InRlc3Qtbm9uY2UiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MTcwMDAwMzYwMCwiaWQiOjk4NzY1NDMyMX0.27SMqtqsv4X6hXdnAwa8CL2zKtNQf8aksVS0iQXajzJibEeIi2SZE8dTOzCulIygmNX7Y-XKZw0NyPZ0ft3iPqPZq522E-MqCCb1APcX7mar9jyxPofH2LjKaE4hfyUDNlpnpKf31HVC7EmAaUgEGSPfRB5kA_HzUdLO9mrSscCWep0xewxLBye6sA2yARGUp7IkOqAInu6ezn_IJkyCMUmrvfWm1BHAEDVoTFX0qkslQp4npkyoPYhbbK45Au9TV8Pc427xvk642KFOsGIqSafJE7HHvDnQsnqgGz87zzemvz-wB615HJmtWcP1Y8sRzEPh6d-R1bNVc-mLydEPyw";
    const SAMPLE_KEYS: &str = r#"{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"fixture","n":"6X7MQ7FZVePsAV_3NCCLrV8DcQRZOFylWRMENNg7uI-B1swsArz0xYCPeueR2h6m1L7jdYcd_dozSc5LaoQknft_zfbarYdnwCCl_pui2zNeXtA36DB8k70_4T1awp_Q10sKFHZyy3air-qOt-s8CqlmHHVn2fpMHCbbY-nKK9jq03WX4n9izeLV8naJPA8kI7yJ7ymUF79FK7l7PYKcHq6uvgERJwNwBku48KLCkILAG3IQWGOcIC6-UPSywAS8vXEDyeb7QT5ECXcOflBwTum0HXwp6Yrf2Fmi8Wffi6yMshwEH8IZWQtF7Av2MaUKom51HKTCcuDrvgWKQDL8cw","e":"AQAB"}]}"#;

    #[test]
    fn checks_telegram_signature_audience_expiry_and_popup_nonce() {
        let verify = |token, client, nonce, now| {
            telegram_id_from_token(
                token,
                serde_json::from_str(SAMPLE_KEYS).unwrap(),
                client,
                nonce,
                now,
            )
        };
        assert_eq!(
            verify(SAMPLE_TOKEN, 12345, "test-nonce", 1_700_000_100),
            Ok(987654321)
        );
        assert_eq!(
            verify(SAMPLE_TOKEN, 54321, "test-nonce", 1_700_000_100),
            Err(TokenRejection::Audience)
        );
        assert_eq!(
            verify(SAMPLE_TOKEN, 12345, "another-nonce", 1_700_000_100),
            Err(TokenRejection::Nonce)
        );
        assert_eq!(
            verify(SAMPLE_TOKEN, 12345, "test-nonce", 1_700_003_600),
            Err(TokenRejection::Time)
        );

        let (signed, signature) = SAMPLE_TOKEN.rsplit_once('.').unwrap();
        let (header, payload) = signed.split_once('.').unwrap();
        let mut claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        claims["id"] = serde_json::json!(42);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        assert_eq!(
            verify(
                &format!("{header}.{payload}.{signature}"),
                12345,
                "test-nonce",
                1_700_000_100
            ),
            Err(TokenRejection::Signature)
        );
    }

    #[test]
    fn verifies_es256_and_normalizes_telegram_identifiers() {
        use ring::{
            rand::SystemRandom,
            signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
        };
        use serde_json::json;

        let rng = SystemRandom::new();
        let algorithm = &ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(algorithm, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8.as_ref(), &rng).unwrap();
        let point = pair.public_key().as_ref();
        let keys = json!({"keys": [{
            "kid": "ec-fixture", "kty": "EC", "alg": "ES256", "use": "sig", "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..])
        }]});
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"ec-fixture"}"#);
        let mut claims = json!({
            "iss": ISSUER, "aud": 12345, "azp": 12345, "sub": "opaque",
            "nonce": "test-nonce", "id": "987654321", "iat": 1700000000, "exp": 1700003600
        });
        let verify = |claims: &serde_json::Value| {
            let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
            let signed = format!("{header}.{payload}");
            let signature = pair.sign(&rng, signed.as_bytes()).unwrap();
            let token = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()));
            telegram_id_from_token(
                &token,
                serde_json::from_value(keys.clone()).unwrap(),
                12345,
                "test-nonce",
                1_700_000_100,
            )
        };
        assert_eq!(verify(&claims), Ok(987654321));
        claims["aud"] = json!([12345, 54321]);
        assert_eq!(verify(&claims), Err(TokenRejection::Audience));
        claims["aud"] = json!([12345]);
        claims["nonce"] = json!(null);
        assert_eq!(verify(&claims), Err(TokenRejection::Nonce));
        claims["nonce"] = json!("test-nonce");
        claims["id"] = json!(null);
        assert_eq!(verify(&claims), Err(TokenRejection::TelegramId));
    }

    #[test]
    fn verifies_tokens_using_a_gzipped_telegram_key_set() {
        use flate2::{Compression, write::GzEncoder};
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(SAMPLE_KEYS.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        for (body, gzip) in [
            (SAMPLE_KEYS.as_bytes(), false),
            (compressed.as_slice(), true),
        ] {
            assert_eq!(
                telegram_id_from_token(
                    SAMPLE_TOKEN,
                    decode_keys(body, gzip).unwrap(),
                    12345,
                    "test-nonce",
                    1_700_000_100
                ),
                Ok(987654321)
            );
        }
    }
}

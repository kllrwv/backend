use super::{Service, WebPushBuilder, browser_keys, endpoint};
use crate::{App, Result};
use serde::Serialize;
use std::time::Duration;
use tokio::{
    task::JoinSet,
    time::{MissedTickBehavior, interval},
};
use uuid::Uuid;
#[derive(sqlx::FromRow)]
struct Delivery {
    id: i64,
    kind: String,
    variant: Option<i16>,
    attempts: i16,
    session_id: String,
    endpoint: String,
    p256dh: String,
    auth: String,
    lang: String,
    event_kind: Option<String>,
    actor_name: Option<String>,
    actor_username: Option<String>,
    post_username: Option<String>,
    post_id: Option<Uuid>,
    excerpt: Option<String>,
    timestamp: i64,
    sound: bool,
}
#[derive(Serialize)]
struct Payload {
    title: String,
    body: String,
    url: String,
    tag: String,
    timestamp: i64,
    silent: bool,
    lang: String,
}
impl Delivery {
    fn payload(&self, app: &App) -> Option<Payload> {
        let copy = &app.0.translations.get(&self.lang).web_push;
        let text = match self.kind.as_str() {
            "reminders" => copy.reminders.get(self.variant? as usize)?,
            "activity" => {
                let kind = self.event_kind.as_deref()?;
                copy.events
                    .get(if kind == "mention" && self.post_id.is_none() {
                        "profile_mention"
                    } else {
                        kind
                    })?
            }
            kind => copy.events.get(kind)?,
        };
        let post_url = self
            .post_username
            .as_deref()
            .zip(self.post_id)
            .map(|(name, post)| format!("/@{name}/post/{post}"));
        let url = match self.kind.as_str() {
            "reminders" => "/".to_owned(),
            "following" | "recommendations" => post_url?,
            "activity" => post_url
                .or_else(|| self.actor_username.as_ref().map(|name| format!("/@{name}")))
                .unwrap_or_else(|| "/notifications".to_owned()),
            _ => "/notifications".to_owned(),
        };
        let name = self.actor_name.as_deref().unwrap_or("");
        let mut body = text.body.replace("{name}", name);
        if matches!(self.kind.as_str(), "following" | "recommendations") {
            let excerpt = self
                .excerpt
                .as_deref()
                .unwrap_or("")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if !excerpt.is_empty() {
                body.push_str(&format!(" · {excerpt}"));
            }
        }
        Some(Payload {
            title: text.title.replace("{name}", name),
            body,
            url,
            tag: format!("kw-{}", self.id),
            timestamp: self.timestamp,
            silent: !self.sound,
            lang: self.lang.clone(),
        })
    }
    async fn send(&self, service: &Service, payload: Payload) -> Outcome {
        let Some(url) = endpoint(&self.endpoint) else {
            return Outcome::Expired;
        };
        let Some((public_key, auth)) = browser_keys(&self.p256dh, &self.auth) else {
            return Outcome::Expired;
        };
        let Ok(uri) = url.as_str().parse() else {
            return Outcome::Expired;
        };
        let Ok(data) = serde_json::to_vec(&payload) else {
            return Outcome::Finish;
        };
        let Ok(request) = WebPushBuilder::new(uri, public_key, auth)
            .with_valid_duration(Duration::from_secs(14_400))
            .with_vapid(&service.key, &service.subject)
            .build(data)
        else {
            return Outcome::Finish;
        };
        let (parts, body) = request.into_parts();
        let response = service
            .http
            .post(url)
            .headers(parts.headers)
            .body(body)
            .send()
            .await;
        let Ok(response) = response else {
            return Outcome::Retry(self.delay());
        };
        let status = response.status();
        match status.as_u16() {
            404 | 410 => Outcome::Expired,
            429 | 500..=599 => {
                let wait = response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or_else(|| self.delay());
                Outcome::Retry(wait.clamp(30, 3600))
            }
            200..=299 => Outcome::Finish,
            _ => {
                eprintln!("web push rejected: http {}", status.as_u16());
                Outcome::Finish
            }
        }
    }
    fn delay(&self) -> i64 {
        30 * (1_i64 << self.attempts.clamp(0, 6))
    }
}
enum Outcome {
    Finish,
    Expired,
    Retry(i64),
}
pub async fn run(app: App) {
    tokio::join!(deliveries(app.clone()), scheduled(app));
}
async fn deliveries(app: App) {
    let mut ticker = interval(Duration::from_secs(3));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let ids = sqlx::query_scalar::<_, i64>("WITH ready AS (
            SELECT id FROM web_push_jobs WHERE available_at<=now() AND attempts<5 AND created_at>now()-interval '12 hours'
            ORDER BY available_at,id LIMIT 12 FOR UPDATE SKIP LOCKED
        ) UPDATE web_push_jobs j SET attempts=j.attempts+1,available_at=now()+interval '90 seconds'
          FROM ready WHERE j.id=ready.id RETURNING j.id").fetch_all(&app.0.db).await;
        let Ok(ids) = ids else {
            eprintln!("web push queue read failed");
            continue;
        };
        let mut workers = JoinSet::new();
        for id in ids {
            workers.spawn(deliver(app.clone(), id));
        }
        while let Some(result) = workers.join_next().await {
            if !matches!(result, Ok(Ok(()))) {
                eprintln!("web push delivery could not update queue");
            }
        }
    }
}
async fn deliver(app: App, id: i64) -> Result<()> {
    let job: Option<Delivery> = sqlx::query_as(include_str!("delivery.sql"))
        .bind(id)
        .fetch_optional(&app.0.db)
        .await?;
    if let (Some(job), Some(service)) = (job, app.0.push.as_ref()) {
        if let Some(payload) = job.payload(&app) {
            match job.send(service, payload).await {
                Outcome::Expired => {
                    sqlx::query(
                        "DELETE FROM web_push_subscriptions WHERE session_id=$1 AND endpoint=$2",
                    )
                    .bind(&job.session_id)
                    .bind(&job.endpoint)
                    .execute(&app.0.db)
                    .await?;
                }
                Outcome::Retry(wait) if job.attempts < 5 => {
                    sqlx::query("UPDATE web_push_jobs SET available_at=now()+$2::integer*interval '1 second' WHERE id=$1")
                        .bind(id).bind(wait as i32).execute(&app.0.db).await?;
                    return Ok(());
                }
                _ => {}
            }
        }
    }
    sqlx::query("DELETE FROM web_push_jobs WHERE id=$1")
        .bind(id)
        .execute(&app.0.db)
        .await?;
    Ok(())
}
async fn scheduled(app: App) {
    let mut ticker = interval(Duration::from_secs(900));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if schedule(&app).await.is_err() {
            eprintln!("web push scheduling failed");
        }
    }
}
async fn schedule(app: &App) -> Result<()> {
    let mut tx = app.0.db.begin().await?;
    if !sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock(73460650021403)")
        .fetch_one(&mut *tx)
        .await?
    {
        return Ok(());
    }
    let variants = app
        .0
        .translations
        .ru
        .web_push
        .reminders
        .len()
        .min(app.0.translations.en.web_push.reminders.len());
    sqlx::query("DELETE FROM web_push_jobs WHERE created_at<=now()-interval '12 hours' OR (attempts>=5 AND available_at<=now())")
        .execute(&mut *tx).await?;
    sqlx::query(include_str!("recommendations.sql"))
        .execute(&mut *tx)
        .await?;
    if variants > 1 {
        sqlx::query(include_str!("reminders.sql"))
            .bind(variants as i32)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

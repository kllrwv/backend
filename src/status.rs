use crate::App;
use axum::{Json, extract::State};
use serde::Serialize;
use std::time::{Duration, Instant};
const SERVICES: [(&str, &str); 4] = [
    ("database", "SELECT 1"),
    ("auth", "SELECT id FROM sessions LIMIT 1"),
    ("feed", "SELECT id FROM posts LIMIT 1"),
    ("media", "SELECT post_id FROM post_media LIMIT 1"),
];
#[derive(Serialize, sqlx::FromRow)]
struct Sample {
    service: String,
    minute: i64,
    state: String,
}
#[derive(Serialize)]
pub struct Status {
    minute: i64,
    current: Vec<Sample>,
    history: Vec<Sample>,
}
fn minute() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp() / 60
}
async fn sample(app: &App) -> Vec<Sample> {
    let checked_at = minute();
    let mut results = Vec::with_capacity(SERVICES.len());
    for (service, query) in SERVICES {
        let started = Instant::now();
        let state = match tokio::time::timeout(
            Duration::from_millis(800),
            sqlx::query(query).fetch_optional(&app.0.db),
        )
        .await
        {
            Ok(Ok(_)) if started.elapsed() < Duration::from_millis(300) => "ok",
            Ok(Ok(_)) => "slow",
            _ => "down",
        };
        results.push(Sample {
            service: service.into(),
            minute: checked_at,
            state: state.into(),
        });
    }
    results
}
pub async fn show(State(app): State<App>) -> Json<Status> {
    let now = minute();
    let current = sample(&app).await;
    let history = tokio::time::timeout(
        Duration::from_millis(800),
        sqlx::query_as(
            "SELECT service, minute, state FROM service_checks WHERE minute >= $1 ORDER BY minute",
        )
        .bind(now - 1440)
        .fetch_all(&app.0.db),
    )
    .await
    .ok()
    .and_then(|result| result.ok())
    .unwrap_or_default();
    Json(Status {
        minute: now,
        current,
        history,
    })
}
pub async fn monitor(app: App) {
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let results = sample(&app).await;
        for result in results {
            let _ = sqlx::query(
                "INSERT INTO service_checks(service, minute, state) VALUES($1,$2,$3)
                 ON CONFLICT(service, minute) DO UPDATE SET state=EXCLUDED.state",
            )
            .bind(result.service)
            .bind(result.minute)
            .bind(result.state)
            .execute(&app.0.db)
            .await;
        }
        let _ = sqlx::query("DELETE FROM service_checks WHERE minute < $1")
            .bind(minute() - 7 * 1440)
            .execute(&app.0.db)
            .await;
    }
}

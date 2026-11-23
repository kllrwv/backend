mod language;
pub(crate) mod support;
pub(crate) mod web;
use crate::{
    App,
    auth::{code_matches, digest, key, security, six_digits},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, fmt, time::Duration};
use uuid::Uuid;
#[derive(Clone)]
pub struct Bot {
    api_base: String,
    client: reqwest::Client,
    pub username: String,
}
#[derive(Deserialize)]
struct Reply<T> {
    result: Option<T>,
    error_code: Option<u16>,
    description: Option<String>,
    parameters: Option<ResponseParameters>,
}
#[derive(Deserialize)]
struct ResponseParameters {
    retry_after: Option<u64>,
}
#[derive(Debug)]
pub(crate) struct Rejected {
    method: &'static str,
    pub code: u16,
    pub missing_thread: bool,
    pub missing_message: bool,
    pub not_modified: bool,
    retry_after: Option<u64>,
}
impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "telegram {} failed ({})", self.method, self.code)
    }
}
impl std::error::Error for Rejected {}
#[derive(Deserialize)]
struct Identity {
    username: String,
}
impl Bot {
    pub async fn connect(token: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            token.split_once(':').is_some_and(|(id, secret)| {
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_digit())
                    && !secret.is_empty()
                    && secret
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }),
            "invalid telegram token format"
        );
        let mut bot = Self {
            api_base: format!("https://api.telegram.org/bot{token}"),
            username: String::new(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(35))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        };
        let identity: Identity = bot.call("getMe", json!({})).await?;
        anyhow::ensure!(
            identity
                .username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid bot username"
        );
        bot.username = identity.username;
        let webhook: Webhook = bot.call("getWebhookInfo", json!({})).await?;
        anyhow::ensure!(
            webhook.url.is_empty(),
            "use a dedicated telegram bot without an active webhook"
        );
        Ok(bot)
    }
    pub(crate) async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        body: Value,
    ) -> anyhow::Result<T> {
        let url = format!("{}/{method}", self.api_base);
        let reply: Reply<T> = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("telegram {method} request failed"))?
            .json()
            .await
            .map_err(|_| anyhow::anyhow!("invalid telegram {method} response"))?;
        reply.result.ok_or_else(|| {
            let description = reply.description.unwrap_or_default().to_ascii_lowercase();
            Rejected {
                method,
                code: reply.error_code.unwrap_or(0),
                missing_thread: description.contains("message thread not found"),
                missing_message: description.contains("message to edit not found"),
                not_modified: description.contains("not modified")
                    || description.contains("topic_not_modified"),
                retry_after: reply
                    .parameters
                    .and_then(|parameters| parameters.retry_after),
            }
            .into()
        })
    }
    pub(crate) async fn send(&self, chat: i64, text: &str, keyboard: Value) -> anyhow::Result<()> {
        let result = self
            .call::<Value>(
                "sendMessage",
                json!({ "chat_id": chat, "text": text, "reply_markup": keyboard }),
            )
            .await;
        if let Err(error) = result {
            eprintln!("{error}");
        }
        Ok(())
    }
}
#[derive(Deserialize)]
struct Webhook {
    url: String,
}
#[derive(Deserialize)]
struct Update {
    update_id: i64,
    message: Option<Message>,
    edited_message: Option<Message>,
    callback_query: Option<language::Callback>,
    message_reaction: Option<support::MessageReaction>,
}
#[derive(Deserialize)]
pub(crate) struct Message {
    pub chat: Chat,
    pub from: Option<Sender>,
    pub sender_chat: Option<Chat>,
    pub text: Option<String>,
    pub caption: Option<String>,
    #[serde(default)]
    pub message_id: i64,
    pub message_thread_id: Option<i64>,
    contact: Option<Contact>,
    reply_to_message: Option<QuotedMessage>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}
#[derive(Deserialize)]
struct QuotedMessage {
    text: Option<String>,
    contact: Option<Value>,
}
#[derive(Deserialize)]
pub(crate) struct Chat {
    pub id: i64,
    #[serde(rename = "type")]
    pub kind: String,
}
#[derive(Deserialize)]
pub(crate) struct Sender {
    pub id: i64,
    pub username: Option<String>,
    pub language_code: Option<String>,
    pub is_bot: bool,
}
#[derive(Deserialize)]
struct Contact {
    user_id: Option<i64>,
    phone_number: String,
}
pub async fn poll(app: App, bot: Bot) {
    let mut next = None;
    let allowed = if app.0.support_chat.is_some() {
        &[
            "message",
            "edited_message",
            "message_reaction",
            "callback_query",
        ][..]
    } else {
        &["message", "callback_query"][..]
    };
    loop {
        let events: anyhow::Result<Vec<Update>> = bot
            .call(
                "getUpdates",
                json!({
                    "offset": next, "timeout": 25, "allowed_updates": allowed
                }),
            )
            .await;
        match events {
            Ok(events) => {
                for event in events {
                    let update_id = event.update_id;
                    if let Err(error) = handle_update(&app, &bot, event).await {
                        eprintln!("telegram update retry: {error}");
                        let delay = error
                            .downcast_ref::<Rejected>()
                            .and_then(|failure| failure.retry_after)
                            .unwrap_or(3)
                            .clamp(3, 60);
                        tokio::time::sleep(Duration::from_secs(delay)).await;
                        break;
                    }
                    next = Some(update_id + 1);
                }
            }
            Err(error) => {
                eprintln!("{error}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}
async fn handle_update(app: &App, bot: &Bot, event: Update) -> anyhow::Result<()> {
    if let Some(message) = event.message {
        handle(app, bot, message).await
    } else if let Some(callback) = event.callback_query {
        language::handle(app, bot, callback).await
    } else if let Some(message) = event.edited_message {
        if let Some(sender) = private_sender(&message) {
            support::refresh(app, bot, sender).await;
        }
        Ok(())
    } else if let Some(reaction) = event.message_reaction {
        support::react(app, bot, reaction, event.update_id).await
    } else {
        Ok(())
    }
}
pub(crate) fn remove_keyboard() -> Value {
    json!({ "remove_keyboard": true })
}
enum PhonePurpose {
    Registration,
    Change,
}
async fn phone_prompt(
    bot: &Bot,
    chat: i64,
    copy: &crate::locale::Bot,
    purpose: PhonePurpose,
) -> anyhow::Result<()> {
    let text = match purpose {
        PhonePurpose::Registration => &copy.phone_prompt,
        PhonePurpose::Change => &copy.phone_change_prompt,
    };
    bot.send(
        chat,
        text,
        json!({
            "keyboard": [[{ "text": copy.phone_button, "request_contact": true }]],
            "resize_keyboard": true, "one_time_keyboard": true
        }),
    )
    .await
}
async fn continue_auth(
    bot: &Bot,
    chat: i64,
    copy: &crate::locale::Bot,
    needs_code: bool,
) -> anyhow::Result<()> {
    if needs_code {
        bot.send(chat, &copy.code_prompt, remove_keyboard()).await
    } else {
        phone_prompt(bot, chat, copy, PhonePurpose::Registration).await
    }
}
#[derive(sqlx::FromRow)]
struct BotFlow {
    id: String,
    kind: String,
    telegram_key: String,
    telegram_code: Option<String>,
    telegram_language_selected: bool,
    telegram_attempts: i16,
}
async fn start_in_chat(
    app: &App,
    sender: i64,
    link: &str,
    has_language: bool,
) -> anyhow::Result<Option<bool>> {
    let needs_code = sqlx::query_scalar(
        "WITH target AS (
             SELECT id FROM auth_flows WHERE telegram_key=$1 AND stage='telegram'
               AND expires_at>now() AND (telegram_sender IS NULL OR telegram_sender=$2)
         ), updated AS (
             UPDATE auth_flows SET paired=(id IN (SELECT id FROM target)),
                telegram_sender=$2, telegram_language_selected=$3 AND (id IN (SELECT id FROM target))
             WHERE stage='telegram' AND expires_at>now() AND EXISTS (SELECT 1 FROM target)
               AND ((id IN (SELECT id FROM target) AND (telegram_sender IS NULL OR telegram_sender=$2))
                    OR (paired AND telegram_sender=$2))
             RETURNING paired, telegram_code IS NOT NULL AS needs_code
         )
         SELECT needs_code FROM updated WHERE paired",
    ).bind(digest(link)).bind(sender).bind(has_language).fetch_optional(&app.0.db).await
        .map_err(|_| anyhow::anyhow!("registration link lookup failed"))?;
    Ok(needs_code)
}
async fn handle(app: &App, bot: &Bot, message: Message) -> anyhow::Result<()> {
    if message.chat.kind == "supergroup" && Some(message.chat.id) == app.0.support_chat {
        return support::reply(app, bot, &message).await;
    }
    let Some(sender) = private_sender(&message) else {
        return Ok(());
    };
    let result = handle_private(app, bot, &message, sender).await;
    if result.is_ok() {
        support::refresh(app, bot, sender).await;
    }
    result
}
fn private_sender(message: &Message) -> Option<&Sender> {
    message.from.as_ref().filter(|sender| {
        message.chat.kind == "private" && !sender.is_bot && message.chat.id == sender.id
    })
}
async fn handle_private(
    app: &App,
    bot: &Bot,
    message: &Message,
    sender: &Sender,
) -> anyhow::Result<()> {
    let chat = message.chat.id;
    let saved = language::saved(app, sender.id).await?;
    let lang = saved
        .as_deref()
        .unwrap_or_else(|| language::default(sender));
    let base_copy = &app.0.translations.get(lang).bot;
    let input = message.text.as_deref().unwrap_or("").trim();
    if command_payload(input, "/lang", &bot.username).is_some() {
        return language::choose(app, bot, chat, lang).await;
    }
    if let Some(payload) = command_payload(input, "/start", &bot.username) {
        if payload.is_empty() {
            return support::start(app, bot, sender, lang, saved.is_none()).await;
        }
        support::pause(app, sender.id).await?;
        if let Some(token) = payload.strip_prefix("phone_") {
            let opened = security::open_phone(app, sender.id, token)
                .await
                .map_err(|_| anyhow::anyhow!("phone change link lookup failed"))?;
            if opened {
                return phone_prompt(bot, chat, base_copy, PhonePurpose::Change).await;
            }
            return bot
                .send(
                    chat,
                    &base_copy.phone_change_invalid_link,
                    remove_keyboard(),
                )
                .await;
        }
        if let Some(needs_code) = start_in_chat(app, sender.id, payload, saved.is_some()).await? {
            return if saved.is_some() {
                continue_auth(bot, chat, base_copy, needs_code).await
            } else {
                language::choose(app, bot, chat, lang).await
            };
        }
        return bot
            .send(chat, &base_copy.invalid_link, remove_keyboard())
            .await;
    }
    if let Some(phone) = message
        .contact
        .as_ref()
        .filter(|contact| contact.user_id == Some(sender.id))
        .and_then(|contact| phone_number(&contact.phone_number))
    {
        match security::confirm_phone(app, sender.id, &phone)
            .await
            .map_err(|_| anyhow::anyhow!("phone change failed"))?
        {
            Some(true) => {
                return bot
                    .send(chat, &base_copy.phone_changed, remove_keyboard())
                    .await;
            }
            Some(false) => {
                return bot
                    .send(chat, &base_copy.phone_change_unavailable, remove_keyboard())
                    .await;
            }
            None => {}
        }
    }
    if security::phone_change_pending(app, sender.id)
        .await
        .map_err(|_| anyhow::anyhow!("phone change lookup failed"))?
    {
        return phone_prompt(bot, chat, base_copy, PhonePurpose::Change).await;
    }
    let languages = &app.0.translations;
    let selected = if input == languages.ru.bot.language_button {
        Some("ru")
    } else if input == languages.en.bot.language_button {
        Some("en")
    } else {
        None
    };
    let mut tx = app
        .0
        .db
        .begin()
        .await
        .map_err(|_| anyhow::anyhow!("telegram transaction failed"))?;
    let flow: Option<BotFlow> = sqlx::query_as(
        "SELECT id, kind, telegram_key, telegram_code, telegram_language_selected, telegram_attempts
         FROM auth_flows WHERE telegram_sender=$1 AND stage='telegram' AND paired AND expires_at>now()
         ORDER BY expires_at DESC, id LIMIT 1 FOR UPDATE",
    ).bind(sender.id).fetch_optional(&mut *tx).await
        .map_err(|_| anyhow::anyhow!("telegram flow lookup failed"))?;
    let Some(flow) = flow else {
        drop(tx);
        if app.0.support_chat.is_some() {
            if is_support_message(message, languages, &bot.username) {
                support::forward(app, bot, message, sender).await?;
            }
            return Ok(());
        }
        return bot
            .send(chat, &base_copy.open_from_website, remove_keyboard())
            .await;
    };
    if !flow.telegram_language_selected {
        let Some(language) = selected else {
            drop(tx);
            return language::choose(app, bot, chat, lang).await;
        };
        language::save(&mut tx, sender.id, language).await?;
        sqlx::query("UPDATE auth_flows SET lang=$2, telegram_language_selected=true WHERE id=$1")
            .bind(&flow.id)
            .bind(language)
            .execute(&mut *tx)
            .await
            .map_err(|_| anyhow::anyhow!("language selection failed"))?;
        tx.commit()
            .await
            .map_err(|_| anyhow::anyhow!("language commit failed"))?;
        let copy = &languages.get(language).bot;
        return continue_auth(bot, chat, copy, flow.telegram_code.is_some()).await;
    }
    let copy = base_copy;
    if let Some(expected) = flow.telegram_code.as_deref() {
        if flow.telegram_attempts >= 5 {
            drop(tx);
            return bot.send(chat, &copy.code_locked, remove_keyboard()).await;
        }
        if !six_digits(input) {
            drop(tx);
            return bot.send(chat, &copy.code_prompt, remove_keyboard()).await;
        }
        if !code_matches(&key(app, &flow.telegram_key, input), Some(expected)) {
            sqlx::query("UPDATE auth_flows SET telegram_attempts=telegram_attempts+1 WHERE id=$1")
                .bind(&flow.id)
                .execute(&mut *tx)
                .await
                .map_err(|_| anyhow::anyhow!("code attempt update failed"))?;
            tx.commit()
                .await
                .map_err(|_| anyhow::anyhow!("code attempt commit failed"))?;
            return bot.send(chat, &copy.code_wrong, remove_keyboard()).await;
        }
        if flow.kind == "register" {
            sqlx::query("UPDATE auth_flows SET telegram_code=NULL WHERE id=$1")
                .bind(&flow.id)
                .execute(&mut *tx)
                .await
                .map_err(|_| anyhow::anyhow!("code confirmation failed"))?;
            tx.commit()
                .await
                .map_err(|_| anyhow::anyhow!("code confirmation commit failed"))?;
            return phone_prompt(bot, chat, copy, PhonePurpose::Registration).await;
        }
        let account: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM accounts WHERE telegram_id=$1 AND deleted_at IS NULL",
        )
        .bind(sender.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| anyhow::anyhow!("linked account lookup failed"))?;
        let stage = if account.is_some() {
            "ready"
        } else {
            "unlinked"
        };
        sqlx::query(
            "UPDATE auth_flows SET stage=$2, account_id=$3, telegram_code=NULL WHERE id=$1",
        )
        .bind(&flow.id)
        .bind(stage)
        .bind(account)
        .execute(&mut *tx)
        .await
        .map_err(|_| anyhow::anyhow!("telegram login update failed"))?;
        tx.commit()
            .await
            .map_err(|_| anyhow::anyhow!("telegram login commit failed"))?;
        let reply = if account.is_some() {
            &copy.success
        } else {
            &copy.unlinked
        };
        return bot.send(chat, reply, remove_keyboard()).await;
    }
    let Some(phone) = message
        .contact
        .as_ref()
        .filter(|contact| contact.user_id == Some(sender.id))
        .and_then(|contact| phone_number(&contact.phone_number))
    else {
        drop(tx);
        return phone_prompt(bot, chat, copy, PhonePurpose::Registration).await;
    };
    let phone_key = app.0.contacts.phone_lookup(&key(app, "phone", &phone));
    let phone_tail = app
        .0
        .contacts
        .seal_phone_tail(&phone[phone.len() - 4..], &phone_key)
        .map_err(|_| anyhow::anyhow!("contact encryption failed"))?;
    let phone_ciphertext = app
        .0
        .contacts
        .seal_phone(&phone, &phone_key)
        .map_err(|_| anyhow::anyhow!("contact encryption failed"))?;
    let account: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO accounts(id, email_lookup, email_ciphertext, password_hash, telegram_id, phone_key, phone_tail_ciphertext, phone_ciphertext)
         SELECT $2, email_lookup, email_ciphertext, password_hash, $3, $4, $5, $6 FROM auth_flows WHERE id=$1
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(&flow.id)
    .bind(Uuid::new_v4())
    .bind(sender.id)
    .bind(phone_key)
    .bind(phone_tail)
    .bind(phone_ciphertext)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| anyhow::anyhow!("account creation failed"))?;
    let stage = if account.is_some() {
        "ready"
    } else {
        "conflict"
    };
    sqlx::query("UPDATE auth_flows SET stage=$2, account_id=$3, password_hash=NULL WHERE id=$1")
        .bind(&flow.id)
        .bind(stage)
        .bind(account)
        .execute(&mut *tx)
        .await
        .map_err(|_| anyhow::anyhow!("registration update failed"))?;
    tx.commit()
        .await
        .map_err(|_| anyhow::anyhow!("registration commit failed"))?;
    let reply = if account.is_some() {
        &copy.success
    } else {
        &copy.conflict
    };
    bot.send(chat, reply, remove_keyboard()).await
}
fn command_payload<'a>(input: &'a str, expected: &str, bot_name: &str) -> Option<&'a str> {
    let command_end = input.find(char::is_whitespace).unwrap_or(input.len());
    let (command, payload) = input.split_at(command_end);
    (command == expected
        || command.split_once('@').is_some_and(|(command, name)| {
            command == expected && name.eq_ignore_ascii_case(bot_name)
        }))
    .then(|| payload.trim())
}
fn is_support_message(
    message: &Message,
    languages: &crate::locale::Translations,
    bot_name: &str,
) -> bool {
    if message.contact.is_some() || message.extra.contains_key("forward_origin") {
        return false;
    }
    if message.reply_to_message.as_ref().is_some_and(|quoted| {
        quoted.contact.is_some()
            || quoted
                .text
                .as_deref()
                .is_some_and(|text| is_auth_input(text.trim(), languages, bot_name))
    }) {
        return false;
    }
    let input = message
        .text
        .as_deref()
        .or(message.caption.as_deref())
        .unwrap_or("")
        .trim();
    if is_auth_input(input, languages, bot_name) {
        return false;
    }
    !input.is_empty()
        || [
            "photo",
            "video",
            "audio",
            "voice",
            "document",
            "sticker",
            "animation",
            "video_note",
        ]
        .iter()
        .any(|kind| message.extra.contains_key(*kind))
}
fn is_auth_input(input: &str, languages: &crate::locale::Translations, bot_name: &str) -> bool {
    let code = input.strip_prefix("phone_").unwrap_or(input);
    let recovery = input.split('-');
    input.starts_with('/')
        || six_digits(input)
        || phone_number(input).is_some()
        || input
            .split_whitespace()
            .filter_map(|word| reqwest::Url::parse(word).ok())
            .any(|url| {
                url.host_str() == Some("t.me")
                    && url.path().trim_matches('/').eq_ignore_ascii_case(bot_name)
                    && url.query_pairs().any(|(key, _)| key == "start")
            })
        || (code.len() == 43
            && code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
        || (recovery.clone().count() == 8
            && recovery
                .clone()
                .all(|word| word.len() == 4 && word.bytes().all(|b| b.is_ascii_hexdigit())))
        || input
            == format!(
                "{} / {}",
                languages.ru.bot.choose_language, languages.en.bot.choose_language
            )
        || [&languages.ru.bot, &languages.en.bot]
            .into_iter()
            .any(|copy| {
                [
                    &copy.language_button,
                    &copy.choose_language,
                    &copy.language_saved,
                    &copy.open_from_website,
                    &copy.invalid_link,
                    &copy.code_prompt,
                    &copy.code_wrong,
                    &copy.code_locked,
                    &copy.phone_prompt,
                    &copy.phone_change_prompt,
                    &copy.phone_change_invalid_link,
                    &copy.phone_change_unavailable,
                    &copy.phone_button,
                    &copy.phone_changed,
                    &copy.conflict,
                    &copy.unlinked,
                    &copy.success,
                ]
                .into_iter()
                .any(|line| line == input)
            })
}
pub(crate) fn phone_number(raw: &str) -> Option<String> {
    let trimmed = raw.trim().strip_prefix('+').unwrap_or(raw.trim());
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_digit() || b" -()".contains(&b))
    {
        return None;
    }
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    ((7..=15).contains(&digits.len()) && !digits.starts_with('0')).then_some(digits)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, auth::hash_password, router};
    use axum::{Json, Router, routing::post};
    use lettre::AsyncSmtpTransport;
    use reqwest::{Client, Response, StatusCode, header, multipart};
    use sqlx::PgPool;
    use std::sync::{Arc, Mutex};
    use tokio::{net::TcpListener, sync::Semaphore};
    struct Fixture {
        app: App,
        bot: Bot,
        origin: String,
        password_hash: String,
        messages: Arc<Mutex<Vec<Value>>>,
    }
    async fn fixture(db: &PgPool, support_chat: Option<i64>) -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let bot = Bot {
            api_base: format!("{origin}/bot"),
            client: Client::new(),
            username: "test_killerwave_bot".into(),
        };
        let password_hash = hash_password(b"a local test password").unwrap();
        let contacts = crate::auth::contacts::Store::new(&[7; 32], "integration-test-key");
        contacts.migrate(db).await.unwrap();
        let app = App(Arc::new(Config {
            db: db.clone(),
            origin: origin.clone(),
            secure: false,
            secret: "integration-test-key".into(),
            contacts,
            sender: "test@killerwave.local".parse().unwrap(),
            mailer: AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("127.0.0.1")
                .build(),
            bot: Some(bot.clone()),
            support_chat,
            translations: crate::locale::Translations::load().unwrap(),
            telegram_web: None,
            hash_slots: Arc::new(Semaphore::new(1)),
            image_slots: Arc::new(Semaphore::new(1)),
            upload_slots: Semaphore::new(1),
            media: None,
            dummy_hash: password_hash.clone(),
            admin: crate::admin::Settings::for_test(),
        }));
        let messages = Arc::new(Mutex::new(Vec::<Value>::new()));
        let record = messages.clone();
        let routes = router(app.clone()).merge(Router::new().route(
            "/bot/{method}",
            post(
                move |axum::extract::Path(method): axum::extract::Path<String>,
                      Json(mut message): Json<Value>| {
                    let record = record.clone();
                    async move {
                        message["method"] = json!(method);
                        let mut messages = record.lock().unwrap();
                        messages.push(message.clone());
                        let calls = || messages
                                .iter()
                                .filter(|message| message["method"] == method)
                                .count();
                        let result = match method.as_str() {
                            "getChat" if message["chat_id"] == -1009876543210_i64 => json!({
                                "type": "supergroup", "is_forum": true, "active_usernames": ["public_forum"]
                            }),
                            "getChat" => json!({"type":"supergroup","is_forum":true}),
                            "createForumTopic" => json!({ "message_thread_id": 100 + calls() }),
                            "copyMessage" => json!({ "message_id": 1000 + calls() }),
                            "sendMessage" => json!({ "message_id": 500 + calls() }),
                            "editForumTopic" | "answerCallbackQuery" => json!(true),
                            "getChatMember" => json!({
                                "status": match message["user_id"].as_i64() {
                                    Some(3001) => "administrator",
                                    Some(3003) => "creator",
                                    _ => "member",
                                }
                            }),
                            "setMessageReaction" if message["reaction"][0]["type"] == "custom_emoji" => {
                                return Json(json!({ "error_code": 400, "description": "Bad Request: REACTION_INVALID" }));
                            }
                            "setMessageReaction" => json!(true),
                            _ => json!({}),
                        };
                        Json(json!({ "result": result }))
                    }
                },
            ),
        ));
        tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        Fixture {
            app,
            bot,
            origin,
            password_hash,
            messages,
        }
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn registration_requires_own_unique_contact_and_profile(db: PgPool) {
        let Fixture {
            app,
            bot,
            origin,
            password_hash,
            messages,
        } = fixture(&db, None).await;
        let client = Client::new();
        let post = |path: &str, cookie: &str| {
            client
                .post(format!("{origin}/api/{path}"))
                .header(header::ORIGIN, &origin)
                .header(header::COOKIE, cookie)
        };
        let get = |path: &str, cookie: &str| {
            client
                .get(format!("{origin}/api/{path}"))
                .header(header::COOKIE, cookie)
        };
        for (ticket, email, sender) in [
            ("first-test-ticket", "first@example.test", 1001),
            ("second-test-ticket", "second@example.test", 1002),
        ] {
            let flow_id = digest(ticket);
            let lookup = app.0.contacts.email_lookup(email);
            let ciphertext = app.0.contacts.seal_email(email, &lookup).unwrap();
            sqlx::query(
                "INSERT INTO auth_flows(id, kind, stage, lang, email_lookup, email_ciphertext, password_hash, email_code, expires_at)
                 VALUES($1,'register','email','en',$2,$3,$4,$5,now() + interval '15 minutes')",
            ).bind(&flow_id).bind(lookup).bind(ciphertext).bind(&password_hash)
                .bind(key(&app, &flow_id, "013579")).execute(&db).await.unwrap();
            let flow_cookie = format!("kw_flow={ticket}");
            let verification = post("auth/email", &flow_cookie)
                .json(&json!({"code":"013579"}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            assert!(verification["bot_url"].is_null());
            let contact = json!({"contact":{"user_id":sender,"phone_number":"+1 (202) 555-0100"}});
            deliver(&app, &bot, sender, contact.clone()).await;
            assert_eq!(
                account_id(&db, sender).await,
                None,
                "contact before Telegram Login"
            );
            let confirmed = if sender == 1001 {
                let jar = axum_extra::extract::CookieJar::new()
                    .add(axum_extra::extract::cookie::Cookie::new("kw_flow", ticket));
                let flow = crate::auth::confirm_telegram_registration(&app, &jar, &flow_id, sender)
                    .await
                    .unwrap();
                serde_json::to_value(flow).unwrap()
            } else {
                post("auth/telegram/bot", &flow_cookie)
                    .json(&json!({"mode":"register","lang":"ru"}))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .json()
                    .await
                    .unwrap()
            };
            let link = confirmed["bot_url"]
                .as_str()
                .unwrap()
                .split("start=")
                .nth(1)
                .unwrap();
            let another_sender = sender + 2000;
            if sender == 1001 {
                deliver(
                    &app,
                    &bot,
                    another_sender,
                    json!({"text":format!("/start {link}")}),
                )
                .await;
                deliver(
                    &app,
                    &bot,
                    another_sender,
                    json!({
                        "contact":{"user_id":another_sender,"phone_number":"+1 (202) 555-0111"}
                    }),
                )
                .await;
                assert_eq!(
                    account_id(&db, another_sender).await,
                    None,
                    "forwarded registration link"
                );
            }
            deliver(&app, &bot, sender, contact.clone()).await;
            assert_eq!(
                account_id(&db, sender).await,
                None,
                "contact before opening registration link"
            );
            deliver(&app, &bot, sender, json!({"text":format!("/start {link}")})).await;
            deliver(&app, &bot, sender, contact.clone()).await;
            assert_eq!(
                account_id(&db, sender).await,
                None,
                "contact before choosing a language"
            );
            if sender == 1001 {
                let choose = serde_json::from_value(json!({
                    "update_id":1,"callback_query":{
                        "id":"registration-language","from":{"id":sender,"is_bot":false},
                        "message":{"chat":{"id":sender,"type":"private"}},"data":"lang:en"
                    }
                }))
                .unwrap();
                handle_update(&app, &bot, choose).await.unwrap();
            } else {
                let language = &app.0.translations.en.bot.language_button;
                deliver(&app, &bot, sender, json!({"text":language})).await;
            }
            if let Some(code) = confirmed["bot_code"].as_str() {
                deliver(&app, &bot, sender, contact.clone()).await;
                assert_eq!(
                    account_id(&db, sender).await,
                    None,
                    "contact before fallback code"
                );
                deliver(&app, &bot, sender, json!({"text":code})).await;
            }
            deliver(
                &app,
                &bot,
                sender,
                json!({"contact":{"user_id":1999,"phone_number":"+1 (202) 555-0111"}}),
            )
            .await;
            assert_eq!(
                account_id(&db, sender).await,
                None,
                "somebody else's contact"
            );
            deliver(&app, &bot, sender, contact).await;
            let result = post("auth/complete", &flow_cookie).send().await.unwrap();
            if sender == 1002 {
                assert_eq!(result.json::<Value>().await.unwrap()["stage"], "conflict");
                assert_eq!(
                    account_id(&db, sender).await,
                    None,
                    "duplicate normalized number"
                );
                continue;
            }
            assert!(account_id(&db, sender).await.is_some());
            let (lookup, encrypted): (String, Vec<u8>) = sqlx::query_as(
                "SELECT phone_key, phone_ciphertext FROM accounts WHERE telegram_id=$1",
            )
            .bind(sender)
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(
                app.0.contacts.open_phone(&lookup, encrypted).unwrap(),
                "12025550100"
            );
            let session = response_cookie(&result, "kw_session");
            assert_eq!(result.json::<Value>().await.unwrap()["stage"], "ready");
            assert_eq!(
                get("feed", &session).send().await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
            let mut png = std::io::Cursor::new(Vec::new());
            image::RgbImage::from_pixel(40, 30, image::Rgb([80, 80, 80]))
                .write_to(&mut png, image::ImageFormat::Png)
                .unwrap();
            let form = || {
                multipart::Form::new()
                    .text("name", "Имя")
                    .text("username", "Ёж-Профиль_54")
                    .text("bio", "Hello!")
            };
            let unavailable = post("profile", &session)
                .multipart(form().part(
                    "avatar",
                    multipart::Part::bytes(png.into_inner()).file_name("test.png"),
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                get("feed", &session).send().await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
            let saved = post("profile", &session)
                .multipart(form())
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            assert_eq!(saved["username"], "ёж-профиль_54");
            assert_eq!(saved["display_name"], "имя");
            assert_eq!(saved["bio"], "hello!");
            assert_eq!(saved["has_avatar"], false);
            assert_eq!(
                get("profile/avatar", &session)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                get("feed", &session).send().await.unwrap().status(),
                StatusCode::OK
            );
            let change = post("settings/phone", &session)
                .json(&json!({"password":"a local test password"}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            let change_id = change["id"].as_str().unwrap();
            let start = change["url"]
                .as_str()
                .unwrap()
                .split("start=")
                .nth(1)
                .unwrap();
            let en = &app.0.translations.en.bot;
            let last_bot_message = || messages.lock().unwrap().last().unwrap().clone();
            deliver(&app, &bot, 1999, json!({"text": format!("/start {start}")})).await;
            assert_eq!(last_bot_message()["text"], en.phone_change_invalid_link);
            deliver(
                &app,
                &bot,
                sender,
                json!({"text": format!("/start {start}")}),
            )
            .await;
            assert_eq!(last_bot_message()["text"], en.phone_change_prompt);
            deliver(
                &app,
                &bot,
                sender,
                json!({"contact":{"user_id":1999,"phone_number":"+1 202 555 0119"}}),
            )
            .await;
            assert_eq!(last_bot_message()["text"], en.phone_change_prompt);
            deliver(&app, &bot, sender, json!({"text":"12025550119"})).await;
            assert_eq!(last_bot_message()["text"], en.phone_change_prompt);
            let language_switch = serde_json::from_value(json!({
                "update_id":2,"callback_query":{
                    "id":"phone-change-language","from":{"id":sender,"is_bot":false},
                    "message":{"chat":{"id":sender,"type":"private"}},"data":"lang:ru"
                }
            }))
            .unwrap();
            handle_update(&app, &bot, language_switch).await.unwrap();
            let ru = &app.0.translations.ru.bot;
            assert_eq!(last_bot_message()["text"], ru.phone_change_prompt);
            assert_eq!(
                last_bot_message()["reply_markup"]["keyboard"][0][0]["request_contact"],
                true
            );
            let pending = get(&format!("settings/phone/{change_id}"), &session)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            assert!(pending["result"].is_null());
            deliver(
                &app,
                &bot,
                sender,
                json!({"contact":{"user_id":sender,"phone_number":"+1 202 555 0119"}}),
            )
            .await;
            assert_eq!(last_bot_message()["text"], ru.phone_changed);
            let completed = get(&format!("settings/phone/{change_id}"), &session)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            assert_eq!(completed["result"], "done");
            let old_retired: bool = sqlx::query_scalar("SELECT contact_retired('phone',$1)")
                .bind(
                    app.0
                        .contacts
                        .phone_lookup(&key(&app, "phone", "12025550100")),
                )
                .fetch_one(&db)
                .await
                .unwrap();
            assert!(old_retired);
            assert_eq!(
                post("auth/logout", &session).send().await.unwrap().status(),
                StatusCode::NO_CONTENT
            );
            assert_eq!(
                get("feed", &session).send().await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let fallback = post("auth/telegram/bot", "")
            .json(&json!({"mode":"login","lang":"en"}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let flow_cookie = response_cookie(&fallback, "kw_flow");
        let flow: Value = fallback.json().await.unwrap();
        let link = flow["bot_url"]
            .as_str()
            .unwrap()
            .split("start=")
            .nth(1)
            .unwrap();
        let code = flow["bot_code"].as_str().unwrap();
        let ru = &app.0.translations.ru.bot;
        let en = &app.0.translations.en.bot;
        let last_message = || messages.lock().unwrap().last().unwrap().clone();
        deliver(&app, &bot, 1001, json!({"text":format!("/start {link}")})).await;
        assert_eq!(last_message()["text"], ru.code_prompt);
        deliver(&app, &bot, 1001, json!({"text":"/lang"})).await;
        assert_eq!(
            last_message()["reply_markup"]["inline_keyboard"][0][0]["text"],
            ru.language_button
        );
        assert_eq!(
            last_message()["reply_markup"]["inline_keyboard"][0][1]["text"],
            en.language_button
        );
        let change = serde_json::from_value(json!({
            "update_id":1,"callback_query":{
                "id":"switch-login-language","from":{"id":1001,"is_bot":false},
                "message":{"chat":{"id":1001,"type":"private"}},"data":"lang:ru"
            }
        }))
        .unwrap();
        handle_update(&app, &bot, change).await.unwrap();
        assert_eq!(last_message()["text"], ru.code_prompt);
        deliver(&app, &bot, 1001, json!({"text":format!("/start {link}")})).await;
        assert_eq!(last_message()["text"], ru.code_prompt);
        deliver(&app, &bot, 1001, json!({"text":code})).await;
        assert_eq!(last_message()["text"], ru.success);
        let result = post("auth/complete", &flow_cookie).send().await.unwrap();
        let session = response_cookie(&result, "kw_session");
        assert_eq!(
            get("feed", &session).send().await.unwrap().status(),
            StatusCode::OK
        );
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn support_reuses_separate_topics_and_keeps_auth_private(db: PgPool) {
        const GROUP: i64 = -1001234567890;
        let Fixture {
            app,
            bot,
            origin,
            password_hash,
            messages,
        } = fixture(&db, Some(GROUP)).await;
        let id = Uuid::new_v4();
        let address = "support-test@example.test";
        let phone = "12025550140";
        let phone_lookup = app.0.contacts.phone_lookup(&key(&app, "phone", phone));
        let lookup = app.0.contacts.email_lookup(address);
        let encrypted = app.0.contacts.seal_email(address, &lookup).unwrap();
        sqlx::query(
            "INSERT INTO accounts (id,email_lookup,email_ciphertext,password_hash,telegram_id,phone_key,username,display_name)
             VALUES ($1,$2,$3,$4,2001,$5,'linked','Linked test account')",
        ).bind(id).bind(lookup).bind(encrypted).bind(password_hash)
            .bind(&phone_lookup)
            .execute(&db).await.unwrap();
        deliver(
            &app,
            &bot,
            2001,
            json!({
                "text":"/start@test_killerwave_bot","message_id":1,
                "from":{"id":2001,"is_bot":false,"username":"telegramname","language_code":"ru"}
            }),
        )
        .await;
        assert_eq!(
            messages.lock().unwrap().last().unwrap()["text"],
            app.0.translations.ru.bot.support_prompt
        );
        let relay = |mut details: Value| {
            if details.get("from").is_none() {
                details["from"] = json!({"id":2001,"is_bot":false,"username":"telegramname","language_code":"ru"});
            }
            deliver(&app, &bot, 2001, details)
        };
        relay(json!({"text":"карточка поста не открывается","message_id":2})).await;
        relay(json!({"text":"карточка поста не открывается","message_id":2})).await;
        relay(json!({"photo":[{}],"message_id":3})).await;
        for detail in [
            json!({"text":"012345","message_id":4}),
            json!({"contact":{"user_id":2001,"phone_number":"+1 202 555 0140"},"message_id":5}),
            json!({"text":"основной код пришёл сюда","message_id":6,"reply_to_message":{"text":app.0.translations.ru.bot.code_prompt}}),
            json!({"text":"ссылка https://t.me/test_killerwave_bot?start=example","message_id":7}),
            json!({"text":"приватное сообщение","message_id":8,"forward_origin":{"type":"hidden_user"}}),
        ] {
            relay(detail).await;
        }
        deliver(&app, &bot, 2002, json!({"text":"/start","message_id":1})).await;
        deliver(
            &app,
            &bot,
            2002,
            json!({
                "text":"I cannot create an account","message_id":2,
                "from":{"id":2002,"is_bot":false,"username":"guestname"}
            }),
        )
        .await;
        let recorded = || messages.lock().unwrap().clone();
        let topics = || {
            recorded()
                .into_iter()
                .filter(|message| message["method"] == "createForumTopic")
                .collect::<Vec<_>>()
        };
        let copies = || {
            recorded()
                .into_iter()
                .filter(|message| message["method"] == "copyMessage")
                .collect::<Vec<_>>()
        };
        assert_eq!(topics().len(), 2);
        assert_eq!(topics()[0]["name"], "@telegramname · 2001");
        assert_eq!(topics()[1]["name"], "@guestname · 2002");
        let first_thread_calls: Vec<_> = recorded()
            .into_iter()
            .filter(|msg| msg["chat_id"] == GROUP && msg["message_thread_id"] == 101)
            .collect();
        assert_eq!(first_thread_calls.len(), 3);
        let card = &first_thread_calls[0];
        assert_eq!(card["method"], "sendMessage");
        assert_eq!(card["protect_content"], true);
        let card_message_id: i64 = sqlx::query_scalar(
            "SELECT card_message_id FROM telegram_support_chats WHERE group_id=$1 AND user_id=2001",
        )
        .bind(GROUP)
        .fetch_one(&db)
        .await
        .unwrap();
        let card_text = card["text"].as_str().unwrap();
        for value in [
            id.to_string().as_str(),
            "@linked",
            address,
            "Linked test account",
            "код на почту",
            "полный номер не сохранён",
        ] {
            assert!(card_text.contains(value), "missing card value: {value}");
        }
        assert!(!card_text.contains("argon2"));
        assert_eq!(
            copies()
                .iter()
                .map(|msg| (
                    msg["chat_id"].as_i64().unwrap(),
                    msg["message_thread_id"].as_i64().unwrap(),
                    msg["from_chat_id"].as_i64().unwrap(),
                    msg["message_id"].as_i64().unwrap()
                ))
                .collect::<Vec<_>>(),
            [
                (GROUP, 101, 2001, 2),
                (GROUP, 101, 2001, 3),
                (GROUP, 102, 2002, 2)
            ]
        );
        let staff = |details| async {
            let message = serde_json::from_value(details).unwrap();
            handle(&app, &bot, message).await.unwrap();
        };
        let staff_reply = json!({
            "chat":{"id":GROUP,"type":"supergroup"},"from":{"id":3001,"is_bot":false},
            "message_thread_id":101,"message_id":1025,"text":"Проверяем"
        });
        staff(staff_reply.clone()).await;
        staff(staff_reply.clone()).await;
        staff(json!({
            "chat":{"id":GROUP,"type":"supergroup"},"from":{"id":3001,"is_bot":false},
            "message_thread_id":102,"message_id":1026,"text":"We can help"
        }))
        .await;
        for unwanted in [
            json!({"chat":{"id":GROUP-1,"type":"supergroup"},"from":{"id":3001,"is_bot":false},"message_thread_id":101,"message_id":1027,"text":"unrelated group"}),
            json!({"chat":{"id":GROUP,"type":"supergroup"},"from":{"id":3001,"is_bot":false},"message_thread_id":199,"message_id":1028,"text":"unrelated topic"}),
            json!({"chat":{"id":GROUP,"type":"supergroup"},"from":{"id":3001,"is_bot":true},"message_thread_id":101,"message_id":1029,"text":"other bot"}),
        ] {
            staff(unwanted).await;
        }
        let replies: Vec<_> = recorded()
            .into_iter()
            .filter(|message| {
                message["text"].as_str().is_some_and(|text| {
                    text.starts_with("ответ от поддержки:")
                        || text.starts_with("reply from support:")
                })
            })
            .collect();
        assert_eq!(replies.len(), 2);
        assert!(
            replies
                .iter()
                .all(|reply| reply.get("reply_markup").is_none())
        );
        assert_eq!(replies[0]["chat_id"], 2001);
        assert_eq!(replies[0]["text"], "ответ от поддержки: Проверяем");
        assert_eq!(replies[1]["chat_id"], 2002);
        assert_eq!(replies[1]["text"], "reply from support: We can help");
        let flow = Client::new()
            .post(format!("{origin}/api/auth/telegram/bot"))
            .header(header::ORIGIN, &origin)
            .json(&json!({"mode":"login","lang":"ru"}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        let link = flow["bot_url"]
            .as_str()
            .unwrap()
            .split_once("start=")
            .unwrap()
            .1;
        let launch = json!({"text":format!("/start {link}"),"message_id":9});
        relay(launch.clone()).await;
        relay(json!({"text":"/start","message_id":10})).await;
        let paired: bool = sqlx::query_scalar("SELECT paired FROM auth_flows")
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(!paired);
        relay(json!({"text":"прикладываю скриншот","message_id":11})).await;
        assert_eq!(copies().len(), 4);
        relay(launch).await;
        relay(json!({"text":app.0.translations.ru.bot.language_button,"message_id":12})).await;
        relay(json!({"text":flow["bot_code"],"message_id":13})).await;
        let stage: String = sqlx::query_scalar("SELECT stage FROM auth_flows")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(stage, "ready");
        relay(json!({"text":"в чате входа","message_id":14})).await;
        assert_eq!(copies().len(), 4);
        relay(json!({"text":"/start","message_id":15})).await;
        relay(json!({"text":"возвращаюсь к обращению","message_id":16})).await;
        assert_eq!(topics().len(), 2);
        assert_eq!(copies().len(), 5);
        assert_eq!(copies()[4]["message_thread_id"], 101);
        let new_email = "updated@example.test";
        let lookup = app.0.contacts.email_lookup(new_email);
        let encrypted = app.0.contacts.seal_email(new_email, &lookup).unwrap();
        sqlx::query(
            "UPDATE accounts SET email_lookup=$2,email_ciphertext=$3,
             display_name='Updated',totp_generation=$4,totp_secret=$5,totp_last_step=0 WHERE id=$1",
        )
        .bind(id)
        .bind(lookup)
        .bind(encrypted)
        .bind(Uuid::new_v4())
        .bind(b"test-secret")
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO sessions(id,account_id) VALUES($1,$2)")
            .bind("test-phone-session")
            .bind(id)
            .execute(&db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO account_changes(account_id,session_id,kind,previous,bot_opened)
             VALUES($1,'test-phone-session','phone',$2,true)",
        )
        .bind(id)
        .bind(&phone_lookup)
        .execute(&db)
        .await
        .unwrap();
        for input in [
            json!({"contact":{"user_id":2001,"phone_number":format!("+{phone}")},"message_id":17}),
            json!({"text":"012345","message_id":18}),
        ] {
            let mut input = input;
            input["from"] = json!({"id":2001,"is_bot":false,"username":"newtelegram"});
            relay(input).await;
        }
        let retired: bool = sqlx::query_scalar("SELECT contact_retired('phone',$1)")
            .bind(&phone_lookup)
            .fetch_one(&db)
            .await
            .unwrap();
        assert!(!retired);
        assert_eq!(copies().len(), 5);
        let updated: Vec<_> = recorded()
            .into_iter()
            .filter(|call| {
                matches!(
                    call["method"].as_str(),
                    Some("editForumTopic" | "editMessageText")
                )
            })
            .collect();
        assert_eq!(updated.len(), 2);
        assert_eq!(updated[0]["method"], "editForumTopic");
        assert_eq!(updated[0]["name"], "@newtelegram · 2001");
        assert_eq!(updated[1]["message_id"], card_message_id);
        let edited = updated[1]["text"].as_str().unwrap();
        for value in [
            "@newtelegram",
            new_email,
            "+12025550140",
            "Updated",
            "приложение-аутентификатор",
        ] {
            assert!(edited.contains(value), "missing card value: {value}");
        }
        for secret in [address, "test-secret", "012345"] {
            assert!(!edited.contains(secret));
        }
        sqlx::query("DELETE FROM accounts WHERE id=$1")
            .bind(id)
            .execute(&db)
            .await
            .unwrap();
        deliver(&app, &bot, 2001, json!({"text":"/start","message_id":19})).await;
        let redacted = recorded()
            .into_iter()
            .filter(|call| call["method"] == "editMessageText")
            .last()
            .unwrap();
        assert_eq!(redacted["message_id"], card_message_id);
        let redacted = redacted["text"].as_str().unwrap();
        assert!(redacted.contains("аккаунт killerwave не привязан"));
        assert!(!redacted.contains(new_email));
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn bot_language_switches_in_support_and_persists_for_sign_in(db: PgPool) {
        const GROUP: i64 = -1001234567890;
        const USER: i64 = 2001;
        let Fixture {
            app,
            bot,
            origin,
            messages,
            ..
        } = fixture(&db, Some(GROUP)).await;
        let last = || messages.lock().unwrap().last().unwrap().clone();
        let ru = &app.0.translations.ru.bot;
        let en = &app.0.translations.en.bot;
        let choose = |lang, chat, kind, update| {
            let event = serde_json::from_value(json!({
                "update_id":update, "callback_query":{
                    "id":format!("choice-{update}"),"from":{"id":USER,"is_bot":false,"language_code":"en"},
                    "message":{"chat":{"id":chat,"type":kind}},"data":format!("lang:{lang}")
                }
            })).unwrap();
            handle_update(&app, &bot, event)
        };
        let staff_reply = |message_id| {
            let message = serde_json::from_value(json!({
                "chat":{"id":GROUP,"type":"supergroup"},"from":{"id":3001,"is_bot":false},
                "message_thread_id":101,"message_id":message_id,"text":"Проверим вопрос"
            }))
            .unwrap();
            handle(&app, &bot, message)
        };
        deliver(&app, &bot, USER, json!({"text":"/start","message_id":1})).await;
        let welcome = last();
        assert_eq!(welcome["text"], en.support_prompt);
        assert_eq!(
            welcome["reply_markup"]["inline_keyboard"][0][0]["text"],
            ru.language_button
        );
        deliver(&app, &bot, USER, json!({"text":"Hello","message_id":2})).await;
        deliver(
            &app,
            &bot,
            USER,
            json!({"text":"/lang@Test_Killerwave_Bot","message_id":3}),
        )
        .await;
        assert_eq!(last()["text"], en.choose_language);
        choose("ru", USER, "private", 4).await.unwrap();
        assert_eq!(last()["method"], "editMessageText");
        assert!(
            last()["text"]
                .as_str()
                .unwrap()
                .contains("язык бота: русский")
        );
        staff_reply(1025).await.unwrap();
        assert_eq!(
            last()["text"],
            format!("{} Проверим вопрос", ru.support_reply)
        );
        deliver(&app, &bot, USER, json!({"text":"/start","message_id":5})).await;
        assert_eq!(last()["text"], ru.support_prompt);
        assert!(last()["reply_markup"].get("inline_keyboard").is_none());
        let flow = Client::new()
            .post(format!("{origin}/api/auth/telegram/bot"))
            .header(header::ORIGIN, &origin)
            .json(&json!({"mode":"login","lang":"en"}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        let link = flow["bot_url"]
            .as_str()
            .unwrap()
            .split_once("start=")
            .unwrap()
            .1;
        deliver(
            &app,
            &bot,
            USER,
            json!({"text":format!("/start {link}"),"message_id":6}),
        )
        .await;
        assert_eq!(last()["text"], ru.code_prompt);
        deliver(&app, &bot, USER, json!({"text":"/lang","message_id":7})).await;
        assert_eq!(last()["text"], ru.choose_language);
        choose("en", USER, "private", 8).await.unwrap();
        choose("ru", GROUP, "supergroup", 9).await.unwrap();
        assert_eq!(
            language::saved(&app, USER).await.unwrap().as_deref(),
            Some("en")
        );
        deliver(
            &app,
            &bot,
            USER,
            json!({"text":flow["bot_code"],"message_id":8}),
        )
        .await;
        assert_eq!(last()["text"], en.unlinked);
        staff_reply(1026).await.unwrap();
        assert_eq!(
            last()["text"],
            format!("{} Проверим вопрос", en.support_reply)
        );
        let records = messages.lock().unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|call| call["method"] == "copyMessage")
                .count(),
            1
        );
        assert!(records.iter().any(
            |call| call["method"] == "answerCallbackQuery" && call["text"] == ru.language_saved
        ));
        assert!(records.iter().any(
            |call| call["method"] == "answerCallbackQuery" && call["text"] == en.language_saved
        ));
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn support_does_not_publish_to_public_supergroups(db: PgPool) {
        const GROUP: i64 = -1009876543210;
        let Fixture {
            app, bot, messages, ..
        } = fixture(&db, Some(GROUP)).await;
        deliver(&app, &bot, 2001, json!({"text":"/start","message_id":1})).await;
        deliver(&app, &bot, 2001, json!({"text":"Need help","message_id":2})).await;
        let recorded = messages.lock().unwrap();
        let group_calls: Vec<_> = recorded
            .iter()
            .filter(|call| call["chat_id"] == GROUP)
            .collect();
        assert_eq!(group_calls.len(), 1);
        assert_eq!(group_calls[0]["method"], "getChat");
        assert_eq!(
            recorded.last().unwrap()["text"],
            app.0.translations.en.bot.support_unavailable
        );
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn support_reactions_track_authorized_changes_on_the_original_message(db: PgPool) {
        const GROUP: i64 = -1001234567890;
        let Fixture {
            app, bot, messages, ..
        } = fixture(&db, Some(GROUP)).await;
        for user in [2001, 2002] {
            deliver(&app, &bot, user, json!({"text":"/start","message_id":1})).await;
            deliver(
                &app,
                &bot,
                user,
                json!({"text":"test support message","message_id":42}),
            )
            .await;
        }
        let send = |update_id, group, copy, actor, old, new| {
            let event = serde_json::from_value(json!({
                "update_id":update_id,"message_reaction":{
                    "chat":{"id":group,"type":"supergroup"},"message_id":copy,"date":2000000000,
                    "user":{"id":actor,"is_bot":false},"old_reaction":old,"new_reaction":new
                }
            }))
            .unwrap();
            let (app, bot) = (&app, &bot);
            async move { handle_update(app, bot, event).await.unwrap() }
        };
        let emoji = |symbol: &str| json!([{"type":"emoji","emoji":symbol}]);
        let reactions = || {
            messages
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call["method"] == "setMessageReaction")
                .cloned()
                .collect::<Vec<_>>()
        };
        send(1, GROUP - 1, 1001, 3001, json!([]), emoji("👍")).await;
        send(2, GROUP, 9999, 3001, json!([]), emoji("👍")).await;
        send(3, GROUP, 1001, 3002, json!([]), emoji("👍")).await;
        assert!(reactions().is_empty());
        send(4, GROUP, 1001, 3001, json!([]), emoji("👍")).await;
        send(4, GROUP, 1001, 3001, json!([]), emoji("👍")).await;
        send(5, GROUP, 1001, 3003, json!([]), emoji("🔥")).await;
        send(6, GROUP, 1001, 3003, emoji("🔥"), json!([])).await;
        send(7, GROUP, 1001, 3001, emoji("👍"), json!([])).await;
        send(4, GROUP, 1001, 3001, json!([]), emoji("👍")).await;
        let calls = reactions();
        assert_eq!(calls.len(), 4);
        for call in &calls {
            assert_eq!(call["chat_id"], 2001);
            assert_eq!(call["message_id"], 42);
        }
        assert_eq!(calls[0]["reaction"], emoji("👍"));
        assert_eq!(calls[1]["reaction"], emoji("🔥"));
        assert_eq!(calls[2]["reaction"], emoji("👍"));
        assert_eq!(calls[3]["reaction"], json!([]));
        let custom = json!([{"type":"custom_emoji","custom_emoji_id":"444"}]);
        send(8, GROUP, 1002, 3001, json!([]), custom.clone()).await;
        let calls = reactions();
        assert_eq!(calls.len(), 6);
        assert_eq!(calls[4]["reaction"], custom);
        assert_eq!(calls[5]["reaction"], emoji("👍"));
        assert_eq!(calls[5]["chat_id"], 2002);
        assert_eq!(calls[5]["message_id"], 42);
    }
    async fn account_id(db: &PgPool, sender: i64) -> Option<Uuid> {
        sqlx::query_scalar("SELECT id FROM accounts WHERE telegram_id=$1 AND deleted_at IS NULL")
            .bind(sender)
            .fetch_optional(db)
            .await
            .unwrap()
    }
    async fn deliver(app: &App, bot: &Bot, sender: i64, details: Value) {
        let mut message = json!({
            "chat":{"id":sender,"type":"private"},
            "from":{"id":sender,"is_bot":false}
        });
        message
            .as_object_mut()
            .unwrap()
            .extend(details.as_object().unwrap().clone());
        handle(app, bot, serde_json::from_value(message).unwrap())
            .await
            .unwrap();
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn admin_bridge_permissions_moderation_and_undo(db: PgPool) {
        const GROUP: i64 = -1001234567890;
        let Fixture {
            app,
            origin,
            password_hash,
            messages,
            ..
        } = fixture(&db, Some(GROUP)).await;
        let ids = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];
        for (index, id) in ids.iter().enumerate() {
            let email = format!("admin-fixture-{index}@example.test");
            let lookup = app.0.contacts.email_lookup(&email);
            let encrypted = app.0.contacts.seal_email(&email, &lookup).unwrap();
            sqlx::query(
                "INSERT INTO accounts(id,email_lookup,email_ciphertext,password_hash,telegram_id,phone_key,username,display_name)
                 VALUES($1,$2,$3,$4,$5,$6,$7,$7)",
            ).bind(id).bind(lookup).bind(encrypted).bind(&password_hash).bind(4001+index as i64)
                .bind(app.0.contacts.phone_lookup(&format!("phone-{index}")))
                .bind(format!("test-user-{index}")).execute(&db).await.unwrap();
            sqlx::query("INSERT INTO sessions(id,account_id) VALUES($1,$2)")
                .bind(digest(&format!("session-{index}")))
                .bind(id)
                .execute(&db)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO admin_roles(account_id,owner,permissions) VALUES($1,true,'{}'),($2,false,ARRAY['admins.grant'])")
            .bind(ids[0]).bind(ids[1]).execute(&db).await.unwrap();
        let id: Uuid = sqlx::query_scalar("INSERT INTO posts(id,author_id,body) VALUES(gen_random_uuid(),$1,'example post') RETURNING id")
            .bind(ids[2]).fetch_one(&db).await.unwrap();
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let get = |path: &str, cookie: &str| {
            client
                .get(format!("{origin}/api/{path}"))
                .header(header::COOKIE, cookie)
        };
        let panel = |path: &str, cookie: &str, value: Value| {
            client
                .post(format!("{origin}/api/admin/{path}"))
                .header(header::ORIGIN, "http://localhost:3001")
                .header(header::COOKIE, cookie)
                .json(&value)
        };
        let social = |path: &str, cookie: &str, value: Value| {
            client
                .post(format!("{origin}/api/{path}"))
                .header(header::ORIGIN, &origin)
                .header(header::COOKIE, cookie)
                .json(&value)
        };
        assert_eq!(
            get("admin/accounts", "kw_session=session-0")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get("admin/session/start", "kw_session=session-2")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut staff_cookies = Vec::new();
        for index in 0..2 {
            let link = get(
                "admin/session/start",
                &format!("kw_session=session-{index}"),
            )
            .send()
            .await
            .unwrap();
            assert_eq!(link.status(), StatusCode::SEE_OTHER);
            let location = link
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap();
            let ticket = location.split("ticket=").nth(1).unwrap();
            let wrong_origin = social("admin/session/claim", "", json!({"ticket":ticket}))
                .send()
                .await
                .unwrap();
            assert_eq!(wrong_origin.status(), StatusCode::FORBIDDEN);
            let response = panel("session/claim", "", json!({"ticket":ticket}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            staff_cookies.push(response_cookie(&response, "kw_admin"));
            assert_eq!(
                panel("session/claim", "", json!({"ticket":ticket}))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let (owner, staff) = (&staff_cookies[0], &staff_cookies[1]);
        assert_eq!(
            panel(
                "roles/test-user-2",
                staff,
                json!({"permissions":["accounts.read"]})
            )
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            panel(
                "roles/test-user-2",
                owner,
                json!({"permissions":["accounts.read"]})
            )
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::NO_CONTENT
        );
        let account = panel(
            &format!("accounts/{}", ids[2]),
            owner,
            json!({"op":"email","value":"changed@example.test"}),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(account.status(), StatusCode::NO_CONTENT);
        let account = get(&format!("admin/accounts/{}", ids[2]), owner)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(account["email"], "changed@example.test");
        assert!(account.get("password_hash").is_none());
        assert_eq!(
            get("me", "kw_session=session-2")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()["profile"],
            Value::Null
        );
        sqlx::query("INSERT INTO sessions(id,account_id) VALUES($1,$2)")
            .bind(digest("session-2"))
            .bind(ids[2])
            .execute(&db)
            .await
            .unwrap();
        let comment: Uuid = sqlx::query_scalar(
            "INSERT INTO posts(id,author_id,reply_to,body) VALUES(gen_random_uuid(),$1,$2,'example comment') RETURNING id",
        ).bind(ids[2]).bind(id).fetch_one(&db).await.unwrap();
        sqlx::query("UPDATE accounts SET avatar_object_id=gen_random_uuid(),banner_object_id=gen_random_uuid() WHERE id=$1")
            .bind(ids[2]).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO post_media(post_id,position,object_id,kind,mime) VALUES($1,0,gen_random_uuid(),'image','image/webp')")
            .bind(id).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO polls(post_id,question) VALUES($1,'example question')")
            .bind(id)
            .execute(&db)
            .await
            .unwrap();
        for (kind, target, part) in [
            ("account", ids[2], None),
            ("avatar", ids[2], None),
            ("banner", ids[2], None),
            ("post", id, None),
            ("comment", comment, None),
            ("attachment", id, Some(0)),
            ("poll", id, None),
        ] {
            let response = social(
                "reports",
                "kw_session=session-2",
                json!({"kind":kind,"id":target,"part":part,"reason":"spam","description":""}),
            )
            .send()
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{kind}");
            assert_eq!(
                response.json::<Value>().await.unwrap()["error"],
                "report_own_content",
                "{kind}"
            );
        }
        assert_eq!(
            social(
                "reports",
                "kw_session=session-1",
                json!({"kind":"post","id":id,"reason":"spam","description":"example report"})
            )
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::NO_CONTENT
        );
        let reports = get("admin/reports", owner)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Vec<Value>>()
            .await
            .unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["body"], "example post");
        let report = reports[0]["id"].as_str().unwrap();
        assert_eq!(
            panel(
                &format!("reports/{report}/review"),
                owner,
                json!({"accept":true,"remove":true})
            )
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            get(&format!("posts/{id}"), "kw_session=session-2")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let removed = get(&format!("posts/{id}"), "kw_session=session-0")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(removed["deleted"], true);
        assert_eq!(
            panel(
                &format!("accounts/{}", ids[2]),
                owner,
                json!({
                    "op":"profile","name":"обновлённое имя","username":"test-user-2",
                    "bio":"","theme":"light","wall_access":"everyone","like_access":"nobody",
                    "message_access":"everyone","show_online":true,
                    "notice_preferences":{"like":false}
                })
            )
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::NO_CONTENT
        );
        let event_count: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_events")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            event_count, 4,
            "sign-in and read requests must not create events"
        );
        sqlx::query("INSERT INTO admin_events(id,actor_id,actor_name,action,created_at)
                     VALUES(gen_random_uuid(),$1,'test-user-0','session_read',now()-interval '1 day')")
            .bind(ids[0]).execute(&db).await.unwrap();
        let events = get("admin/audit", owner)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Vec<Value>>()
            .await
            .unwrap();
        assert_eq!(events.len(), 4, "historical read events are filtered");
        assert!(
            events
                .iter()
                .all(|event| event["details"].get("_telegram").is_none())
        );
        for action in ["report_review", "email"] {
            let event = events
                .iter()
                .find(|entry| entry["action"] == action)
                .unwrap()["id"]
                .as_str()
                .unwrap();
            assert_eq!(
                panel(&format!("audit/{event}/undo"), owner, json!({}))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NO_CONTENT
            );
        }
        assert_eq!(
            get(&format!("posts/{id}"), "kw_session=session-2")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let account = get(&format!("admin/accounts/{}", ids[2]), owner)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(account["email"], "admin-fixture-2@example.test");
        let state = get("admin/server", owner)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(state["accounts"]["total"], 3);
        assert_eq!(state["countries"]["unknown"], 3);
        let delivery = tokio::spawn(crate::admin::deliver_audit(app.clone()));
        let sent = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(message) = messages
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|message| {
                        message["method"] == "sendMessage" && message["chat_id"] == GROUP
                    })
                    .cloned()
                {
                    break message;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        delivery.abort();
        assert_eq!(sent["message_thread_id"], 6);
        let sent = sent["text"].as_str().unwrap();
        assert!(sent.contains("изменение прав"));
        assert!(sent.contains("выдали права: смотреть аккаунты"));
        assert!(sent.contains("@test-user-2"));
        let summaries: Vec<String> = sqlx::query_scalar(
            "SELECT details->>'_telegram' FROM admin_events WHERE details ? '_telegram'",
        )
        .fetch_all(&db)
        .await
        .unwrap();
        for expected in [
            "имя: «test-user-2» → «обновлённое имя»",
            "тема: тёмная → светлая",
            "уведомления о лайках: выкл.",
            "почта аккаунта заменена\nзавершено сессий: 1",
            "решение: жалоба принята",
            "объект скрыт модерацией",
            "решение: жалоба возвращена на рассмотрение",
            "объект восстановлен",
            "восстановлена предыдущая почта",
        ] {
            assert!(
                summaries.iter().any(|summary| summary.contains(expected)),
                "{expected}"
            );
        }
        assert!(
            summaries
                .iter()
                .any(|summary| summary.contains(&id.to_string())
                    && summary.contains("причина жалобы: спам"))
        );
        assert!(
            summaries
                .iter()
                .all(|summary| !summary.contains("@example.test"))
        );
        sqlx::query("DELETE FROM sessions WHERE account_id=$1")
            .bind(ids[0])
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(
            get("admin/session", owner).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn recommended_feed_mixes_sparse_posts_and_surfaces_engagement(db: PgPool) {
        let Fixture {
            origin,
            password_hash,
            ..
        } = fixture(&db, None).await;
        let viewer = Uuid::from_u128(1);
        let author = Uuid::from_u128(2);
        let other = Uuid::from_u128(3);
        sqlx::query(
            "INSERT INTO accounts(id,username,display_name,password_hash,review_account)
             VALUES($1,'viewer','viewer',$4,true),($2,'author','author',$4,true),($3,'other','other',$4,true)",
        )
        .bind(viewer).bind(author).bind(other).bind(password_hash)
        .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO sessions(id,account_id) VALUES($1,$2)")
            .bind(digest("ranking-fixture"))
            .bind(viewer)
            .execute(&db)
            .await
            .unwrap();
        let posts: Vec<_> = (100..125).map(Uuid::from_u128).collect();
        sqlx::query(
            "INSERT INTO posts(id,author_id,body,created_at)
             SELECT id, CASE WHEN position % 2 = 1 THEN $2 ELSE $3 END,
                    'ranking fixture', now() - position * interval '1 minute'
             FROM unnest($1::uuid[]) WITH ORDINALITY AS p(id,position)",
        )
        .bind(&posts)
        .bind(author)
        .bind(other)
        .execute(&db)
        .await
        .unwrap();
        let client = Client::new();
        let feed = |query: &'static str| {
            let request = client
                .get(format!("{origin}/api/feed?{query}"))
                .header("cookie", "kw_session=ranking-fixture");
            async move {
                let json: Value = request
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                json["posts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|post| post["id"].as_str().unwrap().parse::<Uuid>().unwrap())
                    .collect::<Vec<_>>()
            }
        };
        let first = feed("mode=recommended").await;
        assert_eq!(first.len(), 20);
        assert_ne!(first, posts[..20]);
        assert_eq!(first, feed("mode=recommended").await);
        let mut all = first;
        all.extend(feed("mode=recommended&offset=20").await);
        all.sort_unstable();
        assert_eq!(all, posts);
        let older = Uuid::from_u128(200);
        sqlx::query("INSERT INTO posts(id,author_id,body,created_at) VALUES($1,$2,'older post',now()-interval '1 day')")
            .bind(older).bind(other).execute(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO posts(id,author_id,body,reply_to)
                     SELECT gen_random_uuid(),$1,'reply',$2 FROM generate_series(1,12)",
        )
        .bind(author)
        .bind(older)
        .execute(&db)
        .await
        .unwrap();
        assert_eq!(feed("mode=recommended").await[0], older);
        sqlx::query("INSERT INTO follows(follower_id,followed_id) VALUES($1,$2)")
            .bind(viewer)
            .bind(author)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(
            feed("mode=following").await,
            posts.into_iter().step_by(2).collect::<Vec<_>>()
        );
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn review_accounts_use_password_login_and_cannot_become_admins(db: PgPool) {
        let Fixture {
            app,
            origin,
            password_hash,
            ..
        } = fixture(&db, None).await;
        let password = "a test-only review password";
        for (index, permissions) in [
            vec!["accounts.review.create"],
            vec!["accounts.read"],
            vec!["accounts.read"],
        ]
        .into_iter()
        .enumerate()
        {
            let id = Uuid::new_v4();
            let email = format!("review-admin-{index}@example.test");
            let lookup = app.0.contacts.email_lookup(&email);
            let cipher = app.0.contacts.seal_email(&email, &lookup).unwrap();
            sqlx::query("INSERT INTO accounts(id,email_lookup,email_ciphertext,password_hash,telegram_id,phone_key,username,display_name)
                         VALUES($1,$2,$3,$4,$5,$6,$7,$7)")
                .bind(id).bind(lookup).bind(cipher).bind(&password_hash).bind(5000 + index as i64)
                .bind(app.0.contacts.phone_lookup(&format!("phone-{index}")))
                .bind(format!("review-admin-{index}")).execute(&db).await.unwrap();
            let session = digest(&format!("review-staff-{index}"));
            sqlx::query("INSERT INTO sessions(id,account_id) VALUES($1,$2)")
                .bind(&session)
                .bind(id)
                .execute(&db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO admin_roles(account_id,owner,permissions) VALUES($1,$2,$3)")
                .bind(id)
                .bind(index == 2)
                .bind(permissions)
                .execute(&db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO admin_sessions(digest,session_id) VALUES($1,$2)")
                .bind(digest(&format!("review-admin-{index}")))
                .bind(session)
                .execute(&db)
                .await
                .unwrap();
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let panel = |path: &str, cookie: &str, data: Value| {
            client
                .post(format!("{origin}/api/admin/{path}"))
                .header(header::ORIGIN, "http://localhost:3001")
                .header(header::COOKIE, cookie)
                .json(&data)
        };
        let social = |path: &str, cookie: &str, data: Value| {
            client
                .post(format!("{origin}/api/{path}"))
                .header(header::ORIGIN, &origin)
                .header(header::COOKIE, cookie)
                .json(&data)
        };
        let get = |path: &str, cookie: &str| {
            client
                .get(format!("{origin}/api/{path}"))
                .header(header::COOKIE, cookie)
        };
        let draft = json!({"name":"проверка","username":"@Review-Test","password":password});
        for (cookie, status) in [
            ("", StatusCode::UNAUTHORIZED),
            ("kw_admin=review-admin-1", StatusCode::FORBIDDEN),
        ] {
            assert_eq!(
                panel("accounts", cookie, draft.clone())
                    .send()
                    .await
                    .unwrap()
                    .status(),
                status
            );
        }
        let creator = "kw_admin=review-admin-0";
        let created = panel("accounts", creator, draft.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let created: Value = created.json().await.unwrap();
        let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(created["username"], "review-test");
        assert_eq!(
            panel("accounts", creator, draft)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let account = get(&format!("admin/accounts/{id}"), "kw_admin=review-admin-2")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(account["review_account"], true);
        assert_eq!(account["email"], Value::Null);
        assert_eq!(account["phone"], Value::Null);
        assert_eq!(account["telegram"], Value::Null);
        assert_eq!(
            panel(
                "roles/review-test",
                "kw_admin=review-admin-2",
                json!({"permissions":["accounts.read"]})
            )
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::FORBIDDEN
        );
        let audit: Value = sqlx::query_scalar("SELECT details FROM admin_events WHERE target_id=$1 AND action='review_account_create'")
            .bind(id).fetch_one(&db).await.unwrap();
        assert!(
            audit["_telegram"]
                .as_str()
                .unwrap()
                .contains("@review-test")
        );
        assert!(!audit.to_string().contains(password));
        assert_eq!(
            social(
                "auth/login",
                "",
                json!({"login":"review-test","password":"wrong","lang":"ru"})
            )
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let login = || {
            social(
                "auth/login",
                "",
                json!({"login":"@review-test","password":password,"lang":"ru"}),
            )
        };
        let start = login().send().await.unwrap().error_for_status().unwrap();
        let flow = response_cookie(&start, "kw_flow");
        assert_eq!(start.json::<Value>().await.unwrap()["stage"], "ready");
        let complete = social("auth/complete", &flow, json!({}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let session = response_cookie(&complete, "kw_session");
        let me = get("me", &session)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(me["profile"]["username"], "review-test");
        assert_eq!(
            get("admin/session/start", &session)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let security = get("settings/security", &session)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(security["email"], Value::Null);
        assert_eq!(security["phone_linked"], false);
        assert_eq!(security["telegram_linked"], false);
        assert_eq!(
            social("settings/phone", &session, json!({"password":password}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let generation = Uuid::new_v4();
        let cipher = app
            .0
            .contacts
            .seal_totp(id, generation, "JBSWY3DPEHPK3PXP")
            .unwrap();
        sqlx::query(
            "UPDATE accounts SET totp_generation=$2,totp_secret=$3,totp_last_step=0 WHERE id=$1",
        )
        .bind(id)
        .bind(generation)
        .bind(cipher)
        .execute(&db)
        .await
        .unwrap();
        assert_eq!(
            login()
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()["stage"],
            "totp"
        );
    }
    fn response_cookie(response: &Response, name: &str) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split(';').next())
            .find(|value| value.starts_with(&format!("{name}=")))
            .unwrap()
            .into()
    }
}

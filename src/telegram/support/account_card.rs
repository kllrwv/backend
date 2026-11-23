use crate::telegram::{Bot, Rejected, Sender};
use crate::{App, auth};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fmt::Write;
use uuid::Uuid;
pub(super) fn topic_name(app: &App, sender: &Sender) -> String {
    let fallback = &app.0.translations.admin_bot().topic_fallback;
    let label = telegram_name(sender).unwrap_or_else(|| fallback.clone());
    format!("{label} · {}", sender.id)
}
fn telegram_name(sender: &Sender) -> Option<String> {
    sender
        .username
        .as_ref()
        .map(|username| format!("@{username}"))
}
#[derive(Deserialize)]
struct Group {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    is_forum: bool,
    username: Option<String>,
    #[serde(default)]
    active_usernames: Vec<String>,
    linked_chat_id: Option<i64>,
}
#[derive(Debug)]
pub(super) struct PrivateGroupRequired;
impl std::fmt::Display for PrivateGroupRequired {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("support requires a private forum supergroup")
    }
}
impl std::error::Error for PrivateGroupRequired {}
pub(super) async fn require_private_group(bot: &Bot, group: i64) -> anyhow::Result<()> {
    let info: Group = bot.call("getChat", json!({ "chat_id": group })).await?;
    if info.kind == "supergroup"
        && info.is_forum
        && info.username.is_none()
        && info.active_usernames.is_empty()
        && info.linked_chat_id.is_none()
    {
        Ok(())
    } else {
        Err(PrivateGroupRequired.into())
    }
}
#[derive(sqlx::FromRow)]
struct TopicState {
    thread_id: i64,
    topic_name: Option<String>,
    card_message_id: Option<i64>,
    card_fingerprint: Option<String>,
    lang: String,
}
#[derive(Deserialize)]
struct CardMessage {
    message_id: i64,
}
pub(super) async fn sync(app: &App, bot: &Bot, group: i64, sender: &Sender) -> anyhow::Result<()> {
    let mut tx = app.0.db.begin().await?;
    let Some(topic) = sqlx::query_as::<_, TopicState>(
        "SELECT c.thread_id,c.topic_name,c.card_message_id,c.card_fingerprint,coalesce(l.lang,c.lang) AS lang
         FROM telegram_support_chats c LEFT JOIN telegram_bot_languages l USING (user_id)
         WHERE c.group_id=$1 AND c.user_id=$2 AND c.thread_id IS NOT NULL FOR UPDATE OF c",
    )
    .bind(group)
    .bind(sender.id)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Ok(());
    };
    let account = sqlx::query_as::<_, Account>(
        "SELECT id,username,display_name,bio,email_lookup,email_ciphertext,phone_key,
                phone_ciphertext,phone_tail_ciphertext,totp_generation IS NOT NULL AS authenticator,review_account,
                to_char(created_at AT TIME ZONE 'UTC','DD.MM.YYYY HH24:MI:SS') AS created,
                to_char(last_seen AT TIME ZONE 'UTC','DD.MM.YYYY HH24:MI:SS') AS last_seen,
                (SELECT count(*) FROM sessions s WHERE s.account_id=a.id AND s.expires_at>now()) AS sessions,
                avatar IS NOT NULL OR avatar_object_id IS NOT NULL AS avatar,
                banner_object_id IS NOT NULL AS banner,
                theme,wall_access,like_access,message_access,show_online,notice_preferences
         FROM accounts a WHERE telegram_id=$1 AND a.deleted_at IS NULL",
    )
    .bind(sender.id)
    .fetch_optional(&mut *tx)
    .await?;
    let name = topic_name(app, sender);
    let card = render(app, sender, &topic.lang, account)?;
    let fingerprint = auth::key(app, "telegram-support-account-card", &card);
    let rename = topic.topic_name.as_deref() != Some(&name);
    let update =
        topic.card_message_id.is_none() || topic.card_fingerprint.as_deref() != Some(&fingerprint);
    if !rename && !update {
        return Ok(());
    }
    require_private_group(bot, group).await?;
    if rename {
        let result = bot
            .call::<bool>(
                "editForumTopic",
                json!({
                    "chat_id": group, "message_thread_id": topic.thread_id, "name": name,
                }),
            )
            .await;
        if let Err(error) = result
            && !error
                .downcast_ref::<Rejected>()
                .is_some_and(|failure| failure.not_modified)
        {
            return Err(error);
        }
    }
    let id = if update {
        Some(publish(bot, group, &topic, &card).await?)
    } else {
        topic.card_message_id
    };
    sqlx::query(
        "UPDATE telegram_support_chats SET topic_name=$3,card_message_id=$4,card_fingerprint=$5
         WHERE group_id=$1 AND user_id=$2",
    )
    .bind(group)
    .bind(sender.id)
    .bind(name)
    .bind(id)
    .bind(fingerprint)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}
async fn publish(bot: &Bot, group: i64, topic: &TopicState, card: &str) -> anyhow::Result<i64> {
    if let Some(id) = topic.card_message_id {
        let result = bot
            .call::<Value>(
                "editMessageText",
                json!({
                    "chat_id": group, "message_id": id, "text": card,
                    "link_preview_options": { "is_disabled": true },
                }),
            )
            .await;
        match result {
            Ok(_) => return Ok(id),
            Err(error) => match error.downcast_ref::<Rejected>() {
                Some(failure) if failure.not_modified => return Ok(id),
                Some(failure) if failure.missing_message => {}
                _ => return Err(error),
            },
        }
    }
    let message: CardMessage = bot
        .call(
            "sendMessage",
            json!({
                "chat_id": group, "message_thread_id": topic.thread_id, "text": card,
                "protect_content": true, "disable_notification": true,
                "link_preview_options": { "is_disabled": true },
            }),
        )
        .await?;
    anyhow::ensure!(
        message.message_id > 0,
        "invalid support account card message ID"
    );
    Ok(message.message_id)
}
#[derive(sqlx::FromRow)]
struct Account {
    id: Uuid,
    username: Option<String>,
    display_name: Option<String>,
    bio: String,
    email_lookup: Option<String>,
    email_ciphertext: Option<Vec<u8>>,
    phone_key: Option<String>,
    phone_ciphertext: Option<Vec<u8>>,
    phone_tail_ciphertext: Option<Vec<u8>>,
    authenticator: bool,
    review_account: bool,
    created: String,
    last_seen: Option<String>,
    sessions: i64,
    avatar: bool,
    banner: bool,
    theme: String,
    wall_access: String,
    like_access: String,
    message_access: String,
    show_online: bool,
    notice_preferences: Value,
}
fn render(
    app: &App,
    sender: &Sender,
    lang: &str,
    account: Option<Account>,
) -> anyhow::Result<String> {
    let t = &app.0.translations.admin_bot().card;
    let telegram = telegram_name(sender);
    let empty = t.empty.as_str();
    let mut card = t.title.clone();
    let bot_language = if lang == "ru" { &t.ru } else { &t.en };
    card.push('\n');
    fields(
        &mut card,
        [
            (&t.telegram_id, &sender.id.to_string()),
            (&t.telegram_username, telegram.as_deref().unwrap_or(empty)),
            (&t.bot_language, bot_language),
        ],
    )?;
    let Some(account) = account else {
        section(&mut card, &t.missing_account);
        return Ok(card);
    };
    let contacts = &app.0.contacts;
    let decrypt_failed = |_| anyhow::anyhow!("could not read a support account contact");
    let email = account
        .email_lookup
        .zip(account.email_ciphertext)
        .map(|(key, data)| contacts.open_email(&key, data))
        .transpose()
        .map_err(decrypt_failed)?;
    let phone = if let Some((key, encrypted)) =
        account.phone_key.as_deref().zip(account.phone_ciphertext)
    {
        format!(
            "+{}",
            contacts
                .open_phone(key, encrypted)
                .map_err(decrypt_failed)?
        )
    } else if let Some((key, encrypted)) = account
        .phone_key
        .as_deref()
        .zip(account.phone_tail_ciphertext)
    {
        let digits = contacts
            .open_phone_tail(key, encrypted)
            .map_err(decrypt_failed)?;
        t.phone_tail.replace("{digits}", &digits)
    } else if account.phone_key.is_some() {
        t.missing_phone.clone()
    } else {
        t.no.clone()
    };
    let username = account.username.map(|value| format!("@{value}"));
    let second_factor = if account.authenticator {
        &t.authenticator_factor
    } else if account.review_account {
        &t.no
    } else {
        &t.email_factor
    };
    let last_seen = account
        .last_seen
        .map(|value| t.time_utc.replace("{time}", &value));
    let enabled = |value| if value { t.yes.as_str() } else { t.no.as_str() };
    let audience = |value: &str| match value {
        "everyone" => t.everyone.as_str(),
        "followers" => &t.followers,
        _ => &t.nobody,
    };
    section(&mut card, &t.account);
    fields(
        &mut card,
        [
            (&t.account_id, &account.id.to_string()),
            (&t.name, account.display_name.as_deref().unwrap_or(empty)),
            (&t.username, username.as_deref().unwrap_or(empty)),
            (&t.email, email.as_deref().unwrap_or(empty)),
            (&t.phone, &phone),
            (&t.sign_in, &t.sign_in_methods),
            (&t.second_factor, second_factor),
            (&t.created, &t.time_utc.replace("{time}", &account.created)),
            (&t.last_seen, last_seen.as_deref().unwrap_or(empty)),
            (&t.sessions, &account.sessions.to_string()),
            (&t.avatar, enabled(account.avatar)),
            (&t.banner, enabled(account.banner)),
        ],
    )?;
    section(&mut card, &t.settings);
    fields(
        &mut card,
        [
            (
                &t.theme,
                match account.theme.as_str() {
                    "light" => &t.light,
                    "system" => &t.system,
                    _ => &t.dark,
                },
            ),
            (&t.wall, audience(&account.wall_access)),
            (&t.likes, audience(&account.like_access)),
            (&t.messages, audience(&account.message_access)),
            (&t.show_online, enabled(account.show_online)),
        ],
    )?;
    section(&mut card, &t.notices);
    for (key, label) in [
        ("all", &t.all),
        ("sound", &t.sound),
        ("messages", &t.messages),
        ("follow", &t.follows),
        ("wall", &t.wall),
        ("like", &t.likes),
        ("reply", &t.replies),
        ("mention", &t.mentions),
    ] {
        let value = account.notice_preferences[key]
            .as_bool()
            .unwrap_or(key != "sound");
        write!(card, "\n{label}: {}", enabled(value))?;
    }
    if !account.bio.is_empty() {
        section(&mut card, &t.bio);
        write!(card, "\n{}", account.bio)?;
    }
    Ok(card)
}
fn section(card: &mut String, title: &str) {
    card.push_str("\n\n");
    card.push_str(title);
}
fn fields<const N: usize>(card: &mut String, values: [(&str, &str); N]) -> std::fmt::Result {
    for (name, value) in values {
        write!(card, "\n{name}: {value}")?;
    }
    Ok(())
}

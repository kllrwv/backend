mod account_card;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::types::Json;

use crate::App;

use super::{Bot, Chat, Message, Rejected, Sender, remove_keyboard};

pub(crate) async fn private_group(bot: &Bot, group: i64) -> anyhow::Result<()> {
    account_card::require_private_group(bot, group).await
}

pub async fn refresh(app: &App, bot: &Bot, sender: &Sender) {
    if let Some(group) = app.0.support_chat
        && let Err(error) = account_card::sync(app, bot, group, sender).await
    {
        eprintln!("telegram support account card: {error}");
    }
}

pub fn chat_from_env() -> anyhow::Result<Option<i64>> {
    let raw = std::env::var("TELEGRAM_SUPPORT_CHAT_ID").unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let id: i64 = raw
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid TELEGRAM_SUPPORT_CHAT_ID"))?;
    anyhow::ensure!(
        id < 0,
        "TELEGRAM_SUPPORT_CHAT_ID must be a negative supergroup ID"
    );
    Ok(Some(id))
}

pub async fn start(
    app: &App,
    bot: &Bot,
    sender: &Sender,
    lang: &str,
    offer_language: bool,
) -> anyhow::Result<()> {
    let copy = &app.0.translations.get(lang).bot;
    let Some(group) = app.0.support_chat else {
        return bot
            .send(sender.id, &copy.support_unavailable, remove_keyboard())
            .await;
    };
    let mut tx = app.0.db.begin().await?;
    sqlx::query(
        "UPDATE auth_flows SET paired=false,telegram_language_selected=false
         WHERE telegram_sender=$1 AND stage='telegram' AND paired AND expires_at>now()",
    )
    .bind(sender.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE account_changes c SET bot_opened=false FROM accounts a
         WHERE c.account_id=a.id AND a.telegram_id=$1 AND c.kind='phone' AND c.bot_opened",
    )
    .bind(sender.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO telegram_support_chats (group_id,user_id,lang) VALUES ($1,$2,$3)
         ON CONFLICT (group_id,user_id) DO UPDATE SET lang=EXCLUDED.lang,active=true",
    )
    .bind(group)
    .bind(sender.id)
    .bind(lang)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let keyboard = if offer_language {
        super::language::picker(app)
    } else {
        remove_keyboard()
    };
    bot.send(sender.id, &copy.support_prompt, keyboard).await
}

pub async fn pause(app: &App, user: i64) -> anyhow::Result<()> {
    if let Some(group) = app.0.support_chat {
        sqlx::query(
            "UPDATE telegram_support_chats SET active=false WHERE group_id=$1 AND user_id=$2 AND active",
        ).bind(group).bind(user).execute(&app.0.db).await?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct Topic {
    message_thread_id: i64,
}

async fn create_topic(app: &App, bot: &Bot, group: i64, sender: &Sender) -> anyhow::Result<i64> {
    let mut tx = app.0.db.begin().await?;
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT thread_id FROM telegram_support_chats WHERE group_id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(group)
    .bind(sender.id)
    .fetch_one(&mut *tx)
    .await?;
    if let Some(thread) = existing {
        tx.commit().await?;
        return Ok(thread);
    }
    account_card::require_private_group(bot, group).await?;
    let name = account_card::topic_name(app, sender);
    let topic: Topic = bot
        .call(
            "createForumTopic",
            json!({ "chat_id": group, "name": name }),
        )
        .await?;
    sqlx::query("UPDATE telegram_support_chats SET thread_id=$3, topic_name=$4 WHERE group_id=$1 AND user_id=$2")
        .bind(group)
        .bind(sender.id)
        .bind(topic.message_thread_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(topic.message_thread_id)
}

pub async fn forward(
    app: &App,
    bot: &Bot,
    message: &Message,
    sender: &Sender,
) -> anyhow::Result<()> {
    let Some(group) = app.0.support_chat else {
        return Ok(());
    };
    let chat: Option<(Option<i64>, String)> = sqlx::query_as(
        "SELECT c.thread_id,coalesce(l.lang,c.lang) FROM telegram_support_chats c
         LEFT JOIN telegram_bot_languages l USING (user_id) WHERE c.group_id=$1 AND c.user_id=$2 AND c.active",
    ).bind(group).bind(sender.id).fetch_optional(&app.0.db).await?;
    let Some((existing, lang)) = chat else {
        return Ok(());
    };
    if message.message_id <= 0 || delivered(app, message, 0).await? {
        return Ok(());
    }
    let copy = &app.0.translations.get(&lang).bot;
    let result = forward_to_topic(app, bot, group, sender, message.message_id, existing).await;
    match result {
        Ok(copy) => record_copy(app, group, copy, message).await,
        Err(error) if permanent(&error) || error.is::<account_card::PrivateGroupRequired>() => {
            eprintln!("telegram support: {error}");
            bot.send(sender.id, &copy.support_unavailable, remove_keyboard())
                .await
        }
        Err(error) => Err(error),
    }
}

async fn forward_to_topic(
    app: &App,
    bot: &Bot,
    group: i64,
    sender: &Sender,
    message_id: i64,
    existing: Option<i64>,
) -> anyhow::Result<i64> {
    let thread = match existing {
        Some(thread) => thread,
        None => create_topic(app, bot, group, sender).await?,
    };
    let result = copy_to_ready_topic(app, bot, group, sender, thread, message_id).await;
    if existing.is_some()
        && result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<Rejected>())
            .is_some_and(|failure| failure.missing_thread)
    {
        sqlx::query("UPDATE telegram_support_chats SET thread_id=NULL, topic_name=NULL, card_message_id=NULL, card_fingerprint=NULL WHERE group_id=$1 AND user_id=$2 AND thread_id=$3")
            .bind(group).bind(sender.id).bind(thread).execute(&app.0.db).await?;
        let new_thread = create_topic(app, bot, group, sender).await?;
        return copy_to_ready_topic(app, bot, group, sender, new_thread, message_id).await;
    }
    result
}

async fn copy_to_ready_topic(
    app: &App,
    bot: &Bot,
    group: i64,
    sender: &Sender,
    thread: i64,
    message_id: i64,
) -> anyhow::Result<i64> {
    account_card::sync(app, bot, group, sender).await?;
    copy_message(bot, group, thread, sender.id, message_id).await
}

#[derive(Deserialize)]
struct CopiedMessage {
    message_id: i64,
}

async fn copy_message(
    bot: &Bot,
    group: i64,
    thread: i64,
    sender: i64,
    message: i64,
) -> anyhow::Result<i64> {
    let copy: CopiedMessage = bot.call("copyMessage", json!({
        "chat_id": group, "message_thread_id": thread, "from_chat_id": sender, "message_id": message
    })).await?;
    Ok(copy.message_id)
}

async fn record_copy(app: &App, group: i64, copy: i64, original: &Message) -> anyhow::Result<()> {
    let mut tx = app.0.db.begin().await?;
    if copy > 0 {
        sqlx::query(
            "INSERT INTO telegram_support_message_copies (group_id,group_message_id,user_id,user_message_id)
             VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
        ).bind(group).bind(copy).bind(original.chat.id).bind(original.message_id)
            .execute(&mut *tx).await?;
    }
    mark_delivered(&mut *tx, original, 0).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn reply(app: &App, bot: &Bot, message: &Message) -> anyhow::Result<()> {
    let group = message.chat.id;
    let human = match &message.sender_chat {
        Some(chat) => chat.id == group && chat.kind == "supergroup",
        None => message.from.as_ref().is_some_and(|sender| !sender.is_bot),
    };
    if !human || message.message_id <= 0 {
        return Ok(());
    }
    let (Some(thread), Some(text)) = (message.message_thread_id, message.text.as_deref()) else {
        return Ok(());
    };
    let text = text.trim();
    if text.is_empty() || text.starts_with('/') {
        return Ok(());
    }
    let target: Option<(i64, String)> = sqlx::query_as(
        "SELECT c.user_id,coalesce(l.lang,c.lang) FROM telegram_support_chats c
         LEFT JOIN telegram_bot_languages l USING (user_id) WHERE c.group_id=$1 AND c.thread_id=$2",
    )
    .bind(group)
    .bind(thread)
    .fetch_optional(&app.0.db)
    .await?;
    let Some((user, lang)) = target else {
        return Ok(());
    };
    let copy = &app.0.translations.get(&lang).bot;
    let text = format!("{} {text}", copy.support_reply);
    match send_reply(app, bot, message, user, &text).await {
        Ok(()) => Ok(()),
        Err(error) if permanent(&error) => {
            eprintln!("telegram support: {error}");
            if let Err(error) = bot
                .call::<Value>(
                    "sendMessage",
                    json!({
                        "chat_id": group, "message_thread_id": thread,
                        "text": app.0.translations.admin_bot().support_delivery_failed,
                    }),
                )
                .await
            {
                eprintln!("telegram support: {error}");
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn send_reply(
    app: &App,
    bot: &Bot,
    message: &Message,
    user: i64,
    mut text: &str,
) -> anyhow::Result<()> {
    let mut index = 0;
    while !text.is_empty() {
        let mut units = 0;
        let end = text
            .char_indices()
            .find_map(|(index, c)| {
                units += c.len_utf16();
                (units > 4096).then_some(index)
            })
            .unwrap_or(text.len());
        let (part, rest) = text.split_at(end);
        if !delivered(app, message, index).await? {
            bot.call::<Value>("sendMessage", json!({ "chat_id": user, "text": part }))
                .await?;
            mark_delivered(&app.0.db, message, index).await?;
        }
        text = rest;
        index += 1;
    }
    Ok(())
}

fn permanent(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<Rejected>()
        .is_some_and(|failure| matches!(failure.code, 400 | 403 | 404))
}

async fn delivered(app: &App, message: &Message, part: i16) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM telegram_support_deliveries WHERE chat_id=$1 AND message_id=$2 AND part=$3)",
    ).bind(message.chat.id).bind(message.message_id).bind(part).fetch_one(&app.0.db).await?)
}

async fn mark_delivered<'db>(
    db: impl sqlx::Executor<'db, Database = sqlx::Postgres>,
    message: &Message,
    part: i16,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO telegram_support_deliveries (chat_id,message_id,part) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
    ).bind(message.chat.id).bind(message.message_id).bind(part).execute(db).await?;
    Ok(())
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Reaction {
    Emoji {
        emoji: String,
    },
    CustomEmoji {
        custom_emoji_id: String,
    },
    Paid,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize)]
pub(crate) struct MessageReaction {
    chat: Chat,
    message_id: i64,
    user: Option<Sender>,
    actor_chat: Option<Chat>,
    date: i64,
    old_reaction: Vec<Reaction>,
    new_reaction: Vec<Reaction>,
}

#[derive(Deserialize)]
struct ChatMember {
    status: String,
}

pub async fn react(
    app: &App,
    bot: &Bot,
    event: MessageReaction,
    update_id: i64,
) -> anyhow::Result<()> {
    let group = event.chat.id;
    if event.chat.kind == "private" {
        if let Some(sender) = event
            .user
            .as_ref()
            .filter(|user| !user.is_bot && user.id == group)
        {
            refresh(app, bot, sender).await;
        }
        return Ok(());
    }
    if app.0.support_chat != Some(group) || event.chat.kind != "supergroup" {
        return Ok(());
    }
    let original: Option<(i64, i64)> = sqlx::query_as(
        "SELECT user_id,user_message_id FROM telegram_support_message_copies
         WHERE group_id=$1 AND group_message_id=$2",
    )
    .bind(group)
    .bind(event.message_id)
    .fetch_optional(&app.0.db)
    .await?;
    let Some((user, original_id)) = original else {
        return Ok(());
    };
    let Some(actor) = admin_actor(bot, group, &event).await? else {
        return Ok(());
    };
    let accepted = || {
        event
            .new_reaction
            .iter()
            .rev()
            .filter(|reaction| **reaction != Reaction::Unknown)
    };
    let reaction = accepted()
        .find(|reaction| !event.old_reaction.contains(reaction))
        .or_else(|| accepted().next())
        .cloned();
    if reaction.is_none() && !event.new_reaction.is_empty() {
        return Ok(());
    }
    let mut tx = app.0.db.begin().await?;
    let changed = sqlx::query(
        "INSERT INTO telegram_support_admin_reactions
             (group_id,group_message_id,actor_id,reaction,changed_at,update_id)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (group_id,group_message_id,actor_id) DO UPDATE
         SET reaction=EXCLUDED.reaction,changed_at=EXCLUDED.changed_at,update_id=EXCLUDED.update_id
         WHERE (telegram_support_admin_reactions.changed_at,telegram_support_admin_reactions.update_id)
            < (EXCLUDED.changed_at,EXCLUDED.update_id)",
    ).bind(group).bind(event.message_id).bind(actor).bind(reaction.map(Json))
        .bind(event.date).bind(update_id).execute(&mut *tx).await?.rows_affected();
    if changed != 0 {
        // Telegram lets bots display one reaction. Keep the most recent active admin reaction.
        let displayed: Option<Json<Reaction>> = sqlx::query_scalar(
            "SELECT reaction FROM telegram_support_admin_reactions
             WHERE group_id=$1 AND group_message_id=$2 AND reaction IS NOT NULL
             ORDER BY changed_at DESC,update_id DESC LIMIT 1",
        )
        .bind(group)
        .bind(event.message_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Err(error) = set_reaction(
            bot,
            user,
            original_id,
            displayed.map(|Json(reaction)| reaction),
        )
        .await
        {
            if !permanent(&error) {
                return Err(error);
            }
            eprintln!("telegram support reaction: {error}");
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn admin_actor(
    bot: &Bot,
    group: i64,
    event: &MessageReaction,
) -> anyhow::Result<Option<i64>> {
    if let Some(chat) = &event.actor_chat {
        return Ok((chat.id == group && chat.kind == "supergroup").then_some(group));
    }
    let Some(user) = event.user.as_ref().filter(|user| !user.is_bot) else {
        return Ok(None);
    };
    let result = bot
        .call::<ChatMember>(
            "getChatMember",
            json!({ "chat_id": group, "user_id": user.id }),
        )
        .await;
    match result {
        Ok(member) => {
            Ok(matches!(member.status.as_str(), "administrator" | "creator").then_some(user.id))
        }
        Err(error) if permanent(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn set_reaction(
    bot: &Bot,
    user: i64,
    id: i64,
    reaction: Option<Reaction>,
) -> anyhow::Result<()> {
    let thumbs_up = Reaction::Emoji {
        emoji: "👍".into()
    };
    let reaction = match reaction {
        Some(Reaction::Paid) => Some(thumbs_up.clone()),
        other => other,
    };
    let result = bot
        .call::<bool>(
            "setMessageReaction",
            json!({
                "chat_id": user, "message_id": id, "reaction": reaction.as_slice(),
            }),
        )
        .await;
    if matches!(reaction, Some(Reaction::CustomEmoji { .. }))
        && result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<Rejected>())
            .is_some_and(|failure| failure.code == 400)
    {
        bot.call::<bool>(
            "setMessageReaction",
            json!({
                "chat_id": user, "message_id": id, "reaction": [thumbs_up],
            }),
        )
        .await?;
        return Ok(());
    }
    result.map(|_| ())
}

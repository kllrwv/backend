use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::PgConnection;

use crate::{App, auth::security};

use super::{Bot, Chat, PhonePurpose, Sender, continue_auth, phone_prompt, support};

#[derive(Deserialize)]
pub(super) struct Callback {
    id: String,
    from: Sender,
    data: Option<String>,
    message: Option<CallbackMessage>,
}

#[derive(Deserialize)]
struct CallbackMessage {
    chat: Chat,
}

pub(super) fn default(sender: &Sender) -> &'static str {
    if sender
        .language_code
        .as_deref()
        .is_some_and(|lang| lang.starts_with("ru"))
    {
        "ru"
    } else {
        "en"
    }
}

pub(super) async fn saved(app: &App, user: i64) -> anyhow::Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT lang FROM telegram_bot_languages WHERE user_id=$1")
            .bind(user)
            .fetch_optional(&app.0.db)
            .await?,
    )
}

pub(super) async fn save(db: &mut PgConnection, user: i64, lang: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO telegram_bot_languages(user_id,lang) VALUES ($1,$2)
         ON CONFLICT (user_id) DO UPDATE SET lang=EXCLUDED.lang",
    )
    .bind(user)
    .bind(lang)
    .execute(db)
    .await?;
    Ok(())
}

pub(super) fn picker(app: &App) -> Value {
    let t = &app.0.translations;
    json!({"inline_keyboard": [[
        {"text": t.ru.bot.language_button, "callback_data": "lang:ru"},
        {"text": t.en.bot.language_button, "callback_data": "lang:en"},
    ]]})
}

pub(super) async fn choose(app: &App, bot: &Bot, chat: i64, lang: &str) -> anyhow::Result<()> {
    bot.send(
        chat,
        &app.0.translations.get(lang).bot.choose_language,
        picker(app),
    )
    .await
}

pub(super) async fn handle(app: &App, bot: &Bot, callback: Callback) -> anyhow::Result<()> {
    let sender = &callback.from;
    if sender.is_bot
        || !callback
            .message
            .as_ref()
            .is_some_and(|message| message.chat.kind == "private" && message.chat.id == sender.id)
    {
        return Ok(());
    }
    let lang = match callback.data.as_deref() {
        Some("lang:ru") => "ru",
        Some("lang:en") => "en",
        _ => return Ok(()),
    };
    let changing_phone = security::phone_change_pending(app, sender.id)
        .await
        .map_err(|_| anyhow::anyhow!("phone change lookup failed"))?;
    let mut tx = app.0.db.begin().await?;
    save(&mut tx, sender.id, lang).await?;
    let needs_code: Option<bool> = if changing_phone {
        None
    } else {
        sqlx::query_scalar(
            "UPDATE auth_flows SET telegram_language_selected=true
         WHERE id=(
             SELECT id FROM auth_flows WHERE telegram_sender=$1 AND stage='telegram'
               AND paired AND expires_at>now() ORDER BY expires_at DESC,id LIMIT 1
         )
         RETURNING telegram_code IS NOT NULL",
        )
        .bind(sender.id)
        .fetch_optional(&mut *tx)
        .await?
    };
    tx.commit().await?;

    let copy = &app.0.translations.get(lang).bot;
    if let Err(error) = bot
        .call::<bool>(
            "answerCallbackQuery",
            json!({
                "callback_query_id": callback.id, "text": copy.language_saved,
            }),
        )
        .await
    {
        eprintln!("telegram language selection: {error}");
    }
    if changing_phone {
        phone_prompt(bot, sender.id, copy, PhonePurpose::Change).await?;
    } else if let Some(needs_code) = needs_code {
        continue_auth(bot, sender.id, copy, needs_code).await?;
    }
    support::refresh(app, bot, sender).await;
    Ok(())
}

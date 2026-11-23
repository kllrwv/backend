use serde::Deserialize;
use std::{collections::HashMap, fs, io::ErrorKind, path::PathBuf};
const EMBEDDED: &str = include_str!("../translations.json");
#[derive(Deserialize)]
pub struct Translations {
    pub ru: Locale,
    pub en: Locale,
}
#[derive(Deserialize)]
pub struct Locale {
    pub bot: Bot,
    pub email: Email,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bot {
    pub language_button: String,
    pub choose_language: String,
    pub language_saved: String,
    pub open_from_website: String,
    pub invalid_link: String,
    pub code_prompt: String,
    pub code_wrong: String,
    pub code_locked: String,
    pub phone_prompt: String,
    pub phone_change_prompt: String,
    pub phone_change_invalid_link: String,
    pub phone_change_unavailable: String,
    pub phone_button: String,
    pub phone_changed: String,
    pub conflict: String,
    pub unlinked: String,
    pub success: String,
    pub support_prompt: String,
    pub support_unavailable: String,
    pub support_reply: String,
    admin: Option<AdminBot>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminBot {
    pub topic_fallback: String,
    pub support_delivery_failed: String,
    pub card: AccountCard,
    pub audit: AdminAudit,
}
#[derive(Deserialize)]
pub struct AdminAudit {
    pub title: String,
    pub action: String,
    pub actor: String,
    pub time: String,
    pub id: String,
    pub target: String,
    pub unknown: String,
    pub actions: HashMap<String, String>,
    pub details: HashMap<String, String>,
    #[serde(default)]
    pub fields: HashMap<String, String>,
    #[serde(default)]
    pub values: HashMap<String, String>,
    #[serde(default)]
    pub messages: HashMap<String, String>,
    #[serde(default)]
    pub permissions: HashMap<String, String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountCard {
    pub title: String,
    pub telegram_id: String,
    pub telegram_username: String,
    pub bot_language: String,
    pub missing_account: String,
    pub account: String,
    pub account_id: String,
    pub name: String,
    pub username: String,
    pub email: String,
    pub phone: String,
    pub phone_tail: String,
    pub missing_phone: String,
    pub sign_in: String,
    pub sign_in_methods: String,
    pub second_factor: String,
    pub authenticator_factor: String,
    pub email_factor: String,
    pub created: String,
    pub last_seen: String,
    pub sessions: String,
    pub avatar: String,
    pub banner: String,
    pub settings: String,
    pub theme: String,
    pub light: String,
    pub dark: String,
    pub system: String,
    pub wall: String,
    pub likes: String,
    pub messages: String,
    pub show_online: String,
    pub everyone: String,
    pub followers: String,
    pub nobody: String,
    pub notices: String,
    pub all: String,
    pub sound: String,
    pub follows: String,
    pub replies: String,
    pub mentions: String,
    pub bio: String,
    pub ru: String,
    pub en: String,
    pub yes: String,
    pub no: String,
    pub empty: String,
    pub time_utc: String,
}
#[derive(Deserialize)]
pub struct Email {
    pub subject: String,
    pub body: String,
}
impl Translations {
    pub fn load() -> anyhow::Result<Self> {
        let override_path = std::env::var_os("LOCALIZATIONS_PATH").filter(|path| !path.is_empty());
        let default_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("translations.json");
        let path = override_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or(default_path);
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if override_path.is_none() && error.kind() == ErrorKind::NotFound => {
                return Self::embedded();
            }
            Err(error) => return Err(anyhow::anyhow!("cannot read {}: {error}", path.display())),
        };
        Self::parse(&raw)
    }
    fn embedded() -> anyhow::Result<Self> {
        Self::parse(EMBEDDED)
    }
    fn parse(raw: &str) -> anyhow::Result<Self> {
        let translations: Self = serde_json::from_str(raw)?;
        anyhow::ensure!(
            translations.ru.bot.admin.is_some(),
            "missing ru.bot.admin localizations"
        );
        Ok(translations)
    }
    pub fn admin_bot(&self) -> &AdminBot {
        self.ru
            .bot
            .admin
            .as_ref()
            .expect("validated Russian admin locale")
    }
    pub fn get(&self, language: &str) -> &Locale {
        if language.starts_with("ru") {
            &self.ru
        } else {
            &self.en
        }
    }
}

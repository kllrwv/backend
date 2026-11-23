CREATE TABLE telegram_bot_languages (
    user_id bigint PRIMARY KEY,
    lang text NOT NULL CHECK (lang IN ('ru','en'))
);

INSERT INTO telegram_bot_languages (user_id, lang)
SELECT DISTINCT ON (telegram_sender) telegram_sender, lang
FROM auth_flows
WHERE telegram_sender IS NOT NULL AND telegram_language_selected
ORDER BY telegram_sender, expires_at DESC, id DESC;

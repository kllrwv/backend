-- Previous web attempts used redirects; pending attempts must start a fresh popup.
DELETE FROM telegram_web_flows;
ALTER TABLE telegram_web_flows DROP COLUMN state_key, ADD COLUMN registration_key text;

DELETE FROM auth_flows WHERE kind = 'telegram';
UPDATE auth_flows SET telegram_key = NULL, telegram_sender = NULL, paired = false
WHERE kind = 'register' AND stage = 'telegram';
ALTER TABLE auth_flows DROP COLUMN telegram_code, DROP COLUMN telegram_attempts;

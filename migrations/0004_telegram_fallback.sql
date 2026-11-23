ALTER TABLE auth_flows
    ADD COLUMN telegram_code text,
    ADD COLUMN telegram_attempts smallint NOT NULL DEFAULT 0,
    ADD COLUMN telegram_language_selected boolean NOT NULL DEFAULT false;

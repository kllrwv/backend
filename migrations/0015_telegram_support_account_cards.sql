ALTER TABLE telegram_support_chats
    ADD COLUMN topic_name text,
    ADD COLUMN card_message_id bigint,
    ADD COLUMN card_fingerprint text;

ALTER TABLE accounts ADD COLUMN phone_ciphertext bytea;

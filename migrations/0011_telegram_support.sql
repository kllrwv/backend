CREATE TABLE telegram_support_chats (
    group_id bigint NOT NULL,
    user_id bigint NOT NULL,
    thread_id bigint,
    lang text NOT NULL CHECK (lang IN ('ru', 'en')),
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY (group_id, user_id),
    UNIQUE (group_id, thread_id)
);

CREATE TABLE telegram_support_deliveries (
    chat_id bigint NOT NULL,
    message_id bigint NOT NULL,
    part smallint NOT NULL,
    delivered_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (chat_id, message_id, part)
);

CREATE INDEX telegram_support_deliveries_age ON telegram_support_deliveries (delivered_at);

CREATE TABLE telegram_support_reply_buttons (
    user_id bigint NOT NULL,
    private_message_id bigint NOT NULL,
    group_id bigint NOT NULL,
    group_message_id bigint NOT NULL,
    PRIMARY KEY (user_id, private_message_id),
    FOREIGN KEY (group_id, user_id)
        REFERENCES telegram_support_chats (group_id, user_id) ON DELETE CASCADE
);

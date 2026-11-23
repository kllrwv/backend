CREATE TABLE telegram_support_message_copies (
    group_id bigint NOT NULL,
    group_message_id bigint NOT NULL,
    user_id bigint NOT NULL,
    user_message_id bigint NOT NULL,
    PRIMARY KEY (group_id, group_message_id),
    FOREIGN KEY (group_id, user_id) REFERENCES telegram_support_chats (group_id, user_id) ON DELETE CASCADE
);

CREATE TABLE telegram_support_admin_reactions (
    group_id bigint NOT NULL,
    group_message_id bigint NOT NULL,
    actor_id bigint NOT NULL,
    reaction jsonb,
    changed_at bigint NOT NULL,
    update_id bigint NOT NULL,
    PRIMARY KEY (group_id, group_message_id, actor_id),
    FOREIGN KEY (group_id, group_message_id)
        REFERENCES telegram_support_message_copies (group_id, group_message_id) ON DELETE CASCADE
);

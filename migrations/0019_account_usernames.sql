CREATE TABLE account_usernames (
    username text PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    slot smallint NOT NULL CHECK (slot BETWEEN 0 AND 72),
    enabled boolean NOT NULL DEFAULT true,
    UNIQUE (account_id, slot),
    CHECK (slot <> 0 OR enabled)
);
INSERT INTO account_usernames(username, account_id, slot)
SELECT username, id, 0 FROM accounts WHERE username IS NOT NULL;
CREATE FUNCTION sync_primary_username() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.username IS NOT DISTINCT FROM OLD.username THEN RETURN NEW; END IF;
        DELETE FROM account_usernames WHERE account_id = NEW.id AND slot = 0;
    END IF;
    IF NEW.username IS NOT NULL THEN
        INSERT INTO account_usernames(username, account_id, slot) VALUES (NEW.username, NEW.id, 0);
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER account_primary_username AFTER INSERT OR UPDATE OF username ON accounts
FOR EACH ROW EXECUTE FUNCTION sync_primary_username();
UPDATE admin_roles r SET permissions = array_append(r.permissions, 'accounts.aliases.write')
FROM accounts a WHERE a.id = r.account_id AND a.deleted_at IS NULL AND NOT a.review_account
  AND (r.owner OR cardinality(r.permissions) > 0) AND NOT 'accounts.aliases.write' = ANY(r.permissions);
CREATE FUNCTION mentioned_accounts(body text) RETURNS SETOF uuid LANGUAGE sql STABLE STRICT AS $$
    SELECT DISTINCT h.account_id FROM mentioned_usernames(body) AS mention(username)
    JOIN account_usernames h USING (username) JOIN accounts a ON a.id=h.account_id
    WHERE h.enabled AND a.deleted_at IS NULL
$$;
CREATE OR REPLACE FUNCTION notify_post() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE recipient_id uuid;
BEGIN
    IF NEW.wall_owner_id IS NOT NULL THEN
        PERFORM notify_account(NEW.wall_owner_id, NEW.author_id, 'wall', NEW.id);
    END IF;
    IF NEW.reply_to IS NOT NULL THEN
        SELECT author_id INTO recipient_id FROM posts WHERE id = NEW.reply_to;
        PERFORM notify_account(recipient_id, NEW.author_id, 'reply', NEW.reply_to);
    END IF;
    FOR recipient_id IN
        SELECT mentioned_accounts(NEW.body)
    LOOP
        IF visible_post(NEW.id, recipient_id) THEN
            PERFORM notify_account(recipient_id, NEW.author_id, 'mention', NEW.id);
        END IF;
    END LOOP;
    RETURN NEW;
END
$$;
CREATE OR REPLACE FUNCTION notify_profile_mentions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM notify_account(added.account_id, NEW.id, 'mention', NULL)
    FROM (SELECT mentioned_accounts(NEW.bio) EXCEPT SELECT mentioned_accounts(OLD.bio)) AS added(account_id);
    RETURN NEW;
END
$$;

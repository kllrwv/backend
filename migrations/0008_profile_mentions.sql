CREATE FUNCTION mentioned_usernames(body text) RETURNS SETOF text
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT DISTINCT hit[1]
    FROM regexp_matches(lower(body),
        '(?<![[:alnum:]_@-])@([a-zа-яё0-9_-]{3,54})(?![[:alnum:]_-])', 'g'
    ) AS hit
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
        SELECT a.id FROM mentioned_usernames(NEW.body) AS mention(username)
        JOIN accounts a USING (username)
    LOOP
        IF visible_post(NEW.id, recipient_id) THEN
            PERFORM notify_account(recipient_id, NEW.author_id, 'mention', NEW.id);
        END IF;
    END LOOP;
    RETURN NEW;
END
$$;

CREATE FUNCTION notify_profile_mentions() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM notify_account(a.id, NEW.id, 'mention', NULL)
    FROM (
        SELECT * FROM mentioned_usernames(NEW.bio)
        EXCEPT
        SELECT * FROM mentioned_usernames(OLD.bio)
    ) AS added(username)
    JOIN accounts a USING (username);
    RETURN NEW;
END
$$;
CREATE TRIGGER notify_profile_mentions AFTER UPDATE OF bio ON accounts
FOR EACH ROW WHEN (NEW.bio IS DISTINCT FROM OLD.bio)
EXECUTE FUNCTION notify_profile_mentions();

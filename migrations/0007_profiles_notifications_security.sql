ALTER TABLE polls ALTER COLUMN ends_at DROP NOT NULL;
CREATE OR REPLACE FUNCTION poll_view(target uuid, viewer uuid) RETURNS jsonb
LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object(
        'question', question, 'ends_at', extract(epoch FROM ends_at)::bigint,
        'closed', coalesce(ends_at <= now(), false),
        'selected', (SELECT position FROM poll_votes WHERE post_id = target AND voter_id = viewer),
        'total', (SELECT count(*) FROM poll_votes WHERE post_id = target),
        'options', (
            SELECT jsonb_agg(jsonb_build_object(
                'position', o.position, 'label', o.label,
                'votes', (SELECT count(*) FROM poll_votes WHERE post_id = target AND position = o.position)
            ) ORDER BY o.position)
            FROM poll_options o WHERE o.post_id = target
        )
    )
    FROM polls WHERE post_id = target
$$;

ALTER TABLE accounts
    ADD COLUMN banner_object_id uuid UNIQUE,
    ADD COLUMN phone_tail text,
    ADD COLUMN last_seen timestamptz,
    ADD COLUMN wall_access text NOT NULL DEFAULT 'everyone' CHECK (wall_access IN ('everyone','followers','nobody')),
    ADD COLUMN like_access text NOT NULL DEFAULT 'nobody' CHECK (like_access IN ('everyone','followers','nobody')),
    ADD COLUMN message_access text NOT NULL DEFAULT 'everyone' CHECK (message_access IN ('everyone','followers','nobody')),
    ADD COLUMN show_online boolean NOT NULL DEFAULT true,
    ADD COLUMN theme text NOT NULL DEFAULT 'dark' CHECK (theme IN ('dark','light','system')),
    ADD COLUMN notice_preferences jsonb NOT NULL DEFAULT '{}';

CREATE FUNCTION queue_banner_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.banner_object_id IS NOT NULL THEN
        INSERT INTO media_gc VALUES (OLD.banner_object_id, now()) ON CONFLICT DO NOTHING;
    END IF;
    RETURN OLD;
END
$$;
CREATE TRIGGER queue_banner_delete AFTER DELETE ON accounts
FOR EACH ROW EXECUTE FUNCTION queue_banner_delete();
CREATE TRIGGER queue_replaced_banner AFTER UPDATE OF banner_object_id ON accounts
FOR EACH ROW WHEN (OLD.banner_object_id IS DISTINCT FROM NEW.banner_object_id)
EXECUTE FUNCTION queue_banner_delete();

CREATE TABLE account_blocks (
    blocker uuid REFERENCES accounts(id) ON DELETE CASCADE,
    blocked uuid REFERENCES accounts(id) ON DELETE CASCADE,
    PRIMARY KEY (blocker, blocked),
    CHECK (blocker <> blocked)
);

CREATE FUNCTION accounts_blocked(first_id uuid, second_id uuid) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT EXISTS (SELECT 1 FROM account_blocks
        WHERE (blocker, blocked) IN (($1, $2), ($2, $1)))
$$;

CREATE FUNCTION audience_allows(owner uuid, viewer uuid, audience text) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT owner = viewer OR (NOT accounts_blocked(owner, viewer) AND (
        audience = 'everyone' OR (audience = 'followers' AND EXISTS (
            SELECT 1 FROM follows WHERE follower_id = viewer AND followed_id = owner))))
$$;

ALTER TABLE posts ADD COLUMN wall_owner_id uuid REFERENCES accounts(id) ON DELETE CASCADE;
ALTER TABLE posts ADD CONSTRAINT wall_post_kind CHECK (
    wall_owner_id IS NULL OR (wall_owner_id <> author_id AND reply_to IS NULL AND NOT is_repost)
);
CREATE INDEX posts_wall ON posts(wall_owner_id, created_at DESC, id DESC) WHERE wall_owner_id IS NOT NULL;
CREATE INDEX follows_followed ON follows(followed_id);

CREATE FUNCTION visible_post(target uuid, viewer uuid) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT EXISTS (
        SELECT 1 FROM posts p LEFT JOIN posts parent ON parent.id = p.reply_to
        WHERE p.id = target AND NOT accounts_blocked(p.author_id, viewer)
          AND NOT coalesce(accounts_blocked(parent.author_id, viewer), false)
          AND NOT coalesce(accounts_blocked(coalesce(p.wall_owner_id, parent.wall_owner_id), viewer), false)
    )
$$;

CREATE OR REPLACE FUNCTION index_post_hashtags() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        DELETE FROM post_hashtags WHERE post_id = NEW.id;
    END IF;
    IF NEW.reply_to IS NULL AND NEW.wall_owner_id IS NULL THEN
        INSERT INTO post_hashtags(post_id, tag)
        SELECT NEW.id, tag FROM hashtags(NEW.body) AS tag;
    END IF;
    RETURN NEW;
END
$$;

CREATE TABLE notifications (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recipient uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    actor uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('follow','wall','like','reply','mention')),
    post_id uuid REFERENCES posts(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    read_at timestamptz
);
CREATE UNIQUE INDEX notifications_event ON notifications(recipient, actor, kind, post_id) NULLS NOT DISTINCT;
CREATE INDEX notifications_inbox ON notifications(recipient, id DESC);
CREATE INDEX notifications_unread ON notifications(recipient, id) WHERE read_at IS NULL;

CREATE FUNCTION notify_account(recipient_id uuid, actor_id uuid, event_kind text, target uuid)
RETURNS void LANGUAGE sql AS $$
    INSERT INTO notifications(recipient, actor, kind, post_id)
    SELECT id, actor_id, event_kind, target FROM accounts
    WHERE id = recipient_id AND id <> actor_id AND NOT accounts_blocked(id, actor_id)
      AND coalesce((notice_preferences->>'all')::boolean, true)
      AND coalesce((notice_preferences->>event_kind)::boolean, true)
    ON CONFLICT DO NOTHING
$$;

CREATE FUNCTION notify_post() RETURNS trigger LANGUAGE plpgsql AS $$
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
        SELECT DISTINCT a.id FROM regexp_matches(lower(NEW.body),
            '(?<![[:alnum:]_@])@([[:alnum:]_-]{3,54})(?![[:alnum:]_-])', 'g') AS hit
        JOIN accounts a ON a.username = hit[1]
    LOOP
        IF visible_post(NEW.id, recipient_id) THEN
            PERFORM notify_account(recipient_id, NEW.author_id, 'mention', NEW.id);
        END IF;
    END LOOP;
    RETURN NEW;
END
$$;
CREATE TRIGGER notify_post AFTER INSERT ON posts FOR EACH ROW EXECUTE FUNCTION notify_post();

CREATE FUNCTION notify_reaction() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE recipient_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'follows' THEN
        PERFORM notify_account(NEW.followed_id, NEW.follower_id, 'follow', NULL);
    ELSE
        SELECT author_id INTO recipient_id FROM posts WHERE id = NEW.post_id;
        PERFORM notify_account(recipient_id, NEW.account_id, 'like', NEW.post_id);
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER notify_follow AFTER INSERT ON follows FOR EACH ROW EXECUTE FUNCTION notify_reaction();
CREATE TRIGGER notify_like AFTER INSERT ON post_likes FOR EACH ROW EXECUTE FUNCTION notify_reaction();

ALTER TABLE sessions
    ADD COLUMN public_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ADD COLUMN device text,
    ADD COLUMN last_seen timestamptz;
UPDATE sessions SET last_seen = expires_at - interval '30 days';
ALTER TABLE sessions ALTER COLUMN last_seen SET DEFAULT now(), ALTER COLUMN last_seen SET NOT NULL;

CREATE TABLE retired_contacts (
    kind text CHECK (kind IN ('email','phone')),
    fingerprint text,
    PRIMARY KEY (kind, fingerprint)
);

CREATE FUNCTION contact_fingerprint(kind text, value text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT CASE WHEN kind = 'email' THEN encode(sha256(convert_to(lower(value), 'UTF8')), 'hex') ELSE value END
$$;

CREATE FUNCTION contact_retired(contact_kind text, value text) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT EXISTS (SELECT 1 FROM retired_contacts
        WHERE kind = contact_kind AND fingerprint = contact_fingerprint(contact_kind, value))
$$;

CREATE FUNCTION enforce_contact_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.email = OLD.email AND NEW.phone_key = OLD.phone_key THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(73460650021401);
    IF (TG_OP = 'INSERT' OR NEW.email IS DISTINCT FROM OLD.email) AND contact_retired('email', NEW.email)
        OR (TG_OP = 'INSERT' OR NEW.phone_key IS DISTINCT FROM OLD.phone_key) AND contact_retired('phone', NEW.phone_key) THEN
        IF TG_OP = 'INSERT' THEN RETURN NULL; END IF;
        RAISE check_violation USING CONSTRAINT = 'contact_retired';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.email IS DISTINCT FROM OLD.email THEN
            INSERT INTO retired_contacts VALUES ('email', contact_fingerprint('email',OLD.email)) ON CONFLICT DO NOTHING;
        END IF;
        IF NEW.phone_key IS DISTINCT FROM OLD.phone_key THEN
            INSERT INTO retired_contacts VALUES ('phone', OLD.phone_key) ON CONFLICT DO NOTHING;
        END IF;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER enforce_contact_history BEFORE INSERT OR UPDATE OF email, phone_key
ON accounts FOR EACH ROW EXECUTE FUNCTION enforce_contact_history();

CREATE TABLE account_changes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('email','phone')),
    previous text NOT NULL,
    destination text,
    code text,
    bot_digest text UNIQUE,
    bot_opened boolean NOT NULL DEFAULT false,
    result text CHECK (result IN ('done','contact_unavailable')),
    attempts smallint NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL DEFAULT now() + interval '15 minutes',
    UNIQUE (account_id, kind)
);
CREATE INDEX account_changes_expiry ON account_changes(expires_at);

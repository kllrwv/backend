CREATE TABLE post_hashtags (
    post_id uuid REFERENCES posts(id) ON DELETE CASCADE,
    tag text CHECK (char_length(tag) BETWEEN 1 AND 54),
    PRIMARY KEY (post_id, tag)
);
CREATE INDEX post_hashtags_tag ON post_hashtags(tag, post_id);

CREATE FUNCTION hashtags(text) RETURNS SETOF text
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT DISTINCT hit[1] FROM regexp_matches(
        lower($1), '(?<![[:alnum:]_#])#([[:alnum:]_]{1,54})(?![[:alnum:]_])', 'g'
    ) AS hit
$$;

INSERT INTO post_hashtags(post_id, tag)
SELECT p.id, tag FROM posts p CROSS JOIN LATERAL hashtags(p.body) AS tag
WHERE p.reply_to IS NULL;

CREATE FUNCTION index_post_hashtags() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        DELETE FROM post_hashtags WHERE post_id = NEW.id;
    END IF;
    IF NEW.reply_to IS NULL THEN
        INSERT INTO post_hashtags(post_id, tag)
        SELECT NEW.id, tag FROM hashtags(NEW.body) AS tag;
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER index_post_hashtags AFTER INSERT OR UPDATE OF body, reply_to
ON posts FOR EACH ROW EXECUTE FUNCTION index_post_hashtags();

CREATE TABLE media_gc (
    object_id uuid PRIMARY KEY,
    delete_after timestamptz NOT NULL
);
CREATE INDEX media_gc_due ON media_gc(delete_after);

CREATE TABLE post_media (
    post_id uuid REFERENCES posts(id) ON DELETE CASCADE,
    position smallint CHECK (position BETWEEN 0 AND 3),
    object_id uuid NOT NULL UNIQUE,
    kind text NOT NULL CHECK (kind IN ('image', 'video', 'audio')),
    mime text NOT NULL,
    title text NOT NULL DEFAULT '',
    PRIMARY KEY (post_id, position)
);

ALTER TABLE accounts ADD COLUMN avatar_object_id uuid UNIQUE;

CREATE FUNCTION queue_post_media_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO media_gc VALUES (OLD.object_id, now()) ON CONFLICT DO NOTHING;
    RETURN OLD;
END
$$;
CREATE TRIGGER queue_post_media_delete AFTER DELETE ON post_media
FOR EACH ROW EXECUTE FUNCTION queue_post_media_delete();

CREATE FUNCTION queue_avatar_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.avatar_object_id IS NOT NULL THEN
        INSERT INTO media_gc VALUES (OLD.avatar_object_id, now()) ON CONFLICT DO NOTHING;
    END IF;
    RETURN OLD;
END
$$;
CREATE TRIGGER queue_avatar_delete AFTER DELETE ON accounts
FOR EACH ROW EXECUTE FUNCTION queue_avatar_delete();
CREATE TRIGGER queue_replaced_avatar AFTER UPDATE OF avatar_object_id ON accounts
FOR EACH ROW WHEN (OLD.avatar_object_id IS DISTINCT FROM NEW.avatar_object_id)
EXECUTE FUNCTION queue_avatar_delete();

CREATE FUNCTION post_attachments(target uuid) RETURNS jsonb
LANGUAGE sql STABLE AS $$
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'position', position, 'kind', kind, 'title', title
    ) ORDER BY position), '[]'::jsonb)
    FROM post_media WHERE post_id = target
$$;

CREATE TABLE polls (
    post_id uuid PRIMARY KEY REFERENCES posts(id) ON DELETE CASCADE,
    question text NOT NULL CHECK (char_length(question) BETWEEN 1 AND 140),
    ends_at timestamptz NOT NULL
);

CREATE TABLE poll_options (
    post_id uuid REFERENCES polls(post_id) ON DELETE CASCADE,
    position smallint CHECK (position BETWEEN 0 AND 5),
    label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 80),
    PRIMARY KEY (post_id, position)
);

CREATE TABLE poll_votes (
    post_id uuid,
    voter_id uuid REFERENCES accounts(id) ON DELETE CASCADE,
    position smallint NOT NULL,
    PRIMARY KEY (post_id, voter_id),
    FOREIGN KEY (post_id, position) REFERENCES poll_options(post_id, position) ON DELETE CASCADE
);
CREATE INDEX poll_votes_option ON poll_votes(post_id, position);

CREATE FUNCTION poll_view(target uuid, viewer uuid) RETURNS jsonb
LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object(
        'question', question,
        'ends_at', extract(epoch FROM ends_at)::bigint,
        'closed', ends_at <= now(),
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

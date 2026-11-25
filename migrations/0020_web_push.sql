CREATE TABLE web_push_preferences (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    activity boolean NOT NULL DEFAULT true,
    following boolean NOT NULL DEFAULT true,
    recommendations boolean NOT NULL DEFAULT false,
    reminders boolean NOT NULL DEFAULT false,
    last_recommendation timestamptz,
    last_reminder timestamptz,
    reminder_variant smallint
);
CREATE TABLE web_push_subscriptions (
    session_id text PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    endpoint text NOT NULL UNIQUE,
    p256dh text NOT NULL,
    auth text NOT NULL,
    lang text NOT NULL CHECK (lang IN ('ru','en'))
);
CREATE INDEX web_push_subscriptions_account ON web_push_subscriptions(account_id);
CREATE TABLE web_push_jobs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    session_id text NOT NULL REFERENCES web_push_subscriptions(session_id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('activity','following','recommendations','reminders','test')),
    notification_id bigint REFERENCES notifications(id) ON DELETE CASCADE,
    post_id uuid REFERENCES posts(id) ON DELETE CASCADE,
    variant smallint,
    created_at timestamptz NOT NULL DEFAULT now(),
    available_at timestamptz NOT NULL DEFAULT now(),
    attempts smallint NOT NULL DEFAULT 0
);
CREATE INDEX web_push_jobs_available ON web_push_jobs(available_at,id);
CREATE INDEX web_push_jobs_session ON web_push_jobs(session_id);
CREATE INDEX web_push_jobs_notice ON web_push_jobs(notification_id) WHERE notification_id IS NOT NULL;
CREATE INDEX web_push_jobs_post ON web_push_jobs(post_id) WHERE post_id IS NOT NULL;
CREATE FUNCTION enqueue_activity_push() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO web_push_jobs(session_id,kind,notification_id)
    SELECT s.session_id,'activity',NEW.id
    FROM web_push_subscriptions s JOIN web_push_preferences pref ON pref.account_id=s.account_id
    JOIN sessions active ON active.id=s.session_id AND active.expires_at>now()
    WHERE s.account_id=NEW.recipient AND pref.activity;
    RETURN NEW;
END
$$;
CREATE TRIGGER enqueue_activity_push AFTER INSERT ON notifications
FOR EACH ROW EXECUTE FUNCTION enqueue_activity_push();
CREATE FUNCTION enqueue_following_push() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO web_push_jobs(session_id,kind,post_id)
    SELECT s.session_id,'following',NEW.id
    FROM follows f JOIN web_push_subscriptions s ON s.account_id=f.follower_id
    JOIN web_push_preferences pref ON pref.account_id=s.account_id
    JOIN sessions active ON active.id=s.session_id AND active.expires_at>now()
    JOIN accounts a ON a.id=s.account_id AND a.deleted_at IS NULL
    WHERE f.followed_id=NEW.author_id AND pref.following
      AND coalesce((a.notice_preferences->>'all')::boolean,true) AND visible_post(NEW.id,a.id);
    RETURN NEW;
END
$$;
CREATE TRIGGER enqueue_following_push AFTER INSERT ON posts
FOR EACH ROW WHEN (NEW.reply_to IS NULL AND (NEW.wall_owner_id IS NULL OR NEW.wall_owner_id=NEW.author_id))
EXECUTE FUNCTION enqueue_following_push();

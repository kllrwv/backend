CREATE TABLE posts (
    id uuid PRIMARY KEY,
    author_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    body text NOT NULL DEFAULT '' CHECK (char_length(body) <= 1000),
    created_at timestamptz NOT NULL DEFAULT now(),
    is_repost boolean NOT NULL DEFAULT false,
    repost_of uuid REFERENCES posts(id) ON DELETE SET NULL,
    reply_to uuid REFERENCES posts(id) ON DELETE CASCADE,
    CHECK (repost_of IS NULL OR is_repost),
    CHECK (reply_to IS NULL OR NOT is_repost)
);
CREATE INDEX posts_timeline ON posts (created_at DESC, id DESC) WHERE reply_to IS NULL;
CREATE INDEX posts_author ON posts (author_id, created_at DESC);
CREATE INDEX posts_replies ON posts (reply_to, created_at, id) WHERE reply_to IS NOT NULL;
CREATE INDEX posts_repost_targets ON posts (repost_of) WHERE repost_of IS NOT NULL;
CREATE UNIQUE INDEX posts_reposted_once ON posts (author_id, repost_of) WHERE repost_of IS NOT NULL;

CREATE TABLE post_images (
    post_id uuid PRIMARY KEY REFERENCES posts(id) ON DELETE CASCADE,
    data bytea NOT NULL
);
CREATE TABLE post_likes (
    post_id uuid REFERENCES posts(id) ON DELETE CASCADE,
    account_id uuid REFERENCES accounts(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (post_id, account_id)
);
CREATE INDEX post_likes_account ON post_likes (account_id, created_at DESC);

CREATE TABLE post_views (
    post_id uuid REFERENCES posts(id) ON DELETE CASCADE,
    account_id uuid REFERENCES accounts(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, account_id)
);
CREATE TABLE follows (
    follower_id uuid REFERENCES accounts(id) ON DELETE CASCADE,
    followed_id uuid REFERENCES accounts(id) ON DELETE CASCADE,
    CHECK (follower_id <> followed_id),
    PRIMARY KEY (follower_id, followed_id)
);

CREATE TABLE service_checks (
    service text NOT NULL,
    minute bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('ok', 'slow', 'down')),
    PRIMARY KEY (service, minute)
);
CREATE INDEX service_checks_minute ON service_checks (minute);

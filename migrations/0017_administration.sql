ALTER TABLE accounts ADD COLUMN verified boolean NOT NULL DEFAULT false,
    ADD COLUMN avatar_hidden boolean NOT NULL DEFAULT false,
    ADD COLUMN banner_hidden boolean NOT NULL DEFAULT false,
    ADD COLUMN deleted_at timestamptz;
ALTER TABLE posts ADD COLUMN deleted_at timestamptz;
ALTER TABLE post_media ADD COLUMN deleted_at timestamptz;
ALTER TABLE polls ADD COLUMN deleted_at timestamptz;

CREATE TABLE admin_roles (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    owner boolean NOT NULL DEFAULT false,
    permissions text[] NOT NULL
);
CREATE UNIQUE INDEX admin_single_owner ON admin_roles (owner) WHERE owner;

CREATE TABLE admin_logins (
    digest text PRIMARY KEY,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL DEFAULT now() + interval '60 seconds'
);
CREATE TABLE admin_sessions (
    digest text PRIMARY KEY,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL DEFAULT now() + interval '8 hours'
);
CREATE INDEX admin_sessions_parent ON admin_sessions(session_id);

CREATE TABLE admin_events (
    id uuid PRIMARY KEY,
    actor_id uuid NOT NULL,
    actor_name text NOT NULL,
    action text NOT NULL,
    target_id uuid,
    details jsonb NOT NULL DEFAULT '{}',
    undo bytea,
    undone_by uuid REFERENCES admin_events(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz
);
CREATE INDEX admin_events_recent ON admin_events(created_at DESC,id DESC);
CREATE INDEX admin_events_pending ON admin_events(created_at,id) WHERE delivered_at IS NULL;

CREATE TABLE reports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id uuid NOT NULL,
    target_kind text NOT NULL CHECK(target_kind IN ('account','post','comment','attachment','avatar','banner','poll')),
    target_id uuid NOT NULL,
    part smallint NOT NULL DEFAULT -1,
    reason text NOT NULL,
    description text NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','accepted','dismissed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    reviewed_at timestamptz,
    reviewed_by uuid,
    note text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX reports_once ON reports(reporter_id,target_kind,target_id,part) WHERE state='pending';
CREATE INDEX reports_queue ON reports (state,created_at,id);

CREATE FUNCTION admin_can(actor uuid, permission text) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT EXISTS (
        SELECT 1 FROM admin_roles r JOIN accounts a ON a.id=r.account_id
        WHERE r.account_id=$1 AND a.deleted_at IS NULL AND (r.owner OR $2=ANY(r.permissions))
    )
$$;

CREATE OR REPLACE FUNCTION audience_allows(owner uuid, viewer uuid, audience text) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT EXISTS (SELECT 1 FROM accounts WHERE id=owner AND deleted_at IS NULL) AND
        (owner=viewer OR (NOT accounts_blocked(owner,viewer) AND
        (audience='everyone' OR (audience='followers' AND EXISTS (
            SELECT 1 FROM follows WHERE follower_id=viewer AND followed_id=owner)))))
$$;

CREATE FUNCTION post_removed(target uuid) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT coalesce((
        SELECT p.deleted_at IS NOT NULL OR parent.deleted_at IS NOT NULL
            OR a.deleted_at IS NOT NULL OR pa.deleted_at IS NOT NULL OR w.deleted_at IS NOT NULL
        FROM posts p JOIN accounts a ON a.id=p.author_id
        LEFT JOIN posts parent ON parent.id=p.reply_to
        LEFT JOIN accounts pa ON pa.id=parent.author_id
        LEFT JOIN accounts w ON w.id=coalesce(p.wall_owner_id,parent.wall_owner_id)
        WHERE p.id=target
    ),true)
$$;

CREATE OR REPLACE FUNCTION visible_post(target uuid, viewer uuid) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT NOT post_removed(target) AND EXISTS (
        SELECT 1 FROM posts p LEFT JOIN posts parent ON parent.id=p.reply_to
        WHERE p.id=target AND NOT accounts_blocked(p.author_id,viewer)
          AND NOT coalesce(accounts_blocked(parent.author_id,viewer),false)
          AND NOT coalesce(accounts_blocked(coalesce(p.wall_owner_id,parent.wall_owner_id),viewer),false)
    )
$$;

CREATE FUNCTION readable_post(target uuid,viewer uuid) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT visible_post(target,viewer) OR admin_can(viewer,'content.moderate')
$$;

CREATE FUNCTION moderated_attachments(target uuid,viewer uuid) RETURNS jsonb
LANGUAGE sql STABLE STRICT AS $$
    SELECT coalesce(jsonb_agg(jsonb_build_object('position',position,'kind',kind,'title',title,
        'deleted',deleted_at IS NOT NULL) ORDER BY position),'[]'::jsonb)
    FROM post_media WHERE post_id=target AND (deleted_at IS NULL OR admin_can(viewer,'content.moderate'))
$$;

CREATE TABLE media_sizes (
    object_id uuid PRIMARY KEY,
    bytes bigint NOT NULL CHECK(bytes>=0)
);

CREATE TABLE admin_ops_jobs (
    id uuid PRIMARY KEY,
    payload bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    dispatched_at timestamptz
);

DROP INDEX posts_reposted_once;
CREATE UNIQUE INDEX posts_reposted_once ON posts(author_id,repost_of) WHERE repost_of IS NOT NULL AND deleted_at IS NULL;

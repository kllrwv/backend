CREATE TABLE accounts (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    telegram_id bigint NOT NULL UNIQUE,
    phone_key text NOT NULL UNIQUE,
    username text UNIQUE,
    display_name text,
    bio text NOT NULL DEFAULT '',
    avatar bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((username IS NULL) = (display_name IS NULL))
);

CREATE TABLE auth_flows (
    id text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('register', 'login', 'telegram')),
    stage text NOT NULL CHECK (stage IN ('email', 'telegram', 'ready', 'conflict', 'unlinked')),
    lang text NOT NULL CHECK (lang IN ('ru', 'en')),
    email text,
    password_hash text,
    email_code text,
    email_attempts smallint NOT NULL DEFAULT 0,
    telegram_key text UNIQUE,
    telegram_code text,
    telegram_sender bigint,
    telegram_attempts smallint NOT NULL DEFAULT 0,
    paired boolean NOT NULL DEFAULT false,
    account_id uuid REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX auth_flows_sender ON auth_flows (telegram_sender);
CREATE INDEX auth_flows_expiry ON auth_flows (expires_at);

CREATE TABLE sessions (
    id text PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '30 days')
);
CREATE INDEX sessions_expiry ON sessions (expires_at);

CREATE TABLE rate_limits (
    id text PRIMARY KEY,
    hits integer NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX rate_limits_expiry ON rate_limits (expires_at);

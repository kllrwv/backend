CREATE TABLE telegram_web_flows (
    browser_key text PRIMARY KEY,
    state_key text NOT NULL,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '10 minutes')
);
CREATE INDEX telegram_web_flows_expiry ON telegram_web_flows (expires_at);

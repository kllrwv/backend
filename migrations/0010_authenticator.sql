ALTER TABLE accounts
    ADD COLUMN totp_generation uuid,
    ADD COLUMN totp_secret bytea,
    ADD COLUMN totp_last_step bigint,
    ADD CONSTRAINT accounts_totp_state CHECK (
        (totp_generation IS NULL AND totp_secret IS NULL AND totp_last_step IS NULL)
        OR (totp_generation IS NOT NULL AND totp_secret IS NOT NULL AND totp_last_step IS NOT NULL)
    );

ALTER TABLE auth_flows DROP CONSTRAINT auth_flows_stage_check;
ALTER TABLE auth_flows
    ADD COLUMN totp_generation uuid,
    ADD CONSTRAINT auth_flows_stage_check CHECK (stage IN ('email', 'telegram', 'totp', 'ready', 'conflict', 'unlinked')),
    ADD CONSTRAINT auth_flows_totp_state CHECK (
        (stage = 'totp' AND totp_generation IS NOT NULL AND account_id IS NOT NULL AND kind = 'login')
        OR (stage <> 'totp' AND totp_generation IS NULL)
    );

CREATE TABLE totp_enrollments (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    session_id text NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    generation uuid NOT NULL,
    secret bytea NOT NULL,
    expires_at timestamptz NOT NULL DEFAULT now() + interval '10 minutes'
);

CREATE TABLE totp_recovery_codes (
    account_id uuid REFERENCES accounts(id) ON DELETE CASCADE,
    fingerprint text,
    PRIMARY KEY (account_id, fingerprint)
);

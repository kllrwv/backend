ALTER TABLE accounts
    ADD COLUMN email_lookup text,
    ADD COLUMN email_ciphertext bytea,
    ADD COLUMN phone_tail_ciphertext bytea;
ALTER TABLE auth_flows
    ADD COLUMN email_lookup text,
    ADD COLUMN email_ciphertext bytea;
ALTER TABLE account_changes ADD COLUMN destination_ciphertext bytea;

CREATE TABLE contact_storage (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    key_check text NOT NULL
);

ALTER TABLE accounts
    ADD CONSTRAINT accounts_required_email CHECK (
        (email_lookup IS NULL) = (email_ciphertext IS NULL)
        AND (review_account OR email_lookup IS NOT NULL)
    ),
    ADD UNIQUE (email_lookup),
    ADD CONSTRAINT accounts_lookup_format CHECK (email_lookup LIKE 'v1:%' AND phone_key LIKE 'v1:%'),
    DROP COLUMN email,
    DROP COLUMN phone_tail;

ALTER TABLE auth_flows
    ADD CONSTRAINT auth_email_storage CHECK (
        (email_lookup IS NULL AND email_ciphertext IS NULL)
        OR (email_lookup IS NOT NULL AND email_lookup LIKE 'v1:%' AND email_ciphertext IS NOT NULL)
    ),
    DROP COLUMN email;

ALTER TABLE account_changes RENAME COLUMN destination TO destination_lookup;
ALTER TABLE account_changes ADD CONSTRAINT change_contact_storage CHECK (
    previous LIKE 'v1:%' AND (
        (kind = 'phone' AND destination_lookup IS NULL AND destination_ciphertext IS NULL)
        OR (kind = 'email' AND destination_lookup IS NOT NULL AND destination_lookup LIKE 'v1:%'
            AND destination_ciphertext IS NOT NULL)
    )
);
ALTER TABLE retired_contacts ADD CONSTRAINT retired_contact_lookup_format CHECK (fingerprint LIKE 'v1:%');

CREATE OR REPLACE FUNCTION contact_retired(contact_kind text, value text) RETURNS boolean
LANGUAGE sql STABLE STRICT AS $$
    SELECT EXISTS (SELECT 1 FROM retired_contacts WHERE kind = contact_kind AND fingerprint = value)
$$;
DROP FUNCTION contact_fingerprint(text,text);

DROP FUNCTION enforce_contact_history();
CREATE TRIGGER enforce_contact_history BEFORE INSERT OR UPDATE OF email_lookup, phone_key
ON accounts FOR EACH ROW EXECUTE FUNCTION enforce_encrypted_contact_history();

-- Rewrite the live tables to remove old tuple versions and dropped column data.
CLUSTER accounts USING accounts_pkey;
CLUSTER auth_flows USING auth_flows_pkey;
CLUSTER account_changes USING account_changes_pkey;
CLUSTER retired_contacts USING retired_contacts_pkey;

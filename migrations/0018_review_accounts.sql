ALTER TABLE accounts
    ADD COLUMN review_account boolean NOT NULL DEFAULT false,
    ALTER COLUMN phone_key DROP NOT NULL,
    ALTER COLUMN telegram_id DROP NOT NULL,
    ADD CONSTRAINT accounts_required_links CHECK (
        review_account OR (phone_key IS NOT NULL AND telegram_id IS NOT NULL)
    );

ALTER TABLE account_changes ALTER COLUMN previous DROP NOT NULL;

CREATE FUNCTION enforce_encrypted_contact_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.email_lookup IS NOT DISTINCT FROM OLD.email_lookup
                        AND NEW.phone_key IS NOT DISTINCT FROM OLD.phone_key THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(73460650021401);
    IF (TG_OP = 'INSERT' OR NEW.email_lookup IS DISTINCT FROM OLD.email_lookup)
            AND contact_retired('email', NEW.email_lookup)
        OR (TG_OP = 'INSERT' OR NEW.phone_key IS DISTINCT FROM OLD.phone_key)
            AND contact_retired('phone', NEW.phone_key) THEN
        IF TG_OP = 'INSERT' THEN RETURN NULL; END IF;
        RAISE check_violation USING CONSTRAINT = 'contact_retired';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.email_lookup IS NOT NULL AND NEW.email_lookup IS DISTINCT FROM OLD.email_lookup THEN
            INSERT INTO retired_contacts VALUES ('email', OLD.email_lookup) ON CONFLICT DO NOTHING;
        END IF;
        IF OLD.phone_key IS NOT NULL AND NEW.phone_key IS DISTINCT FROM OLD.phone_key THEN
            INSERT INTO retired_contacts VALUES ('phone', OLD.phone_key) ON CONFLICT DO NOTHING;
        END IF;
    END IF;
    RETURN NEW;
END
$$;

-- New installations finish contact encryption after all SQL migrations.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM contact_storage WHERE singleton) THEN
        ALTER TABLE accounts
            ALTER COLUMN email_lookup DROP NOT NULL,
            ALTER COLUMN email_ciphertext DROP NOT NULL,
            ADD CONSTRAINT accounts_required_email CHECK (
                (email_lookup IS NULL) = (email_ciphertext IS NULL)
                AND (review_account OR email_lookup IS NOT NULL)
            );
        DROP TRIGGER enforce_contact_history ON accounts;
        CREATE TRIGGER enforce_contact_history BEFORE INSERT OR UPDATE OF email_lookup, phone_key
            ON accounts FOR EACH ROW EXECUTE FUNCTION enforce_encrypted_contact_history();
        DROP FUNCTION enforce_contact_history();
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION admin_can(actor uuid, permission text) RETURNS boolean LANGUAGE sql STABLE STRICT AS $$
    SELECT EXISTS (
        SELECT 1 FROM admin_roles r JOIN accounts a ON a.id=r.account_id
        WHERE r.account_id=$1 AND a.deleted_at IS NULL AND NOT a.review_account
          AND (r.owner OR $2=ANY(r.permissions))
    )
$$;

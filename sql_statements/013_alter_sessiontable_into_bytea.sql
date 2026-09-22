BEGIN;

TRUNCATE TABLE sessions;

ALTER TABLE sessions
    DROP CONSTRAINT IF EXISTS sessions_pkey;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS session_id;

ALTER TABLE sessions
    ADD COLUMN session_id_hash bytea PRIMARY KEY;

CREATE INDEX IF NOT EXISTS sessions_valid_idx
    ON sessions (session_id_hash, expires_at)
    WHERE revoked_at IS NULL;

COMMIT;

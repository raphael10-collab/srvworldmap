BEGIN;

ALTER TABLE users
    ADD COLUMN email text,
    ADD COLUMN password_hash text;

ALTER TABLE users
    ALTER COLUMN email SET NOT NULL,
    ALTER COLUMN password_hash SET NOT NULL,
    ALTER COLUMN can_view_restricted_map SET DEFAULT false;

ALTER TABLE users
    ADD CONSTRAINT users_email_unique UNIQUE (email);

COMMIT;

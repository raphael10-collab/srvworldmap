CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE user_sessions (
    session_id_hash bytea PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX user_sessions_expiry_idx
    ON user_sessions (expires_at);

CREATE TABLE restricted_markers (
    id bigint PRIMARY KEY,
    owner_user_id bigint NOT NULL REFERENCES users(id),
    geom geometry(Point, 4326) NOT NULL,
    title text NOT NULL,
    description text,
    visible_from timestamptz NULL,
    visible_until timestamptz NULL
);

CREATE INDEX restricted_markers_geom_gix
    ON restricted_markers USING gist (geom);

CREATE INDEX restricted_markers_owner_idx
    ON restricted_markers (owner_user_id);

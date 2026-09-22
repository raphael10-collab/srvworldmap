CREATE EXTENSION IF NOT EXISTS postgis;

CREATE TABLE IF NOT EXISTS users (
    id bigint PRIMARY KEY,
    can_view_restricted_map boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id text PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx
    ON sessions (user_id);

CREATE INDEX IF NOT EXISTS sessions_valid_idx
    ON sessions (session_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS restricted_features (
    id bigint PRIMARY KEY,
    owner_user_id bigint NOT NULL REFERENCES users(id),
    geom geometry(Geometry, 4326) NOT NULL,
    name text,
    properties jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- Required spatial index for tile intersection queries.
CREATE INDEX IF NOT EXISTS restricted_features_geom_gist_idx
    ON restricted_features
    USING GIST (geom);

-- Helps when authorization also filters by owner or tenant.
CREATE INDEX IF NOT EXISTS restricted_features_owner_idx
    ON restricted_features (owner_user_id);

ANALYZE restricted_features;
ANALYZE sessions;

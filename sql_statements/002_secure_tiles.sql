ALTER TABLE restricted_features
ADD COLUMN IF NOT EXISTS geom_3857 geometry(Geometry, 3857);

UPDATE restricted_features
SET geom_3857 = ST_Transform(geom, 3857)
WHERE geom_3857 IS NULL;

ALTER TABLE restricted_features
ALTER COLUMN geom_3857 SET NOT NULL;

CREATE INDEX IF NOT EXISTS restricted_features_geom_3857_gist_idx
    ON restricted_features
    USING GIST (geom_3857);

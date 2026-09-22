UPDATE restricted_features
SET geom_3857 =
    ST_Transform(geom::geometry, 3857)
WHERE geom_3857 IS NULL;

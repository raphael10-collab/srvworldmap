SELECT ST_AsMVT(
    features,
    'restricted',
    4096,
    'geom'
)
FROM (
    SELECT
        rf.id,
        rf.name,
        rf.properties,
        ST_AsMVTGeom(
            ST_Transform(rf.geom, 3857),
            ST_TileEnvelope(6, 33, 22),
            4096,
            64,
            true
        ) AS geom
    FROM restricted_features rf
    WHERE rf.owner_user_id = 1
) AS features;

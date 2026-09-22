CREATE SEQUENCE IF NOT EXISTS restricted_features_id_seq;

SELECT setval(
    'restricted_features_id_seq',
    COALESCE(MAX(id), 1),
    COUNT(*) > 0
)
FROM restricted_features;

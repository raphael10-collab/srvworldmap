ALTER TABLE restricted_features
ALTER COLUMN id
SET DEFAULT nextval('restricted_features_id_seq');

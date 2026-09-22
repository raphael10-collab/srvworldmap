CREATE OR REPLACE FUNCTION restricted_features_set_geom_3857()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.geom_3857 := ST_Transform(NEW.geom, 3857);
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS restricted_features_geom_3857_trigger
ON restricted_features;

CREATE TRIGGER restricted_features_geom_3857_trigger
BEFORE INSERT OR UPDATE OF geom
ON restricted_features
FOR EACH ROW
EXECUTE FUNCTION restricted_features_set_geom_3857();

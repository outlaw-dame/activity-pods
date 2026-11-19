-- Bootstrap a fresh disposable provider database as its owner.
BEGIN;
CREATE SCHEMA paper_private_auth;
REVOKE ALL ON SCHEMA paper_private_auth FROM PUBLIC;
CREATE ROLE paper_private_auth_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE TABLE paper_private_auth.accounts (
  id uuid PRIMARY KEY,
  data jsonb NOT NULL CHECK (jsonb_typeof(data) = 'object' AND octet_length(data::text) <= 65536
    AND data ? 'username' AND jsonb_typeof(data->'username') = 'string'
    AND length(data->>'username') BETWEEN 1 AND 128
    AND NOT (data ?| ARRAY['password','@id','@context','@type'])),
  CHECK (NOT (data ? 'signupReservationId' AND data ? 'webId') OR
    (jsonb_typeof(data->'webId')='string' AND data->>'webId'='https://paper.example.org/' || (data->>'username'))),
  CHECK (NOT (data ? 'signupReservationId') OR (jsonb_typeof(data->'signupReservationId')='string'
    AND data->>'signupReservationId' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'))
);
CREATE UNIQUE INDEX ON paper_private_auth.accounts ((data->>'username'));
CREATE UNIQUE INDEX ON paper_private_auth.accounts (lower(data->>'email'));
CREATE UNIQUE INDEX ON paper_private_auth.accounts ((data->>'webId'));
CREATE UNIQUE INDEX ON paper_private_auth.accounts ((data->>'signupReservationId'));
CREATE FUNCTION paper_private_auth.guard_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.data->'signupReservationId' IS DISTINCT FROM OLD.data->'signupReservationId'
    OR (OLD.data ? 'signupReservationId' AND
        (NEW.data->'username' IS DISTINCT FROM OLD.data->'username'
         OR (OLD.data ? 'webId' AND NEW.data->'webId' IS DISTINCT FROM OLD.data->'webId')
         OR (NEW.data ? 'webId' AND NEW.data->>'webId' <> 'https://paper.example.org/' || (OLD.data->>'username'))))
  THEN RAISE EXCEPTION 'Private account identity is immutable' USING ERRCODE='42501'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER guard_identity BEFORE UPDATE ON paper_private_auth.accounts
FOR EACH ROW EXECUTE FUNCTION paper_private_auth.guard_identity();
GRANT USAGE ON SCHEMA paper_private_auth TO paper_private_auth_runtime;
GRANT SELECT(id,data), INSERT(id,data), UPDATE(data), DELETE ON paper_private_auth.accounts TO paper_private_auth_runtime;
COMMIT;

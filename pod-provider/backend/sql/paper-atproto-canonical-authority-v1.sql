-- Native managed-ATProto authority, PostgreSQL 18.
-- Migration OWNER only. Jena/Solid RDF is a projection, never permission truth.
-- Do not run with Fuseki's database user or a general Moleculer login.
CREATE SCHEMA IF NOT EXISTS paper_atproto_authority;
REVOKE ALL ON SCHEMA paper_atproto_authority FROM PUBLIC;

CREATE TABLE IF NOT EXISTS paper_atproto_authority.identities (
  owner_webid text PRIMARY KEY CHECK (length(owner_webid) BETWEEN 8 AND 2048),
  did text NOT NULL UNIQUE CHECK (length(did) BETWEEN 20 AND 128),
  state text NOT NULL CHECK (state IN ('active','blocked')),
  managed boolean NOT NULL CHECK (managed=true),
  revision bigint NOT NULL CHECK (revision > 0),
  source_proof_sha256 bytea NOT NULL CHECK (octet_length(source_proof_sha256)=32),
  imported_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS paper_atproto_authority.consents (
  owner_webid text NOT NULL REFERENCES paper_atproto_authority.identities(owner_webid),
  app_uri text NOT NULL CHECK (length(app_uri) BETWEEN 8 AND 2048),
  grant_uri text NOT NULL CHECK (length(grant_uri) BETWEEN 8 AND 2048),
  state text NOT NULL CHECK (state IN ('active','blocked')),
  revision bigint NOT NULL CHECK (revision > 0),
  grant_proof_sha256 bytea NOT NULL CHECK (octet_length(grant_proof_sha256)=32),
  imported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(owner_webid,app_uri)
);
-- The (owner_webid,app_uri) PRIMARY KEY supplies the indexed lookup.\n-- Avoid duplicate secondary indexes on the hot revocation path.\n\n-- Only a migration-specific credential can INSERT the verified initial
-- identity and signed SAI grant snapshot. Runtime can NEVER regrant itself.
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_atproto_authority_reader') THEN
    CREATE ROLE paper_atproto_authority_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_atproto_authority_revoker') THEN
    CREATE ROLE paper_atproto_authority_revoker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_atproto_authority_importer') THEN
    CREATE ROLE paper_atproto_authority_importer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END $roles$;
REVOKE ALL ON ALL TABLES IN SCHEMA paper_atproto_authority FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_atproto_authority
  TO paper_atproto_authority_reader, paper_atproto_authority_revoker, paper_atproto_authority_importer;
GRANT SELECT ON paper_atproto_authority.identities, paper_atproto_authority.consents
  TO paper_atproto_authority_reader, paper_atproto_authority_revoker, paper_atproto_authority_importer;
GRANT INSERT ON paper_atproto_authority.identities, paper_atproto_authority.consents
  TO paper_atproto_authority_importer;

-- A function owner may mutate canonical records, but cannot be the revoker
-- LOGIN. Qualify the table, use pg_catalog search_path, revoke PUBLIC execute.
CREATE OR REPLACE FUNCTION paper_atproto_authority.block_consent(
    p_owner text, p_app text, p_grant text, p_expected bigint)
RETURNS TABLE (new_revision bigint, new_state text)
LANGUAGE SQL SECURITY DEFINER SET search_path=pg_catalog AS $function$
  UPDATE paper_atproto_authority.consents AS c
  SET state='blocked', revision=c.revision+1
  WHERE c.owner_webid=p_owner AND c.app_uri=p_app
    AND c.grant_uri=p_grant AND c.revision=p_expected
    AND c.state='active' AND c.revision<9223372036854775807
    AND EXISTS (
      SELECT 1 FROM paper_atproto_authority.identities AS i
      WHERE i.owner_webid=p_owner AND i.state='active' AND i.managed=true
    )
  RETURNING c.revision,c.state
$function$;
REVOKE ALL ON FUNCTION paper_atproto_authority.block_consent(text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.block_consent(text,text,text,bigint)
  TO paper_atproto_authority_revoker;

-- Production secrets: provision distinct LOGIN users externally and GRANT
-- them exactly reader / revoker / importer NOLOGIN roles. The ordinary
-- Fuseki/SPARQL login receives none. Readers cannot write. Revokers cannot
-- UPDATE/INSERT/DELETE tables. No tenant payload is logged by the function.

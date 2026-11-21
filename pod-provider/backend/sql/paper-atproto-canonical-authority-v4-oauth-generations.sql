-- NONACTIVATED: PostgreSQL 18 OAuth/PDS generation authority, after v1-v3.
-- Canonical SAI consent and WebID/DID remain in paper_atproto_authority.
-- Redis may store fast ephemeral grant/refresh state but may not override this
-- durable PG fence after snapshot rollback. PostgreSQL PITR itself still needs
-- an INDEPENDENT non-rewindable witness; see handoff. Do not release.
BEGIN;

CREATE TABLE paper_atproto_authority.oauth_generations (
  owner_webid text NOT NULL,
  app_uri text NOT NULL,
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 8 AND 2048 AND client_id LIKE 'https://%'),
  grant_id text NOT NULL UNIQUE CHECK (grant_id ~ '^[A-Za-z0-9_-]{32}$'),
  scope_sha256 bytea NOT NULL CHECK (octet_length(scope_sha256) = 32),
  revision bigint NOT NULL CHECK (revision > 0),
  sai_revision bigint NOT NULL CHECK (sai_revision > 0),
  state text NOT NULL CHECK (state IN ('active','blocked')),
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (owner_webid, client_id),
  FOREIGN KEY (owner_webid,app_uri)
    REFERENCES paper_atproto_authority.consents(owner_webid,app_uri)
);
REVOKE ALL ON TABLE paper_atproto_authority.oauth_generations FROM PUBLIC;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_oauth_epoch_issuer') THEN
    CREATE ROLE paper_oauth_epoch_issuer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_oauth_epoch_revoker') THEN
    CREATE ROLE paper_oauth_epoch_revoker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_oauth_epoch_reader') THEN
    CREATE ROLE paper_oauth_epoch_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_oauth_epoch_signer') THEN
    CREATE ROLE paper_oauth_epoch_signer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $roles$;
GRANT USAGE ON SCHEMA paper_atproto_authority TO
  paper_oauth_epoch_issuer,paper_oauth_epoch_revoker,paper_oauth_epoch_reader,paper_oauth_epoch_signer;

-- The owner-authenticated coordinator must use a dedicated restricted issuer.
-- This entry point is not currently connected to the owner-browser flow.
-- The canonical SAI row is locked: a concurrent native revocation cannot
-- acknowledge between the SAI check and the generation CAS.
CREATE FUNCTION paper_atproto_authority.issue_oauth_generation(
  p_owner text,p_app text,p_client text,p_grant text,
  p_scope_sha256 bytea,p_expected bigint,p_sai_revision bigint
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE c record; changed bigint;
BEGIN
  IF p_owner IS NULL OR p_app IS NULL OR p_client IS NULL OR
     p_grant IS NULL OR p_scope_sha256 IS NULL OR
     p_expected IS NULL OR p_sai_revision IS NULL OR
     p_expected < 0 OR p_expected = 9223372036854775807 OR
     p_sai_revision <= 0 OR
     length(p_owner) NOT BETWEEN 8 AND 2048 OR
     length(p_app) NOT BETWEEN 8 AND 2048 OR
     length(p_client) NOT BETWEEN 8 AND 2048 OR
     p_owner NOT LIKE 'https://%' OR p_app NOT LIKE 'https://%' OR
     p_client NOT LIKE 'https://%' OR
     p_grant !~ '^[A-Za-z0-9_-]{32}$' OR
     octet_length(p_scope_sha256)<>32 THEN RETURN 0; END IF;
  SELECT s.state,s.revision INTO c
    FROM paper_atproto_authority.consents s
    JOIN paper_atproto_authority.identities i ON i.owner_webid=s.owner_webid
   WHERE s.owner_webid=p_owner AND s.app_uri=p_app
     AND s.state='active' AND s.revision=p_sai_revision
     AND s.activation_operation IS NOT NULL
     AND s.activation_native_readback_at IS NOT NULL
     AND s.activation_request_sha256 IS NOT NULL
     AND i.state='active' AND i.managed=true FOR UPDATE OF s;
  IF NOT FOUND THEN RETURN 0; END IF;
  IF p_expected=0 THEN
    INSERT INTO paper_atproto_authority.oauth_generations
      (owner_webid,app_uri,client_id,grant_id,scope_sha256,revision,sai_revision,state)
    VALUES (p_owner,p_app,p_client,p_grant,p_scope_sha256,1,p_sai_revision,'active')
    ON CONFLICT DO NOTHING RETURNING revision INTO changed;
  ELSE
    UPDATE paper_atproto_authority.oauth_generations e SET
      grant_id=p_grant,scope_sha256=p_scope_sha256,
      revision=e.revision+1,sai_revision=p_sai_revision,
      state='active',changed_at=clock_timestamp()
    WHERE e.owner_webid=p_owner AND e.app_uri=p_app AND e.client_id=p_client
      AND e.revision=p_expected AND e.grant_id<>p_grant
      AND e.revision<9223372036854775807
    RETURNING e.revision INTO changed;
  END IF;
  RETURN coalesce(changed,0);
END $fn$;

-- The revoker must hold a separately authenticated owner-deletion context.
-- Replays lose the revision CAS; no resurrection from a blocked snapshot.
CREATE FUNCTION paper_atproto_authority.revoke_oauth_generation(
  p_owner text,p_client text,p_grant text,p_expected bigint
) RETURNS bigint
LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
  WITH changed AS (
    UPDATE paper_atproto_authority.oauth_generations e
      SET state='blocked',revision=e.revision+1,changed_at=clock_timestamp()
    WHERE e.owner_webid=p_owner AND e.client_id=p_client
      AND e.grant_id=p_grant AND e.revision=p_expected
      AND e.state='active' AND e.revision<9223372036854775807
    RETURNING e.revision
  ) SELECT coalesce((SELECT revision FROM changed),0::bigint)
$fn$;

-- Every credential admission must check this fresh PG predicate in addition
-- to Redis state and signed JWT/DPoP. No cached "true", read-replica lag, or
-- alternate Redis grant may bypass canonical revoked SAI or OAuth state.
CREATE FUNCTION paper_atproto_authority.verify_oauth_generation(
  p_owner text,p_app text,p_client text,p_grant text,
  p_scope_sha256 bytea,p_expected bigint
) RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
  SELECT EXISTS (
    SELECT 1
    FROM paper_atproto_authority.oauth_generations e
    JOIN paper_atproto_authority.consents s
      ON s.owner_webid=e.owner_webid AND s.app_uri=e.app_uri
    JOIN paper_atproto_authority.identities i
      ON i.owner_webid=e.owner_webid
    WHERE e.owner_webid=p_owner AND e.app_uri=p_app
      AND e.client_id=p_client AND e.grant_id=p_grant
      AND e.scope_sha256=p_scope_sha256
      AND e.revision=p_expected AND e.state='active'
      AND s.state='active' AND s.revision=e.sai_revision
      AND s.activation_operation IS NOT NULL
      AND s.activation_native_readback_at IS NOT NULL
      AND s.activation_request_sha256 IS NOT NULL
      AND i.state='active' AND i.managed=true
  )
$fn$;

-- Must be invoked INSIDE the exact same primary-PG transaction that commits
-- a signed PDS repository write. Row locks serialize OAuth/SAI revoke with
-- the commit; a mere preflight boolean read cannot provide that guarantee.
CREATE FUNCTION paper_atproto_authority.lock_oauth_generation_for_write(
  p_owner text,p_app text,p_client text,p_grant text,
  p_scope_sha256 bytea,p_expected bigint
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE allowed boolean DEFAULT false;
BEGIN
  SELECT true INTO allowed
  FROM paper_atproto_authority.oauth_generations e
  JOIN paper_atproto_authority.consents s
    ON s.owner_webid=e.owner_webid AND s.app_uri=e.app_uri
  JOIN paper_atproto_authority.identities i
    ON i.owner_webid=e.owner_webid
  WHERE e.owner_webid=p_owner AND e.app_uri=p_app
    AND e.client_id=p_client AND e.grant_id=p_grant
    AND e.scope_sha256=p_scope_sha256 AND e.revision=p_expected
    AND e.state='active' AND s.state='active'
    AND s.revision=e.sai_revision
    AND s.activation_operation IS NOT NULL
    AND s.activation_native_readback_at IS NOT NULL
    AND s.activation_request_sha256 IS NOT NULL
    AND i.state='active' AND i.managed=true
  FOR SHARE OF e,s,i;
  RETURN coalesce(allowed,false);
END $fn$;

REVOKE ALL ON FUNCTION paper_atproto_authority.issue_oauth_generation(
  text,text,text,text,bytea,bigint,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_authority.revoke_oauth_generation(
  text,text,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_authority.verify_oauth_generation(
  text,text,text,text,bytea,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_authority.lock_oauth_generation_for_write(
  text,text,text,text,bytea,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.issue_oauth_generation(
  text,text,text,text,bytea,bigint,bigint) TO paper_oauth_epoch_issuer;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.revoke_oauth_generation(
  text,text,text,bigint) TO paper_oauth_epoch_revoker;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.verify_oauth_generation(
  text,text,text,text,bytea,bigint) TO paper_oauth_epoch_reader;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.lock_oauth_generation_for_write(
  text,text,text,text,bytea,bigint) TO paper_oauth_epoch_signer;
-- No service LOGIN, provider, SemApps or Jena principal is granted these roles.
-- Deploy only after authenticated issuer/revoker, independent restore witness
-- and exact-hosted positive/negative acceptance are independently verified.
COMMIT;

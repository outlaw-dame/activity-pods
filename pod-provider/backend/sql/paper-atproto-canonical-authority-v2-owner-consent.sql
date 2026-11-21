-- NON-ACTIVATED PostgreSQL 18 consent activation candidate.
-- Apply after paper-atproto-canonical-authority-v1.sql.
-- Trusted account coordinator creates a PENDING owner consent *before* SAI
-- mutation. An independent native-SAI attestor activates it only after fresh
-- readback. Ordinary SemApps/Jena and the projection worker receive no rights.
-- Existing revoked grants are never reactivated by this initial-activation path.
BEGIN;
ALTER TABLE paper_atproto_authority.consents
  DROP CONSTRAINT consents_state_check;
ALTER TABLE paper_atproto_authority.consents
  ADD CONSTRAINT consents_state_check
    CHECK (state IN ('pending', 'active', 'blocked')),
  ADD COLUMN activation_operation uuid,
  ADD COLUMN activation_request_sha256 bytea,
  ADD COLUMN activation_native_readback_at timestamptz,
  ADD CONSTRAINT consent_activation_shape CHECK (
    (activation_operation IS NULL AND activation_request_sha256 IS NULL
      AND activation_native_readback_at IS NULL)
    OR (activation_operation IS NOT NULL
      AND activation_request_sha256 IS NOT NULL
      AND octet_length(activation_request_sha256)=32
      AND (state <> 'pending' OR activation_native_readback_at IS NULL))
  ),
  ADD CONSTRAINT pending_consent_requires_operation CHECK (
    state <> 'pending' OR activation_operation IS NOT NULL
  );

DO $roles$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname='paper_atproto_consent_issuer') THEN
    CREATE ROLE paper_atproto_consent_issuer NOLOGIN NOSUPERUSER
      NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
      WHERE rolname='paper_atproto_consent_attestor') THEN
    CREATE ROLE paper_atproto_consent_attestor NOLOGIN NOSUPERUSER
      NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $roles$;
GRANT USAGE ON SCHEMA paper_atproto_authority
  TO paper_atproto_consent_issuer,paper_atproto_consent_attestor;

-- Only a separately authenticated provider coordinator (not a browser or
-- ordinary SAI write) may reserve a pending *new-account* consent ceremony.
-- This SQL verifies the existing canonical managed identity. The coordinator
-- must independently authenticate owner/signup/operation outside this function.
CREATE FUNCTION paper_atproto_authority.begin_owner_consent(
  p_owner text,p_did text,p_app text,p_operation uuid,p_request_sha256 bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
DECLARE new_row integer;
BEGIN
  IF p_owner IS NULL OR p_did IS NULL OR p_app IS NULL OR
      p_operation IS NULL OR p_request_sha256 IS NULL OR
      octet_length(p_request_sha256)<>32 OR
      length(p_owner) NOT BETWEEN 8 AND 2048 OR
      length(p_app) NOT BETWEEN 8 AND 2048 OR
      p_owner NOT LIKE 'https://%' OR p_app NOT LIKE 'https://%' OR
      p_did !~ '^did:plc:[a-z2-7]{24}$'
  THEN RETURN false; END IF;
  INSERT INTO paper_atproto_authority.consents AS c
    (owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256,
      activation_operation,activation_request_sha256)
  SELECT p_owner,p_app,
    p_owner||'/.private/pending-consent/'||p_operation::text,
    'pending',1,p_request_sha256,p_operation,p_request_sha256
  FROM paper_atproto_authority.identities AS i
  WHERE i.owner_webid=p_owner AND i.did=p_did AND i.state='active'
    AND i.managed=true
  ON CONFLICT (owner_webid,app_uri) DO NOTHING;
  GET DIAGNOSTICS new_row=ROW_COUNT;
  IF new_row=1 THEN RETURN true; END IF;
  -- Lost acknowledgement is idempotent *only for the identical* in-flight
  -- operation and digest. A blocked/active row can never be opened by replay.
  RETURN EXISTS (SELECT 1 FROM paper_atproto_authority.consents AS c
    JOIN paper_atproto_authority.identities AS i
      ON i.owner_webid=c.owner_webid
    WHERE c.owner_webid=p_owner AND c.app_uri=p_app
      AND c.state='pending' AND c.revision=1
      AND c.activation_operation=p_operation
      AND c.activation_request_sha256=p_request_sha256
      AND i.did=p_did AND i.state='active' AND i.managed=true);
END $function$;

-- Independent reader/attestor credential only. It must have read native
-- registration and grant contents from protected Jena, checked exact owner,
-- application, need group and required rights, and hashed that typed evidence.
-- A 2xx Jena write or application boolean is never sufficient for activation.
CREATE FUNCTION paper_atproto_authority.attest_owner_consent(
  p_owner text,p_did text,p_app text,p_operation uuid,
  p_grant text,p_native_readback_sha256 bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
DECLARE changed integer;
BEGIN
  IF p_owner IS NULL OR p_did IS NULL OR p_app IS NULL OR
     p_operation IS NULL OR p_grant IS NULL OR
     p_native_readback_sha256 IS NULL OR
     octet_length(p_native_readback_sha256)<>32 OR
     length(p_grant) NOT BETWEEN 8 AND 2048 OR
     p_grant NOT LIKE 'https://%' OR
     p_owner NOT LIKE 'https://%' OR p_app NOT LIKE 'https://%' OR
     -- Exact owner Pod, not a third-party or user-supplied external grant.
     left(p_grant,length(p_owner)+1)<>p_owner||'/' OR
     p_did !~ '^did:plc:[a-z2-7]{24}$'
  THEN RETURN false; END IF;
  UPDATE paper_atproto_authority.consents AS c
    SET state='active',grant_uri=p_grant,
      grant_proof_sha256=p_native_readback_sha256,
      activation_native_readback_at=clock_timestamp()
  WHERE c.owner_webid=p_owner AND c.app_uri=p_app
    AND c.state='pending' AND c.revision=1
    AND c.activation_operation=p_operation
    AND EXISTS (SELECT 1 FROM paper_atproto_authority.identities AS i
      WHERE i.owner_webid=p_owner AND i.did=p_did
        AND i.state='active' AND i.managed=true);
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed=1 THEN RETURN true; END IF;
  -- Readback after a lost ACK is permitted only at the original revision.
  -- Revocation increments revision and permanently rules out resurrection.
  RETURN EXISTS (SELECT 1 FROM paper_atproto_authority.consents AS c
    JOIN paper_atproto_authority.identities AS i
      ON i.owner_webid=c.owner_webid
    WHERE c.owner_webid=p_owner AND c.app_uri=p_app
      AND c.state='active' AND c.revision=1
      AND c.activation_operation=p_operation
      AND c.grant_uri=p_grant
      AND c.grant_proof_sha256=p_native_readback_sha256
      AND i.did=p_did AND i.state='active' AND i.managed=true);
END $function$;


-- Recheck a just-attested consent from the independent reader login. The
-- confirmation is read-only and requires the identical operation/readback.
-- It does not create a cross-store transaction or supersede operation-time
-- authorization. A revocation acknowledged before this query must deny.
CREATE FUNCTION paper_atproto_authority.confirm_owner_consent(
  p_owner text,p_did text,p_app text,p_operation uuid,
  p_grant text,p_native_readback_sha256 bytea
) RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $function$
  SELECT EXISTS (
    SELECT 1 FROM paper_atproto_authority.consents c
    JOIN paper_atproto_authority.identities i
      ON i.owner_webid=c.owner_webid
    WHERE c.owner_webid=p_owner AND c.app_uri=p_app
      AND c.state='active' AND c.revision=1
      AND c.activation_operation=p_operation
      AND c.grant_uri=p_grant
      AND c.grant_proof_sha256=p_native_readback_sha256
      AND c.activation_native_readback_at IS NOT NULL
      AND i.did=p_did AND i.state='active' AND i.managed=true
  )
$function$;
REVOKE ALL ON FUNCTION paper_atproto_authority.confirm_owner_consent(
  text,text,text,uuid,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.confirm_owner_consent(
  text,text,text,uuid,text,bytea) TO paper_atproto_consent_attestor;

-- A native owner DELETE can arrive while first consent is still pending.
-- Block it durably so an already-started attestor cannot activate a stale
-- readback. The very same row lock serializes concurrent revoke/attest.
CREATE OR REPLACE FUNCTION paper_atproto_authority.block_consent(
    p_owner text,p_app text,p_grant text,p_expected bigint)
RETURNS TABLE (new_revision bigint,new_state text)
LANGUAGE SQL SECURITY DEFINER SET search_path=pg_catalog AS $function$
  UPDATE paper_atproto_authority.consents AS c
  SET state='blocked',revision=c.revision+1
  WHERE c.owner_webid=p_owner AND c.app_uri=p_app
    AND c.grant_uri=p_grant AND c.revision=p_expected
    AND c.state IN ('pending','active')
    AND c.revision<9223372036854775807
    AND EXISTS (
      SELECT 1 FROM paper_atproto_authority.identities AS i
      WHERE i.owner_webid=p_owner AND i.state='active' AND i.managed=true)
  RETURNING c.revision,c.state
$function$;
REVOKE ALL ON FUNCTION paper_atproto_authority.begin_owner_consent(
  text,text,text,uuid,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_authority.attest_owner_consent(
  text,text,text,uuid,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.begin_owner_consent(
  text,text,text,uuid,bytea) TO paper_atproto_consent_issuer;
GRANT EXECUTE ON FUNCTION paper_atproto_authority.attest_owner_consent(
  text,text,text,uuid,text,bytea) TO paper_atproto_consent_attestor;
COMMIT;

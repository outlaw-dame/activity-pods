-- NONACTIVATED restricted PostgreSQL 18 post-enrollment owner admission.
-- Apply ONLY after credential epoch v1/v2 and canonical SAI v1/v2,
-- OAuth generation v4; disposable proof first. No production migration.
--
-- This function cannot authenticate a browser, register a new session,
-- grant consent, revoke a token or override independently immutable
-- credential/witness heads. It exposes the exact current PG join needed
-- by a separately verified owner-bound browser and native-SAI readback.
-- Never treat a user-supplied WebID here as authentication.
BEGIN;
DO $roles$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
   WHERE rolname='paper_oauth_post_enrollment_reader') THEN
  CREATE ROLE paper_oauth_post_enrollment_reader NOLOGIN
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
END $roles$;
GRANT USAGE ON SCHEMA paper_atproto_authority,
 paper_credential_epoch TO paper_oauth_post_enrollment_reader;
-- Credential schema USAGE is necessary for PostgreSQL's named-regclass
-- has_table_privilege(...) admission audit. It grants NO table SELECT,
-- no CREATE, no direct credential read and no ability to change epochs.

-- No separate account/profile store and no duplicate grant authority.
-- The original ActivityPods WebID, canonical managed DID, credential
-- generation, native-attested SAI row and OAuth generation must ALL agree.
CREATE FUNCTION paper_atproto_authority.current_post_enrollment_owner_grant(
 p_owner text,p_client text
) RETURNS TABLE(
 owner_webid text,client_id text,app_uri text,
 grant_id text,scope_sha256 text,oauth_revision text,
 sai_revision text,credential_epoch text
)
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $read$
 SELECT e.owner_webid,e.client_id,e.app_uri,e.grant_id,
        encode(e.scope_sha256,'hex'),e.revision::text,
        e.sai_revision::text,ce.epoch::text
 FROM paper_atproto_authority.oauth_generations e
 JOIN paper_atproto_authority.consents s
  ON s.owner_webid=e.owner_webid AND s.app_uri=e.app_uri
 JOIN paper_atproto_authority.identities i
  ON i.owner_webid=e.owner_webid
 JOIN paper_credential_epoch.owners ce
  ON ce.webid=e.owner_webid
 WHERE e.owner_webid=p_owner AND e.client_id=p_client
   AND e.state='active'
   AND s.state='active' AND s.revision=e.sai_revision
   AND s.activation_operation IS NOT NULL
   AND s.activation_request_sha256 IS NOT NULL
   AND s.activation_native_readback_at IS NOT NULL
   AND i.state='active' AND i.managed=true
   AND ce.mode='unified' AND ce.state='active'
   AND ce.operation_id IS NULL AND ce.next_epoch IS NULL
   AND ce.epoch>0
$read$;

REVOKE ALL ON FUNCTION
 paper_atproto_authority.current_post_enrollment_owner_grant(text,text)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
 paper_atproto_authority.current_post_enrollment_owner_grant(text,text)
 TO paper_oauth_post_enrollment_reader;
-- Role is read-only; no LOGIN is created. Direct identity/SAI/credential
-- table access and issuer/revoker privileges are never granted.
COMMIT;

-- NONACTIVATED disposable PostgreSQL 18 cross-store ACK authority v2.
-- Separate, read-only attestor is the *only* actor able to record verified
-- remote protected RDF evidence. The projection SQL login cannot attest or
-- bypass this receipt. No production migration or signup activation.
BEGIN;
DO $role$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
   WHERE rolname='paper_atproto_rdf_attestor') THEN
  CREATE ROLE paper_atproto_rdf_attestor NOLOGIN NOSUPERUSER NOCREATEDB
    NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
END $role$;
GRANT paper_atproto_authority_reader TO paper_atproto_rdf_attestor
 WITH INHERIT TRUE, SET FALSE, ADMIN FALSE;
GRANT USAGE ON SCHEMA paper_atproto_repo_proof TO paper_atproto_rdf_attestor;
GRANT SELECT ON paper_atproto_repo_proof.repos,
 paper_atproto_repo_proof.rdf_projection_jobs TO paper_atproto_rdf_attestor;

-- One receipt per managed account, not one row per retry or generation.
-- Epoch strictly advances; no per-Pod scan, broker, or unbounded receipt queue.
CREATE TABLE paper_atproto_repo_proof.rdf_attestations (
 account_id text NOT NULL,
 did text NOT NULL,
 lease_owner uuid NOT NULL,
 lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
 head_cid text NOT NULL,
 root_cid text NOT NULL,
 rev text NOT NULL,
 generation bigint NOT NULL CHECK (generation > 0),
 app_uri text NOT NULL,
 grant_uri text NOT NULL,
 consent_revision bigint NOT NULL CHECK (consent_revision > 0),
 rdf_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(rdf_sha256)=32),
 observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
 PRIMARY KEY(account_id,did)
);
REVOKE ALL ON paper_atproto_repo_proof.rdf_attestations FROM PUBLIC;

CREATE FUNCTION paper_atproto_repo_proof.attest_protected_rdf(
 p_owner text,p_did text,p_lease uuid,p_epoch bigint,
 p_head text,p_root text,p_rev text,p_generation bigint,
 p_app text,p_grant text,p_revision bigint,p_rdf_sha256 bytea)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
DECLARE admitted boolean;
BEGIN
 IF p_lease IS NULL OR p_epoch<1 OR p_generation<1 OR p_revision<1 OR
    p_rdf_sha256 IS NULL OR pg_catalog.octet_length(p_rdf_sha256)<>32 OR
    p_owner IS NULL OR p_did IS NULL OR p_head IS NULL OR p_root IS NULL OR
    p_rev IS NULL OR p_app IS NULL OR p_grant IS NULL THEN
  RETURN false;
 END IF;
 -- Same transaction locks active canonical SAI to serialize revocation.
 PERFORM 1 FROM paper_atproto_authority.consents AS c
 JOIN paper_atproto_authority.identities AS i ON i.owner_webid=c.owner_webid
 WHERE c.owner_webid=p_owner AND c.app_uri=p_app AND c.grant_uri=p_grant
   AND c.revision=p_revision AND c.state='active' AND i.did=p_did
   AND i.state='active' AND i.managed=true FOR SHARE OF c,i;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT true INTO admitted
 FROM paper_atproto_repo_proof.rdf_projection_jobs AS j
 JOIN paper_atproto_repo_proof.repos AS r
   ON r.account_id=j.account_id AND r.did=j.did
 WHERE j.account_id=p_owner AND j.did=p_did
   AND j.state='leased' AND j.lease_owner=p_lease
   AND j.lease_epoch=p_epoch AND j.lease_until>pg_catalog.clock_timestamp()
   AND j.head_cid=p_head AND j.root_cid=p_root AND j.rev=p_rev
   AND j.generation=p_generation
   AND r.head_cid=j.head_cid AND r.root_cid=j.root_cid
   AND r.rev=j.rev AND r.generation=j.generation;
 IF admitted IS DISTINCT FROM true THEN RETURN false; END IF;
 INSERT INTO paper_atproto_repo_proof.rdf_attestations AS a
 (account_id,did,lease_owner,lease_epoch,head_cid,root_cid,rev,
  generation,app_uri,grant_uri,consent_revision,rdf_sha256)
 VALUES(p_owner,p_did,p_lease,p_epoch,p_head,p_root,p_rev,
  p_generation,p_app,p_grant,p_revision,p_rdf_sha256)
 ON CONFLICT(account_id,did) DO UPDATE SET
 lease_owner=EXCLUDED.lease_owner,lease_epoch=EXCLUDED.lease_epoch,
 head_cid=EXCLUDED.head_cid,root_cid=EXCLUDED.root_cid,
 rev=EXCLUDED.rev,generation=EXCLUDED.generation,
 app_uri=EXCLUDED.app_uri,grant_uri=EXCLUDED.grant_uri,
 consent_revision=EXCLUDED.consent_revision,
 rdf_sha256=EXCLUDED.rdf_sha256,observed_at=pg_catalog.clock_timestamp()
 WHERE a.lease_epoch<EXCLUDED.lease_epoch;
 -- A duplicate *identical* receipt is idempotent (crash/replay).
 RETURN EXISTS(
  SELECT 1 FROM paper_atproto_repo_proof.rdf_attestations AS a
  WHERE a.account_id=p_owner AND a.did=p_did
    AND a.lease_owner=p_lease AND a.lease_epoch=p_epoch
    AND a.head_cid=p_head AND a.root_cid=p_root AND a.rev=p_rev
    AND a.generation=p_generation AND a.app_uri=p_app
    AND a.grant_uri=p_grant AND a.consent_revision=p_revision
    AND a.rdf_sha256=p_rdf_sha256
    AND a.observed_at>=pg_catalog.clock_timestamp()-INTERVAL '60 seconds');
END $function$;

-- Never let the projection-worker credential call legacy unsupervised ACK
-- after this migration. Only one explicit attested ACK route remains.
REVOKE EXECUTE ON FUNCTION paper_atproto_repo_proof.ack_verified_projection(
 text,text,uuid,bigint,text,text,text,bigint,text,text,bigint)
 FROM paper_atproto_projection_worker;

CREATE FUNCTION paper_atproto_repo_proof.ack_attested_projection(
 p_owner text,p_did text,p_lease uuid,p_epoch bigint,
 p_head text,p_root text,p_rev text,p_generation bigint,
 p_app text,p_grant text,p_revision bigint)
RETURNS TABLE(lease_epoch bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
BEGIN
 IF p_lease IS NULL OR p_epoch<1 OR p_generation<1 OR p_revision<1
 THEN RETURN; END IF;
 PERFORM 1 FROM paper_atproto_authority.consents AS c
 JOIN paper_atproto_authority.identities AS i ON i.owner_webid=c.owner_webid
 WHERE c.owner_webid=p_owner AND c.app_uri=p_app AND c.grant_uri=p_grant
   AND c.revision=p_revision AND c.state='active' AND i.did=p_did
   AND i.state='active' AND i.managed=true FOR SHARE OF c,i;
 IF NOT FOUND THEN RETURN; END IF;
 RETURN QUERY UPDATE paper_atproto_repo_proof.rdf_projection_jobs AS j
 SET state='applied',lease_owner=NULL,lease_until=NULL,
     applied_at=pg_catalog.clock_timestamp(),last_error_code=NULL,
     updated_at=pg_catalog.clock_timestamp()
 WHERE j.account_id=p_owner AND j.did=p_did
   AND j.lease_owner=p_lease AND j.lease_epoch=p_epoch
   AND j.state='leased' AND j.lease_until>pg_catalog.clock_timestamp()
   AND j.head_cid=p_head AND j.root_cid=p_root AND j.rev=p_rev
   AND j.generation=p_generation
   AND EXISTS (
     SELECT 1 FROM paper_atproto_repo_proof.repos AS r
     WHERE r.account_id=j.account_id AND r.did=j.did
       AND r.head_cid=j.head_cid AND r.root_cid=j.root_cid
       AND r.rev=j.rev AND r.generation=j.generation)
   AND EXISTS (
     SELECT 1 FROM paper_atproto_repo_proof.rdf_attestations AS a
     WHERE a.account_id=j.account_id AND a.did=j.did
       AND a.lease_owner=p_lease AND a.lease_epoch=p_epoch
       AND a.head_cid=j.head_cid AND a.root_cid=j.root_cid
       AND a.rev=j.rev AND a.generation=j.generation
       AND a.app_uri=p_app AND a.grant_uri=p_grant
       AND a.consent_revision=p_revision
       AND a.observed_at>=pg_catalog.clock_timestamp()-INTERVAL '60 seconds'
       AND a.observed_at<=pg_catalog.clock_timestamp()
       AND pg_catalog.octet_length(a.rdf_sha256)=32)
 RETURNING j.lease_epoch;
END $function$;

REVOKE ALL ON FUNCTION paper_atproto_repo_proof.attest_protected_rdf(
 text,text,uuid,bigint,text,text,text,bigint,text,text,bigint,bytea)
 FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_repo_proof.ack_attested_projection(
 text,text,uuid,bigint,text,text,text,bigint,text,text,bigint)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_repo_proof.attest_protected_rdf(
 text,text,uuid,bigint,text,text,text,bigint,text,text,bigint,bytea)
 TO paper_atproto_rdf_attestor;
GRANT EXECUTE ON FUNCTION paper_atproto_repo_proof.ack_attested_projection(
 text,text,uuid,bigint,text,text,text,bigint,text,text,bigint)
 TO paper_atproto_projection_worker;
COMMIT;

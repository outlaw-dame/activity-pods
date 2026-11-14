-- NONACTIVATED, DISPOSABLE PostgreSQL 18 projection-worker SQL boundary.
-- Apply after schema.sql, single-record-mutation.sql and canonical authority.
-- Not a production migration. Ordinary Jena/LDP and signed repo workers
-- receive no permission to claim/acknowledge protected projection work.
BEGIN;
DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname='paper_atproto_projection_worker') THEN
    CREATE ROLE paper_atproto_projection_worker NOLOGIN NOSUPERUSER
      NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $role$;
GRANT paper_atproto_authority_reader TO paper_atproto_projection_worker
  WITH INHERIT TRUE, SET FALSE, ADMIN FALSE;
GRANT USAGE ON SCHEMA paper_atproto_repo_proof TO paper_atproto_projection_worker;
GRANT SELECT ON paper_atproto_repo_proof.repos,
  paper_atproto_repo_proof.blocks,
  paper_atproto_repo_proof.native_event_outbox,
  paper_atproto_repo_proof.record_mutations,
  paper_atproto_repo_proof.rdf_projection_jobs
  TO paper_atproto_projection_worker;

-- Every transition is an indexed point operation. Functions own the UPDATE
-- privilege: projection workers cannot issue arbitrary SQL state changes.
-- Canonical SAI is checked inside the same statement/transaction, holding
-- FOR SHARE rows so revocation cannot pass before the transition commits.
-- Never keep a PG transaction open while performing network Jena writes.
CREATE OR REPLACE FUNCTION paper_atproto_repo_proof.claim_verified_projection(
 p_owner text,p_did text,p_lease uuid,p_seconds integer,p_attempts integer,
 p_app text,p_grant text,p_revision bigint)
RETURNS TABLE(account_id text,did text,head_cid text,root_cid text,
 rev text,generation bigint,lease_owner uuid,lease_epoch bigint,
 attempt_count integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
BEGIN
 IF p_lease IS NULL OR p_seconds NOT BETWEEN 1 AND 300
    OR p_attempts NOT BETWEEN 1 AND 20 OR p_revision<1 THEN RETURN; END IF;
 PERFORM 1 FROM paper_atproto_authority.consents AS c
 JOIN paper_atproto_authority.identities AS i ON i.owner_webid=c.owner_webid
 WHERE c.owner_webid=p_owner AND c.app_uri=p_app AND c.grant_uri=p_grant
   AND c.revision=p_revision AND c.state='active' AND i.did=p_did
   AND i.state='active' AND i.managed=true FOR SHARE OF c,i;
 IF NOT FOUND THEN RETURN; END IF;
 RETURN QUERY UPDATE paper_atproto_repo_proof.rdf_projection_jobs AS j
 SET state='leased',lease_owner=p_lease,lease_epoch=j.lease_epoch+1,
 lease_until=pg_catalog.clock_timestamp()+
   (p_seconds*INTERVAL '1 second'),
 attempt_count=j.attempt_count+1,last_error_code=NULL,
 updated_at=pg_catalog.clock_timestamp()
 WHERE j.account_id=p_owner AND j.did=p_did
  AND j.lease_epoch<9223372036854775807
  AND j.attempt_count<p_attempts
  AND ((j.state='pending' AND j.next_attempt_at<=pg_catalog.clock_timestamp())
    OR (j.state='leased' AND j.lease_until<=pg_catalog.clock_timestamp()))
  AND EXISTS (
    SELECT 1 FROM paper_atproto_repo_proof.repos AS r
    WHERE r.account_id=j.account_id AND r.did=j.did
     AND r.head_cid=j.head_cid AND r.root_cid=j.root_cid
     AND r.rev=j.rev AND r.generation=j.generation)
 RETURNING j.account_id,j.did,j.head_cid,j.root_cid,j.rev,
   j.generation,j.lease_owner,j.lease_epoch,j.attempt_count;
END $function$;

-- A signed lease plus an independently read-backed Jena CAS is required at
-- the TRUSTED service layer before this function is called. SQL cannot
-- independently attest remote RDF contents. Production release remains
-- closed until the separate Jena storage-credential boundary is proven.
CREATE OR REPLACE FUNCTION paper_atproto_repo_proof.ack_verified_projection(
 p_owner text,p_did text,p_lease uuid,p_epoch bigint,
 p_commit text,p_root text,p_rev text,p_generation bigint,
 p_app text,p_grant text,p_revision bigint)
RETURNS TABLE(lease_epoch bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
BEGIN
 IF p_lease IS NULL OR p_epoch<1 OR p_generation<1 OR p_revision<1 THEN RETURN; END IF;
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
  AND j.head_cid=p_commit AND j.root_cid=p_root
  AND j.rev=p_rev AND j.generation=p_generation
  AND EXISTS (
    SELECT 1 FROM paper_atproto_repo_proof.repos AS r
    WHERE r.account_id=j.account_id AND r.did=j.did
     AND r.head_cid=j.head_cid AND r.root_cid=j.root_cid
     AND r.rev=j.rev AND r.generation=j.generation)
 RETURNING j.lease_epoch;
END $function$;

CREATE OR REPLACE FUNCTION paper_atproto_repo_proof.release_failed_projection(
 p_owner text,p_did text,p_lease uuid,p_epoch bigint,
 p_state text,p_delay double precision,p_code text)
RETURNS TABLE(lease_epoch bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
BEGIN
 IF p_lease IS NULL OR p_epoch<1 OR p_state NOT IN ('pending','blocked')
    OR p_delay<0 OR p_delay>300 OR p_delay IS NULL
    OR p_code IS NULL OR p_code !~ '^[A-Z][A-Z0-9_]{2,79}$'
 THEN RETURN; END IF;
 RETURN QUERY UPDATE paper_atproto_repo_proof.rdf_projection_jobs AS j
 SET state=p_state,lease_owner=NULL,lease_until=NULL,
  next_attempt_at=pg_catalog.clock_timestamp()+
    (p_delay*INTERVAL '1 second'),
  last_error_code=p_code,updated_at=pg_catalog.clock_timestamp()
 WHERE j.account_id=p_owner AND j.did=p_did AND j.lease_owner=p_lease
  AND j.lease_epoch=p_epoch AND j.state='leased'
  AND j.lease_until>pg_catalog.clock_timestamp()
 RETURNING j.lease_epoch;
END $function$;

CREATE OR REPLACE FUNCTION paper_atproto_repo_proof.block_exhausted_projection(
 p_owner text,p_did text,p_attempts integer)
RETURNS bigint
LANGUAGE SQL VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp
AS $function$
 WITH changed AS (
  UPDATE paper_atproto_repo_proof.rdf_projection_jobs AS j
  SET state='blocked',lease_owner=NULL,lease_until=NULL,
   last_error_code='PROJECTION_RETRY_EXHAUSTED',
   updated_at=pg_catalog.clock_timestamp()
  WHERE j.account_id=p_owner AND j.did=p_did
   AND p_attempts BETWEEN 1 AND 20 AND j.attempt_count>=p_attempts
   AND (j.state='pending' OR
     (j.state='leased' AND j.lease_until<=pg_catalog.clock_timestamp()))
  RETURNING 1
 ) SELECT count(*)::bigint FROM changed
$function$;

REVOKE ALL ON FUNCTION paper_atproto_repo_proof.claim_verified_projection(
 text,text,uuid,integer,integer,text,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_repo_proof.ack_verified_projection(
 text,text,uuid,bigint,text,text,text,bigint,text,text,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_repo_proof.release_failed_projection(
 text,text,uuid,bigint,text,double precision,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_atproto_repo_proof.block_exhausted_projection(
 text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_atproto_repo_proof.claim_verified_projection(
 text,text,uuid,integer,integer,text,text,bigint) TO paper_atproto_projection_worker;
GRANT EXECUTE ON FUNCTION paper_atproto_repo_proof.ack_verified_projection(
 text,text,uuid,bigint,text,text,text,bigint,text,text,bigint) TO paper_atproto_projection_worker;
GRANT EXECUTE ON FUNCTION paper_atproto_repo_proof.release_failed_projection(
 text,text,uuid,bigint,text,double precision,text) TO paper_atproto_projection_worker;
GRANT EXECUTE ON FUNCTION paper_atproto_repo_proof.block_exhausted_projection(
 text,text,integer) TO paper_atproto_projection_worker;
COMMIT;

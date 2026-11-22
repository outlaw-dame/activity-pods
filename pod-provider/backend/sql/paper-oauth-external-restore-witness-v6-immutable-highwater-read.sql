-- NONACTIVATED independent PG18 witness CLUSTER ONLY, after v1..v5.
-- A restored witness PG and restored canonical PG/Redis can agree on an OLD,
-- still-valid grant. A separate immutable archive must provide its LATEST
-- independently read-back high-water epoch on EVERY OAuth admission.
-- This SELECT merely exposes the exact sealed witness snapshot: it is NOT
-- an independently immutable archive, anti-rollback authority, or proof of
-- completed physical PostgreSQL WAL/PITR recovery.
BEGIN;
CREATE FUNCTION paper_oauth_restore_witness.active_checkpoint(
 p_owner text,p_client text,p_grant_hash bytea,p_revision bigint
) RETURNS TABLE(revision text,event_sha256 text,operation_id text)
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT c.revision::text,encode(c.event_sha256,'hex'),
  c.operation_id::text
 FROM paper_oauth_restore_witness.current_epochs c
 JOIN paper_oauth_restore_witness.events e
  ON e.owner_webid=c.owner_webid AND e.client_id=c.client_id
  AND e.revision=c.revision AND e.operation_id=c.operation_id
  AND e.event_sha256=c.event_sha256 AND e.state=c.state
  AND e.grant_sha256=c.grant_sha256
 WHERE c.owner_webid=p_owner AND c.client_id=p_client
  AND c.revision=p_revision AND c.grant_sha256=p_grant_hash
  AND c.state='active' AND c.sealed=true AND e.sealed_at IS NOT NULL;
$fn$;
REVOKE ALL ON FUNCTION
 paper_oauth_restore_witness.active_checkpoint(text,text,bytea,bigint)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
 paper_oauth_restore_witness.active_checkpoint(text,text,bytea,bigint)
 TO paper_oauth_witness_reader;
COMMIT;

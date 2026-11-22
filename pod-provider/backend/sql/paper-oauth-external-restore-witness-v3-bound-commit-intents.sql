-- NONACTIVATED independent PostgreSQL 18 witness CLUSTER ONLY.
-- Apply AFTER witness v1 + v2, BEFORE any live signed-write intents.
-- A witnessed operation must name the EXACT expected previous AND proposed
-- signed repository commit CIDs. Otherwise an unrelated signed commit could
-- be misattributed to a lost/aborted witness operation.
BEGIN;
DO $guard$ BEGIN
 IF EXISTS(SELECT 1 FROM paper_oauth_restore_witness.signed_write_intents)
 THEN
   RAISE EXCEPTION USING ERRCODE='P0001',
    MESSAGE='Existing signed intents require manual immutable-head reconciliation before v3';
 END IF;
END $guard$;

ALTER TABLE paper_oauth_restore_witness.signed_write_intents
 ADD COLUMN proposed_head_cid text NOT NULL
  CHECK(proposed_head_cid ~ '^bafyre[a-z2-7]{53}$'
    AND proposed_head_cid<>expected_head_cid);

-- Drop the old six-argument writer entry point; leaving it executable would
-- allow clients to reserve an unbound intent. The separate writer LOGIN
-- still has NO SELECT/UPDATE/DELETE privilege on the intent table.
DROP FUNCTION paper_oauth_restore_witness.reserve_signed_write(
 text,text,bytea,bigint,uuid,text);

CREATE FUNCTION paper_oauth_restore_witness.reserve_signed_write(
 p_owner text,p_client text,p_grant_hash bytea,p_revision bigint,
 p_operation uuid,p_expected_head text,p_proposed_head text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE allowed boolean; pending_count bigint; inserted uuid;
BEGIN
 IF length(p_owner) NOT BETWEEN 8 AND 2048 OR p_owner NOT LIKE 'https://%'
 OR length(p_client) NOT BETWEEN 8 AND 2048 OR p_client NOT LIKE 'https://%'
 OR octet_length(p_grant_hash)<>32 OR p_revision<1
 OR p_expected_head !~ '^bafyre[a-z2-7]{53}$'
 OR p_proposed_head !~ '^bafyre[a-z2-7]{53}$'
 OR p_proposed_head=p_expected_head
 THEN RETURN false; END IF;
 -- Serialize same-key reservations before count/insert so a concurrent
 -- signer cannot break the bounded in-flight intent limit. The epoch's
 -- FOR SHARE lock also serializes with the independent revoker.
 PERFORM pg_advisory_xact_lock(hashtextextended(
  'paper:witness:writer:v1:'||
    length(p_owner)::text||':'||p_owner||':'||p_client,0));
 SELECT true INTO allowed
 FROM paper_oauth_restore_witness.current_epochs c
 JOIN paper_oauth_restore_witness.events e ON
  e.owner_webid=c.owner_webid AND e.client_id=c.client_id
  AND e.revision=c.revision AND e.event_sha256=c.event_sha256
 WHERE c.owner_webid=p_owner AND c.client_id=p_client
  AND c.revision=p_revision AND c.state='active'
  AND c.sealed=true AND e.sealed_at IS NOT NULL
  AND c.grant_sha256=p_grant_hash
 FOR SHARE OF c;
 IF allowed IS DISTINCT FROM true THEN RETURN false; END IF;
 SELECT count(*) INTO pending_count
 FROM paper_oauth_restore_witness.signed_write_intents i
 WHERE i.owner_webid=p_owner AND i.client_id=p_client
  AND i.state='pending';
 IF pending_count>=8 THEN RETURN false; END IF;
 INSERT INTO paper_oauth_restore_witness.signed_write_intents
  (operation_id,owner_webid,client_id,grant_sha256,revision,
   expected_head_cid,proposed_head_cid)
 VALUES(p_operation,p_owner,p_client,p_grant_hash,p_revision,
  p_expected_head,p_proposed_head)
 ON CONFLICT(operation_id) DO NOTHING
 RETURNING operation_id INTO inserted;
 RETURN COALESCE(inserted=p_operation,false);
END $fn$;

-- Exact proposed CID match is a NECESSARY condition, but only an
-- independently credentialed signer-key/CAR/PG-outbox verifier can attest
-- that the commit actually exists. A naked client-provided CID is never
-- sufficient evidence to call the restricted reconciler entry point.
CREATE OR REPLACE FUNCTION paper_oauth_restore_witness.resolve_signed_write(
 p_operation uuid,p_owner text,p_client text,p_revision bigint,
 p_result text,p_commit_head text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE updated uuid;
BEGIN
 IF p_operation IS NULL OR p_owner IS NULL OR p_client IS NULL OR
    p_revision IS NULL OR p_result IS NULL OR p_revision<1 OR
    p_result NOT IN ('committed','aborted') OR
    (p_result='committed' AND
     (p_commit_head IS NULL OR p_commit_head !~ '^bafyre[a-z2-7]{53}$')) OR
    (p_result='aborted' AND p_commit_head IS NOT NULL)
 THEN RETURN false; END IF;
 PERFORM 1 FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=p_owner AND c.client_id=p_client
  AND c.revision=p_revision AND c.state='active'
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE paper_oauth_restore_witness.signed_write_intents i
 SET state=p_result,result_head_cid=p_commit_head,
     resolved_at=clock_timestamp()
 WHERE i.operation_id=p_operation
  AND i.owner_webid=p_owner AND i.client_id=p_client
  AND i.revision=p_revision AND i.state='pending'
  AND (p_result<>'committed' OR
   (i.proposed_head_cid=p_commit_head AND
    i.expected_head_cid<>p_commit_head))
 RETURNING operation_id INTO updated;
 RETURN COALESCE(updated=p_operation,false);
END $fn$;

DROP FUNCTION paper_oauth_restore_witness.read_signed_write(uuid);
CREATE FUNCTION paper_oauth_restore_witness.read_signed_write(
 p_operation uuid
) RETURNS TABLE(owner_webid text,client_id text,grant_sha256 bytea,
 revision bigint,expected_head_cid text,proposed_head_cid text,
 state text,result_head_cid text)
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT i.owner_webid,i.client_id,i.grant_sha256,i.revision,
        i.expected_head_cid,i.proposed_head_cid,i.state,i.result_head_cid
 FROM paper_oauth_restore_witness.signed_write_intents i
 WHERE i.operation_id=p_operation;
$fn$;

REVOKE ALL ON FUNCTION paper_oauth_restore_witness.reserve_signed_write(
 text,text,bytea,bigint,uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.read_signed_write(uuid)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.reserve_signed_write(
 text,text,bytea,bigint,uuid,text,text) TO paper_oauth_witness_writer;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.read_signed_write(uuid)
 TO paper_oauth_witness_reconciler;
COMMIT;

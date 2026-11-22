-- NONACTIVATED independent PostgreSQL 18 WITNESS CLUSTER ONLY.
-- Apply strictly AFTER paper-oauth-external-restore-witness-v1.sql.
-- No 2PC claim: a durable unresolved signed-PDS commit intent BLOCKS
-- witness revocation ACK until a separately privileged reconciler
-- independently verifies the primary signed head/outbox or a durable
-- abort. Crashed/ambiguous writers NEVER age out automatically.
BEGIN;

DO $roles$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=
    'paper_oauth_witness_writer') THEN
  CREATE ROLE paper_oauth_witness_writer NOLOGIN NOSUPERUSER
   NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=
    'paper_oauth_witness_reconciler') THEN
  CREATE ROLE paper_oauth_witness_reconciler NOLOGIN NOSUPERUSER
   NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
END $roles$;
GRANT USAGE ON SCHEMA paper_oauth_restore_witness TO
 paper_oauth_witness_writer,paper_oauth_witness_reconciler;

CREATE TABLE paper_oauth_restore_witness.signed_write_intents(
 operation_id uuid PRIMARY KEY,
 owner_webid text NOT NULL CHECK(length(owner_webid) BETWEEN 8 AND 2048
   AND owner_webid LIKE 'https://%'),
 client_id text NOT NULL CHECK(length(client_id) BETWEEN 8 AND 2048
   AND client_id LIKE 'https://%'),
 grant_sha256 bytea NOT NULL CHECK(octet_length(grant_sha256)=32),
 revision bigint NOT NULL CHECK(revision>0),
 expected_head_cid text NOT NULL CHECK(
   expected_head_cid ~ '^bafyre[a-z2-7]{53}$'),
 state text NOT NULL DEFAULT 'pending'
   CHECK(state IN ('pending','committed','aborted')),
 result_head_cid text CHECK(result_head_cid IS NULL OR
   result_head_cid ~ '^bafyre[a-z2-7]{53}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 resolved_at timestamptz,
 CHECK ((state='pending' AND result_head_cid IS NULL AND
      resolved_at IS NULL) OR
   (state='aborted' AND result_head_cid IS NULL AND
      resolved_at IS NOT NULL) OR
   (state='committed' AND result_head_cid IS NOT NULL AND
      result_head_cid<>expected_head_cid AND resolved_at IS NOT NULL))
);
CREATE INDEX paper_oauth_writer_unresolved
 ON paper_oauth_restore_witness.signed_write_intents(owner_webid,client_id)
 WHERE state='pending';
REVOKE ALL ON paper_oauth_restore_witness.signed_write_intents
 FROM PUBLIC;

-- A witness revision transition, particularly an owner revocation, must
-- NOT be allowed to finish while a signed-PDS write might still commit.
-- The UPDATE on current_epochs serializes with the reader's FOR SHARE
-- lock; a new reservation can never sneak in between this check and
-- the revoker's epoch transition. A pending write is NOT a timeout lease.
CREATE FUNCTION paper_oauth_restore_witness.reject_unresolved_writes()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
 IF (NEW.revision<>OLD.revision OR NEW.state<>OLD.state) AND EXISTS(
    SELECT 1 FROM paper_oauth_restore_witness.signed_write_intents i
    WHERE i.owner_webid=OLD.owner_webid
      AND i.client_id=OLD.client_id AND i.state='pending'
 ) THEN
   RAISE EXCEPTION USING
     ERRCODE='P0001',MESSAGE='Unresolved signed write prevents OAuth epoch transition';
 END IF;
 RETURN NEW;
END $fn$;

CREATE TRIGGER paper_oauth_witness_write_fence
 BEFORE UPDATE OF revision,state ON
 paper_oauth_restore_witness.current_epochs
 FOR EACH ROW EXECUTE FUNCTION
 paper_oauth_restore_witness.reject_unresolved_writes();

-- Only a dedicated signed-PDS writer LOGIN can reserve, while the exact
-- generation is ALREADY sealed and still current. No grant IDs or owner
-- identity selected by public requests; the provider injects these from
-- signed DPoP/OAuth introspection. Neither the signer nor its LOGIN can
-- settle the intent, alter the witness grant, or acknowledge revocation.
CREATE FUNCTION paper_oauth_restore_witness.reserve_signed_write(
 p_owner text,p_client text,p_grant_hash bytea,p_revision bigint,
 p_operation uuid,p_expected_head text
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE allowed boolean; pending_count bigint; inserted uuid;
BEGIN
 IF length(p_owner) NOT BETWEEN 8 AND 2048 OR p_owner NOT LIKE 'https://%'
 OR length(p_client) NOT BETWEEN 8 AND 2048 OR p_client NOT LIKE 'https://%'
 OR octet_length(p_grant_hash)<>32 OR p_revision<1
 OR p_expected_head !~ '^bafyre[a-z2-7]{53}$'
 THEN RETURN false; END IF;
 -- Serialize reservations for this exact owner/client while preserving
 -- a SHARE grant row lock against the revoker's exclusive transition.
 -- Without this lock multiple concurrent COUNT+INSERT calls could exceed
 -- the strict bounded pending-intent cap.
 PERFORM pg_advisory_xact_lock(hashtextextended(
  'paper:witness:writer:v1:'||length(p_owner)::text||':'||p_owner||':'||p_client,0));
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
 -- Prevent a broken writer from creating unlimited frozen intents; use
 -- the primary signed-repo head CAS for the actual concurrent writer
 -- bound. No unfinished write can be silently evicted to make space.
 IF pending_count>=8 THEN RETURN false; END IF;
 INSERT INTO paper_oauth_restore_witness.signed_write_intents
  (operation_id,owner_webid,client_id,grant_sha256,revision,
   expected_head_cid)
 VALUES(p_operation,p_owner,p_client,p_grant_hash,p_revision,p_expected_head)
 ON CONFLICT (operation_id) DO NOTHING
 RETURNING operation_id INTO inserted;
 RETURN COALESCE(inserted=p_operation,false);
END $fn$;

-- NOT available to the writer. A distinct recovery/attestor principal
-- must verify the signed PRIMARY PG head, immutable blocks, generation,
-- outbox and WAL/commit outcome BEFORE calling this entry point.
-- For "aborted" it must first prove that the primary transaction cannot
-- still commit, including a completed crash/recovery barrier.
-- No automatic expiry, Redis intent, client-provided ACK or reuse.
CREATE FUNCTION paper_oauth_restore_witness.resolve_signed_write(
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
 -- The revoker's epoch transition and intent resolution serialize on
 -- this same row; do not approve if the witness high-water rolled back.
 PERFORM 1 FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=p_owner AND c.client_id=p_client
  AND c.revision=p_revision AND c.state='active'
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE paper_oauth_restore_witness.signed_write_intents i
 SET state=p_result,result_head_cid=p_commit_head,resolved_at=clock_timestamp()
 WHERE i.operation_id=p_operation AND i.owner_webid=p_owner
  AND i.client_id=p_client AND i.revision=p_revision
  AND i.state='pending'
  AND (p_result<>'committed' OR i.expected_head_cid<>p_commit_head)
 RETURNING operation_id INTO updated;
 RETURN COALESCE(updated=p_operation,false);
END $fn$;

-- Limited read-only verification for the independent reconciler to
-- audit a specific operation before comparing primary signed state.
CREATE FUNCTION paper_oauth_restore_witness.read_signed_write(
 p_operation uuid
) RETURNS TABLE(owner_webid text,client_id text,revision bigint,
 expected_head_cid text,state text,result_head_cid text)
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT i.owner_webid,i.client_id,i.revision,i.expected_head_cid,
        i.state,i.result_head_cid
 FROM paper_oauth_restore_witness.signed_write_intents i
 WHERE i.operation_id=p_operation;
$fn$;

REVOKE ALL ON FUNCTION paper_oauth_restore_witness.reject_unresolved_writes()
 FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.reserve_signed_write(
 text,text,bytea,bigint,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.resolve_signed_write(
 uuid,text,text,bigint,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.read_signed_write(
 uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.reserve_signed_write(
 text,text,bytea,bigint,uuid,text) TO paper_oauth_witness_writer;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.resolve_signed_write(
 uuid,text,text,bigint,text,text),
 paper_oauth_restore_witness.read_signed_write(
 uuid) TO paper_oauth_witness_reconciler;
COMMIT;

-- NONACTIVATED candidate. INDEPENDENT witness PostgreSQL 18 ONLY.
-- Apply after v1 -> v2 -> v3 -> v4, with no existing signed intents.
-- The future live writer MUST prove an independently retained PENDING receipt
-- before starting its primary signed repository transaction. A settlement
-- (including independently verified COMMIT) cannot release a revoke ACK until
-- its RESOLVED receipt is independently retained and sealed as well.
-- An ordinary witness SQL snapshot is NOT an anti-PITR external high-water.
BEGIN;
DO $guard$ BEGIN
 IF EXISTS(SELECT 1 FROM paper_oauth_restore_witness.signed_write_intents)
 THEN RAISE EXCEPTION USING ERRCODE='P0001',
   MESSAGE='v5 requires independently archived/reconciled historical intents; refusing unsafe backfill';
 END IF;
END $guard$;

ALTER TABLE paper_oauth_restore_witness.signed_write_intents
 ADD COLUMN epoch_event_sha256 bytea NOT NULL
   CHECK (octet_length(epoch_event_sha256)=32),
 ADD COLUMN pending_receipt_sealed boolean NOT NULL DEFAULT false,
 ADD COLUMN resolution_receipt_sealed boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT signed_write_receipt_state_order CHECK (
   (state='pending' AND resolution_receipt_sealed=false) OR
   (state IN ('committed','aborted') AND pending_receipt_sealed=true)
 );

-- The existing v3 reservation already holds the exact current epoch FOR
-- SHARE. Capture its immutable event hash in the SAME witness transaction.
CREATE FUNCTION paper_oauth_restore_witness.capture_signed_intent_epoch()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE event_hash bytea;
BEGIN
 SELECT c.event_sha256 INTO event_hash
 FROM paper_oauth_restore_witness.current_epochs c
 JOIN paper_oauth_restore_witness.events e
   ON e.owner_webid=c.owner_webid AND e.client_id=c.client_id
  AND e.revision=c.revision AND e.event_sha256=c.event_sha256
 WHERE c.owner_webid=NEW.owner_webid AND c.client_id=NEW.client_id
   AND c.revision=NEW.revision AND c.grant_sha256=NEW.grant_sha256
   AND c.state='active' AND c.sealed=true AND e.sealed_at IS NOT NULL
 FOR SHARE OF c;
 IF event_hash IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='P0001',
    MESSAGE='Unsealed or mismatched epoch cannot reserve signed intent';
 END IF;
 NEW.epoch_event_sha256=event_hash;
 RETURN NEW;
END $fn$;
CREATE TRIGGER paper_signed_intent_capture_epoch
 BEFORE INSERT ON paper_oauth_restore_witness.signed_write_intents
 FOR EACH ROW EXECUTE FUNCTION
 paper_oauth_restore_witness.capture_signed_intent_epoch();

-- Prevent rollback of receipt bits and settlement before pending sealing,
-- independently of the function used by the privileged migration owner.
CREATE FUNCTION paper_oauth_restore_witness.enforce_signed_intent_receipts()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
 IF OLD.operation_id<>NEW.operation_id OR
    OLD.owner_webid<>NEW.owner_webid OR
    OLD.client_id<>NEW.client_id OR
    OLD.revision<>NEW.revision OR
    OLD.grant_sha256<>NEW.grant_sha256 OR
    OLD.epoch_event_sha256<>NEW.epoch_event_sha256 OR
    OLD.expected_head_cid<>NEW.expected_head_cid OR
    OLD.proposed_head_cid<>NEW.proposed_head_cid OR
    (OLD.pending_receipt_sealed AND NOT NEW.pending_receipt_sealed) OR
    (OLD.resolution_receipt_sealed AND NOT NEW.resolution_receipt_sealed) OR
    (OLD.state<>NEW.state AND
     (NOT OLD.pending_receipt_sealed OR OLD.state<>'pending' OR
      NEW.resolution_receipt_sealed)) OR
    (OLD.state=NEW.state AND
     (OLD.result_head_cid IS DISTINCT FROM NEW.result_head_cid OR
      OLD.resolved_at IS DISTINCT FROM NEW.resolved_at)) OR
    (NEW.state='pending' AND NEW.resolution_receipt_sealed)
 THEN
  RAISE EXCEPTION USING ERRCODE='P0001',
    MESSAGE='Signed intent history/receipt transition is immutable';
 END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER paper_signed_intent_receipt_order
 BEFORE UPDATE ON paper_oauth_restore_witness.signed_write_intents
 FOR EACH ROW EXECUTE FUNCTION
 paper_oauth_restore_witness.enforce_signed_intent_receipts();

-- All epoch transitions (especially revocation ACK) must wait for every
-- operation's immutable outcome receipt, not merely its SQL settled state.
CREATE OR REPLACE FUNCTION paper_oauth_restore_witness.reject_unresolved_writes()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $fn$
BEGIN
 IF (NEW.revision<>OLD.revision OR NEW.state<>OLD.state) AND EXISTS(
  SELECT 1 FROM paper_oauth_restore_witness.signed_write_intents i
  WHERE i.owner_webid=OLD.owner_webid
    AND i.client_id=OLD.client_id
    AND (i.state='pending' OR NOT i.pending_receipt_sealed OR
         NOT i.resolution_receipt_sealed)
 ) THEN
  RAISE EXCEPTION USING ERRCODE='P0001',
   MESSAGE='Unarchived signed intent receipt prevents OAuth epoch transition';
 END IF;
 RETURN NEW;
END $fn$;

-- Bytes are derived by the independent witness, NOT furnished by a caller.
-- Stable ASCII LF-separated format; no owner WebID/client ID appears.
-- Subject hash is length-framed and includes both identifiers.
-- Both historical signed CIDs, epoch event and hashed grant are recorded.
CREATE FUNCTION paper_oauth_restore_witness.signed_intent_receipt(
 p_operation uuid,p_phase text
) RETURNS bytea
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT convert_to(
  'paper:witness:signed-intent:v1'||chr(10)||
  encode(sha256(convert_to(
   'paper:witness:subject:v1:'||length(i.owner_webid)::text||':'||
    i.owner_webid||':'||i.client_id,'UTF8')),'hex')||chr(10)||
  i.operation_id::text||chr(10)||i.revision::text||chr(10)||
  encode(i.grant_sha256,'hex')||chr(10)||
  encode(i.epoch_event_sha256,'hex')||chr(10)||
  i.expected_head_cid||chr(10)||i.proposed_head_cid||chr(10)||
  p_phase||chr(10)||
  CASE WHEN p_phase='pending' THEN 'pending' ELSE i.state END||chr(10)||
  CASE WHEN p_phase='pending' THEN '-' ELSE
     coalesce(i.result_head_cid,'-') END||chr(10)
 ,'UTF8')
 FROM paper_oauth_restore_witness.signed_write_intents i
 WHERE i.operation_id=p_operation AND
  (p_phase='pending' OR
   (p_phase='resolved' AND i.state IN ('committed','aborted')))
$fn$;

CREATE FUNCTION paper_oauth_restore_witness.seal_signed_intent_receipt(
 p_operation uuid,p_phase text,p_receipt_hash bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE expected bytea; changed integer;
BEGIN
 IF p_phase NOT IN ('pending','resolved') OR
    octet_length(p_receipt_hash)<>32 THEN RETURN false; END IF;
 SELECT paper_oauth_restore_witness.signed_intent_receipt(p_operation,p_phase)
 INTO expected;
 IF expected IS NULL OR sha256(expected)<>p_receipt_hash THEN RETURN false; END IF;
 IF p_phase='pending' THEN
  UPDATE paper_oauth_restore_witness.signed_write_intents i
  SET pending_receipt_sealed=true
  WHERE i.operation_id=p_operation AND i.state='pending'
    AND i.pending_receipt_sealed=false AND EXISTS(
     SELECT 1 FROM paper_oauth_restore_witness.current_epochs c
     JOIN paper_oauth_restore_witness.events e ON
      e.owner_webid=c.owner_webid AND e.client_id=c.client_id
      AND e.revision=c.revision AND e.event_sha256=c.event_sha256
     WHERE c.owner_webid=i.owner_webid AND c.client_id=i.client_id
      AND c.revision=i.revision AND c.state='active'
      AND c.grant_sha256=i.grant_sha256
      AND c.event_sha256=i.epoch_event_sha256 AND c.sealed=true
      AND e.sealed_at IS NOT NULL);
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed=1 THEN RETURN true; END IF;
  RETURN EXISTS(
   SELECT 1 FROM paper_oauth_restore_witness.signed_write_intents i
   WHERE i.operation_id=p_operation AND i.pending_receipt_sealed=true
     AND sha256(paper_oauth_restore_witness.signed_intent_receipt(
       p_operation,'pending'))=p_receipt_hash);
 END IF;
 UPDATE paper_oauth_restore_witness.signed_write_intents i
 SET resolution_receipt_sealed=true
 WHERE i.operation_id=p_operation AND i.state IN ('committed','aborted')
   AND i.pending_receipt_sealed=true AND i.resolution_receipt_sealed=false
   AND (i.state<>'committed' OR i.result_head_cid=i.proposed_head_cid);
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed=1 THEN RETURN true; END IF;
 RETURN EXISTS(
  SELECT 1 FROM paper_oauth_restore_witness.signed_write_intents i
  WHERE i.operation_id=p_operation AND i.resolution_receipt_sealed=true
    AND sha256(paper_oauth_restore_witness.signed_intent_receipt(
     p_operation,'resolved'))=p_receipt_hash);
END $fn$;

-- The trusted writer may inspect ONLY the exact sealed pending reservation.
-- This is required in addition to the existing sealed-epoch reservation CAS.
CREATE FUNCTION paper_oauth_restore_witness.verify_sealed_signed_intent(
 p_operation uuid,p_owner text,p_client text,p_revision bigint,
 p_expected_head text,p_proposed_head text
) RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT EXISTS(
  SELECT 1 FROM paper_oauth_restore_witness.signed_write_intents i
  JOIN paper_oauth_restore_witness.current_epochs c ON
   c.owner_webid=i.owner_webid AND c.client_id=i.client_id
  JOIN paper_oauth_restore_witness.events e ON
   e.owner_webid=c.owner_webid AND e.client_id=c.client_id
   AND e.revision=c.revision AND e.event_sha256=c.event_sha256
  WHERE i.operation_id=p_operation AND i.owner_webid=p_owner
   AND i.client_id=p_client AND i.revision=p_revision
   AND i.expected_head_cid=p_expected_head
   AND i.proposed_head_cid=p_proposed_head
   AND i.state='pending' AND i.pending_receipt_sealed=true
   AND c.revision=i.revision AND c.state='active' AND c.sealed=true
   AND c.grant_sha256=i.grant_sha256
   AND c.event_sha256=i.epoch_event_sha256 AND e.sealed_at IS NOT NULL
 );
$fn$;

-- Keep v4's generic abort authority inaccessible to ALL runtime roles.
-- Even the restricted positive-commit reconciler may settle ONLY after
-- the pending receipt was sealed; the resolved receipt remains UNSEALED
-- until a different independent attestor performs exact object readback.
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
   AND c.revision=p_revision AND c.state='active' AND c.sealed=true
 FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE paper_oauth_restore_witness.signed_write_intents i
 SET state=p_result,result_head_cid=p_commit_head,
     resolved_at=clock_timestamp()
 WHERE i.operation_id=p_operation AND i.owner_webid=p_owner
   AND i.client_id=p_client AND i.revision=p_revision
   AND i.state='pending' AND i.pending_receipt_sealed=true
   AND i.resolution_receipt_sealed=false
   AND (p_result<>'committed' OR
        (i.proposed_head_cid=p_commit_head AND
         i.expected_head_cid<>p_commit_head))
 RETURNING operation_id INTO updated;
 RETURN COALESCE(updated=p_operation,false);
END $fn$;

REVOKE ALL ON FUNCTION
 paper_oauth_restore_witness.capture_signed_intent_epoch() FROM PUBLIC;
REVOKE ALL ON FUNCTION
 paper_oauth_restore_witness.enforce_signed_intent_receipts() FROM PUBLIC;
REVOKE ALL ON FUNCTION
 paper_oauth_restore_witness.signed_intent_receipt(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION
 paper_oauth_restore_witness.seal_signed_intent_receipt(uuid,text,bytea)
 FROM PUBLIC;
REVOKE ALL ON FUNCTION
 paper_oauth_restore_witness.verify_sealed_signed_intent(
  uuid,text,text,bigint,text,text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION
 paper_oauth_restore_witness.resolve_signed_write(
  uuid,text,text,bigint,text,text)
 FROM paper_oauth_witness_reconciler;
GRANT EXECUTE ON FUNCTION
 paper_oauth_restore_witness.signed_intent_receipt(uuid,text),
 paper_oauth_restore_witness.seal_signed_intent_receipt(uuid,text,bytea)
 TO paper_oauth_witness_attestor;
GRANT EXECUTE ON FUNCTION
 paper_oauth_restore_witness.verify_sealed_signed_intent(
  uuid,text,text,bigint,text,text)
 TO paper_oauth_witness_writer;
COMMIT;

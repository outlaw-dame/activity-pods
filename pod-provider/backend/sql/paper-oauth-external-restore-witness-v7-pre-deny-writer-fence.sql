-- NONACTIVATED independent PostgreSQL 18 WITNESS DATABASE ONLY.
-- Strictly after witness v1..v6, on a NEW or independently reconciled
-- witness with ZERO historical signed-write intents.
--
-- Safety invariant: PREPARE DENY is committed in the independent witness
-- BEFORE the external pre-deny WORM PUT and BEFORE any primary PG/Redis/Jena
-- revocation. From the instant preparation commits, every new signed-PDS
-- reservation fails, active PG witness checks fail, and existing signed
-- operations remain pending until their exact archived outcomes are proven.
-- No timeout, abort, clear/restart or automatic reapproval exists here.
-- The independent witness PG is STILL rewindable under physical PITR:
-- an independently administered nonrewindable COMPLIANCE latest-head
-- MUST guard ALL OAuth/PDS accesses before production release.
BEGIN;

DO $empty$ BEGIN
 IF EXISTS(SELECT 1 FROM paper_oauth_restore_witness.signed_write_intents)
 THEN RAISE EXCEPTION USING ERRCODE='P0001',
  MESSAGE='Witness v7 requires audited signed-intent reconciliation; refusing active-history cutover';
 END IF;
END $empty$;

DO $roles$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles
   WHERE rolname='paper_oauth_witness_pre_deny_preparer') THEN
  CREATE ROLE paper_oauth_witness_pre_deny_preparer NOLOGIN
   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles
   WHERE rolname='paper_oauth_witness_pre_deny_attestor') THEN
  CREATE ROLE paper_oauth_witness_pre_deny_attestor NOLOGIN
   NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
END $roles$;
GRANT USAGE ON SCHEMA paper_oauth_restore_witness TO
 paper_oauth_witness_pre_deny_preparer,
 paper_oauth_witness_pre_deny_attestor;

ALTER TABLE paper_oauth_restore_witness.current_epochs
 ADD COLUMN deny_operation_id uuid,
 ADD COLUMN deny_credential_epoch bigint,
 ADD COLUMN deny_sai_revision bigint,
 ADD COLUMN deny_scope_sha256 bytea,
 ADD COLUMN deny_receipt_sha256 bytea,
 ADD COLUMN deny_sealed_at timestamptz,
 ADD CONSTRAINT pre_deny_exact_transition CHECK (
  (deny_operation_id IS NULL AND deny_credential_epoch IS NULL AND
   deny_sai_revision IS NULL AND deny_scope_sha256 IS NULL AND
   deny_receipt_sha256 IS NULL AND deny_sealed_at IS NULL)
  OR
  (deny_operation_id IS NOT NULL AND deny_credential_epoch>0 AND
   deny_sai_revision>0 AND octet_length(deny_scope_sha256)=32 AND
   ((deny_receipt_sha256 IS NULL AND deny_sealed_at IS NULL)
     OR (octet_length(deny_receipt_sha256)=32 AND
         deny_sealed_at IS NOT NULL)))
 );

-- Even an erroneously privileged SQL caller cannot clear a previously
-- prepared denial through a normal row UPDATE. The only legal progression
-- is NULL -> exact immutable owner-bound intention -> exact sealed receipt.
CREATE FUNCTION paper_oauth_restore_witness.enforce_immutable_pre_deny()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $guard$
BEGIN
 IF OLD.deny_operation_id IS NOT NULL AND (
    NEW.deny_operation_id IS DISTINCT FROM OLD.deny_operation_id OR
    NEW.deny_credential_epoch IS DISTINCT FROM OLD.deny_credential_epoch OR
    NEW.deny_sai_revision IS DISTINCT FROM OLD.deny_sai_revision OR
    NEW.deny_scope_sha256 IS DISTINCT FROM OLD.deny_scope_sha256)
 THEN RAISE EXCEPTION USING ERRCODE='P0001',
   MESSAGE='Immutable pre-denial cannot be cleared or changed';
 END IF;
 IF OLD.deny_receipt_sha256 IS NOT NULL AND (
   NEW.deny_receipt_sha256 IS DISTINCT FROM OLD.deny_receipt_sha256 OR
   NEW.deny_sealed_at IS DISTINCT FROM OLD.deny_sealed_at)
 THEN RAISE EXCEPTION USING ERRCODE='P0001',
   MESSAGE='Sealed independent pre-denial cannot be rewound';
 END IF;
 RETURN NEW;
END $guard$;
CREATE TRIGGER witness_pre_deny_immutable
 BEFORE UPDATE ON paper_oauth_restore_witness.current_epochs
 FOR EACH ROW EXECUTE FUNCTION
 paper_oauth_restore_witness.enforce_immutable_pre_deny();

-- A dedicated provider-held restricted LOGIN performs this one-way CAS.
-- No request JSON may choose the authenticated owner or operation ID:
-- the calling coordinator has to certify the owner session, SAI and
-- credential epoch, and supply the SAME deterministic pre-deny operation
-- already derived for its retained S3-compatible canonical receipt.
CREATE FUNCTION paper_oauth_restore_witness.prepare_pre_deny(
 p_owner text,p_client text,p_grant bytea,p_revision bigint,
 p_operation uuid,p_credential_epoch bigint,p_sai_revision bigint,
 p_scope_sha256 bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $prepare$
DECLARE row record;
BEGIN
 IF length(p_owner) NOT BETWEEN 8 AND 2048 OR
    p_owner NOT LIKE 'https://%' OR
    octet_length(convert_to(p_owner,'UTF8'))<>length(p_owner) OR
    length(p_client) NOT BETWEEN 8 AND 2048 OR
    p_client NOT LIKE 'https://%' OR
    octet_length(convert_to(p_client,'UTF8'))<>length(p_client) OR
    octet_length(p_grant)<>32 OR
    octet_length(p_scope_sha256)<>32 OR
    p_revision<1 OR p_credential_epoch<1 OR p_sai_revision<1 OR
    p_operation::text !~
      '^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$'
 THEN RETURN false; END IF;
 SELECT c.state,c.sealed,c.revision,c.grant_sha256,
   c.deny_operation_id,c.deny_credential_epoch,
   c.deny_sai_revision,c.deny_scope_sha256
 INTO row FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=p_owner AND c.client_id=p_client FOR UPDATE;
 IF NOT FOUND OR row.state<>'active' OR row.sealed<>true OR
    row.revision<>p_revision OR row.grant_sha256<>p_grant
 THEN RETURN false; END IF;
 IF row.deny_operation_id IS NOT NULL THEN
  RETURN row.deny_operation_id=p_operation AND
    row.deny_credential_epoch=p_credential_epoch AND
    row.deny_sai_revision=p_sai_revision AND
    row.deny_scope_sha256=p_scope_sha256;
 END IF;
 UPDATE paper_oauth_restore_witness.current_epochs c SET
   deny_operation_id=p_operation,
   deny_credential_epoch=p_credential_epoch,
   deny_sai_revision=p_sai_revision,
   deny_scope_sha256=p_scope_sha256
 WHERE c.owner_webid=p_owner AND c.client_id=p_client
   AND c.revision=p_revision AND c.state='active'
   AND c.sealed=true AND c.deny_operation_id IS NULL;
 RETURN FOUND;
END $prepare$;

-- Every signed PDS reservation has to serialize with PREPARE's FOR UPDATE
-- of this SAME independent PG row. Trigger is defense in depth for the
-- previous v3 reserve function, including unexpected direct table grants.
-- A writer whose shared lock won before PREPARE is recorded as pending,
-- and v5 forbids block ACK until its independently retained resolution.
CREATE FUNCTION paper_oauth_restore_witness.reject_new_pre_denied_write()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $trigger$
DECLARE permitted boolean;
BEGIN
 SELECT c.deny_operation_id IS NULL INTO permitted
 FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=NEW.owner_webid AND
   c.client_id=NEW.client_id AND c.revision=NEW.revision AND
   c.state='active' AND c.sealed=true
 FOR SHARE;
 IF permitted IS DISTINCT FROM true THEN
  RAISE EXCEPTION USING ERRCODE='P0001',
   MESSAGE='Independent pre-denial blocks a new signed-write reservation';
 END IF;
 RETURN NEW;
END $trigger$;
CREATE TRIGGER witness_pre_deny_signed_write
 BEFORE INSERT ON paper_oauth_restore_witness.signed_write_intents
 FOR EACH ROW EXECUTE FUNCTION
 paper_oauth_restore_witness.reject_new_pre_denied_write();

-- Exact canonical ASCII JSON receipt matches the previously merged
-- oauth-pre-deny-intent-coordinator.mjs key/bytes, including SQL witness-v5
-- owner-length framing. PostgreSQL receives the fresh canonical credential,
-- SAI and scope proofs from a strictly restricted authenticated coordinator.
-- WORM Object Lock verification itself is OUTSIDE this SQL database.
CREATE FUNCTION paper_oauth_restore_witness.pre_deny_receipt(
 p_owner text,p_client text,p_operation uuid
) RETURNS bytea
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $receipt$
 SELECT convert_to(
  '{"kind":"paper.oauth.pre-deny.v1","subject":"'
  ||encode(sha256(convert_to(
    'paper:witness:subject:v1:'||length(c.owner_webid)::text||':'||
    c.owner_webid||':'||c.client_id,'UTF8')),'hex')
  ||'","revision":"'||c.revision::text
  ||'","operationId":"'||c.deny_operation_id::text
  ||'","grantSha256":"'||encode(c.grant_sha256,'hex')
  ||'","credentialEpoch":"'||c.deny_credential_epoch::text
  ||'","saiRevision":"'||c.deny_sai_revision::text
  ||'","scopeSha256":"'||encode(c.deny_scope_sha256,'hex')||'"}',
 'UTF8')
 FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=p_owner AND c.client_id=p_client
   AND c.deny_operation_id=p_operation AND c.state='active';
$receipt$;

-- Independently credentialed attestor must first perform real Object Lock
-- version enumeration, exact bytes+retention GET and write-once proof.
-- This function only seals the SQL witness against exact canonical bytes.
CREATE FUNCTION paper_oauth_restore_witness.seal_pre_deny(
 p_owner text,p_client text,p_operation uuid,p_receipt_sha256 bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $seal$
DECLARE row record; exact bytea;
BEGIN
 IF octet_length(p_receipt_sha256)<>32 THEN RETURN false; END IF;
 SELECT c.deny_operation_id,c.deny_receipt_sha256,c.deny_sealed_at
 INTO row FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=p_owner AND c.client_id=p_client FOR UPDATE;
 IF NOT FOUND OR row.deny_operation_id IS DISTINCT FROM p_operation
 THEN RETURN false; END IF;
 exact=sha256(paper_oauth_restore_witness.pre_deny_receipt(
   p_owner,p_client,p_operation));
 IF exact IS NULL OR exact<>p_receipt_sha256 THEN RETURN false; END IF;
 IF row.deny_sealed_at IS NOT NULL THEN
  RETURN row.deny_receipt_sha256=p_receipt_sha256;
 END IF;
 UPDATE paper_oauth_restore_witness.current_epochs c SET
   deny_receipt_sha256=p_receipt_sha256,
   deny_sealed_at=clock_timestamp()
 WHERE c.owner_webid=p_owner AND c.client_id=p_client AND
   c.deny_operation_id=p_operation AND c.deny_sealed_at IS NULL;
 RETURN FOUND;
END $seal$;

-- All previous witness-verification and active-checkpoint reads must STOP
-- on a prepared denial, even before remote S3 GET/sealing finishes. The
-- original v1/v6 function signature and grants remain compatible.
CREATE OR REPLACE FUNCTION paper_oauth_restore_witness.verify(
 p_owner text,p_client text,p_grant_hash bytea,p_revision bigint
) RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $verify$
 SELECT EXISTS(
  SELECT 1 FROM paper_oauth_restore_witness.current_epochs c
  JOIN paper_oauth_restore_witness.events e
    ON e.owner_webid=c.owner_webid AND e.client_id=c.client_id
   AND e.revision=c.revision AND e.event_sha256=c.event_sha256
  WHERE c.owner_webid=p_owner AND c.client_id=p_client
   AND c.revision=p_revision AND c.grant_sha256=p_grant_hash
   AND c.state='active' AND c.sealed=true AND e.sealed_at IS NOT NULL
   AND c.deny_operation_id IS NULL
 );
$verify$;
CREATE OR REPLACE FUNCTION paper_oauth_restore_witness.active_checkpoint(
 p_owner text,p_client text,p_grant_hash bytea,p_revision bigint
) RETURNS TABLE(revision text,event_sha256 text,operation_id text)
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $checkpoint$
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
  AND c.state='active' AND c.sealed=true AND e.sealed_at IS NOT NULL
  AND c.deny_operation_id IS NULL;
$checkpoint$;

-- Epoch block with the exact prepared operation may proceed only AFTER
-- the independently archived PRE-DENY receipt has been sealed. The v5
-- reject_unresolved_writes BEFORE UPDATE trigger still requires every
-- signed PDS PENDING and COMMITTED/ABORTED receipt to be sealed FIRST.
CREATE OR REPLACE FUNCTION paper_oauth_restore_witness.block(
 p_owner text,p_client text,p_grant_hash bytea,p_expected bigint,p_operation uuid
) RETURNS bigint
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $block$
DECLARE row record;
BEGIN
 SELECT c.state,c.revision,c.sealed,c.grant_sha256,
  c.deny_operation_id,c.deny_receipt_sha256,c.deny_sealed_at
 INTO row FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=p_owner AND c.client_id=p_client FOR UPDATE;
 IF NOT FOUND OR row.state<>'active' OR row.sealed<>true OR
   row.revision<>p_expected OR row.grant_sha256<>p_grant_hash OR
   row.deny_operation_id IS DISTINCT FROM p_operation OR
   row.deny_receipt_sha256 IS NULL OR row.deny_sealed_at IS NULL
 THEN RETURN 0; END IF;
 RETURN paper_oauth_restore_witness.append_event(
  p_owner,p_client,p_grant_hash,p_expected,p_operation,'blocked');
END $block$;

-- Intentionally leave pre-denial marked after a block, so a stale grant
-- cannot be reapproved or resurrected until a separately reviewed
-- independently witnessed NEW owner authorization transition exists.
CREATE OR REPLACE FUNCTION paper_oauth_restore_witness.issue(
 p_owner text,p_client text,p_grant_hash bytea,p_expected bigint,p_operation uuid
) RETURNS bigint
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $issue$
DECLARE prepared uuid;
BEGIN
 SELECT c.deny_operation_id INTO prepared
 FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=p_owner AND c.client_id=p_client FOR UPDATE;
 IF FOUND AND prepared IS NOT NULL THEN RETURN 0; END IF;
 RETURN paper_oauth_restore_witness.append_event(
  p_owner,p_client,p_grant_hash,p_expected,p_operation,'active');
END $issue$;

REVOKE ALL ON FUNCTION paper_oauth_restore_witness.prepare_pre_deny(
 text,text,bytea,bigint,uuid,bigint,bigint,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.pre_deny_receipt(
 text,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.seal_pre_deny(
 text,text,uuid,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.enforce_immutable_pre_deny()
 FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.reject_new_pre_denied_write()
 FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.block(
 text,text,bytea,bigint,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.issue(
 text,text,bytea,bigint,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.prepare_pre_deny(
 text,text,bytea,bigint,uuid,bigint,bigint,bytea)
 TO paper_oauth_witness_pre_deny_preparer;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.pre_deny_receipt(
 text,text,uuid),paper_oauth_restore_witness.seal_pre_deny(
 text,text,uuid,bytea)
 TO paper_oauth_witness_pre_deny_attestor;
-- No LOGIN or direct table permissions are created. Existing v1 issuer,
-- revoker and reader roles remain least-privileged and now deny prepared
-- transitions. The independent witness is STILL NOT a live WORM authority.
COMMIT;

-- NONACTIVATED independent PostgreSQL18 witness database ONLY.
-- Apply strictly AFTER witness v1,v2,v3. This migration is an
-- authorization CUTOVER: the general reconciliation LOGIN must not be able
-- to mark a signed write aborted, because a false abort makes an earlier
-- signed PDS commit look safely resolved and permits a later revoke ACK.
-- There is deliberately NO automatic abort/timeout/WAL recovery role:
-- production cannot release pending intents until a separate independently
-- audited and WORM-backed recovery-barrier service has been proven.
BEGIN;

-- The generic function can still be invoked only by the privileged
-- migration owner in disposable recovery fixtures, NOT the runtime
-- reconciler, signed writer, issuer, revoker, reader or WORM attestor.
REVOKE EXECUTE ON FUNCTION
 paper_oauth_restore_witness.resolve_signed_write(
  uuid,text,text,bigint,text,text)
 FROM paper_oauth_witness_reconciler;

-- Positive settlement only, with exact immutable proposed-CID binding
-- enforced again by the v3 function. This wrapper is SECURITY DEFINER,
-- function owner must be independent of all runtime LOGINs, and no role
-- except the reconciler receives EXECUTE.
CREATE FUNCTION paper_oauth_restore_witness.settle_verified_committed(
 p_operation uuid,p_owner text,p_client text,p_revision bigint,
 p_commit_head text
) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT COALESCE(paper_oauth_restore_witness.resolve_signed_write(
  p_operation,p_owner,p_client,p_revision,'committed',p_commit_head
 ),false);
$fn$;

REVOKE ALL ON FUNCTION paper_oauth_restore_witness.settle_verified_committed(
 uuid,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
 paper_oauth_restore_witness.settle_verified_committed(
  uuid,text,text,bigint,text)
 TO paper_oauth_witness_reconciler;

-- No generic SET/ADMIN privileges are granted here. Migration ownership,
-- runtime restricted LOGINs and external WORM key custody remain separate.
COMMIT;

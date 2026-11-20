-- Restricted credential for postgres-account-lifecycle.sealSignupEvidence.
-- SELECT FOR UPDATE needs an UPDATE privilege; the account guard disallows
-- actual mutation. The journal guard admits only a verified genesis seal.
BEGIN;
CREATE ROLE paper_provider_genesis_sealer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA paper_account_candidate TO paper_provider_genesis_sealer;
GRANT SELECT(account_id,provider_id,username_key,webid,activitypub_actor_uri,atproto_did,
  atproto_handle,atproto_pds_url,atproto_repo_initialized,state,generation),UPDATE(changed_at)
  ON paper_account_candidate.accounts TO paper_provider_genesis_sealer;
GRANT SELECT(operation_id,account_id,state,generation,may_have_side_effects,provider_id,
  app_client_id,hmac_key_version,idempotency_hmac),
  UPDATE(state,generation,evidence_digest,evidence_commit_cid,evidence_root_cid,evidence_rev,
    evidence_fence,evidence_account_generation,evidence_sealed_at,changed_at)
  ON paper_account_candidate.signup_operations TO paper_provider_genesis_sealer;

CREATE FUNCTION paper_account_candidate.guard_provider_genesis_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF NOT pg_has_role(session_user,'paper_provider_genesis_sealer','MEMBER') THEN RETURN NEW; END IF;
  IF TG_TABLE_NAME='signup_operations' THEN
    IF OLD.state='reconciliation_required' AND NEW.state='evidence_sealed'
      AND OLD.enrollment_state='consent_recorded' AND OLD.provider_genesis_rdf_digest IS NOT NULL
      AND NEW.generation=OLD.generation+1 AND EXISTS (
        SELECT 1 FROM paper_account_candidate.accounts a
        JOIN paper_account_reservation_proof.reservations r ON r.expected_webid=a.webid
        CROSS JOIN LATERAL paper_account_reservation_proof.read_provider_genesis(
          r.reservation_id,OLD.operation_id,a.atproto_did) g
        CROSS JOIN LATERAL paper_account_reservation_proof.hosted_genesis_scope(a.atproto_did) h
        WHERE a.account_id=OLD.account_id AND a.generation=NEW.evidence_account_generation
          AND h.operation_id=OLD.operation_id AND h.lease_epoch::bigint=NEW.evidence_fence
          AND h.rdf_digest=OLD.provider_genesis_rdf_digest AND g.head_cid=NEW.evidence_commit_cid
          AND g.root_cid=NEW.evidence_root_cid AND g.rev=NEW.evidence_rev
      ) THEN RETURN NEW; END IF;
  END IF;
  RAISE EXCEPTION 'Provider genesis seal refused' USING ERRCODE='42501';
END $$;
REVOKE ALL ON FUNCTION paper_account_candidate.guard_provider_genesis_seal() FROM PUBLIC;
CREATE TRIGGER guard_provider_account_before_seal BEFORE UPDATE ON paper_account_candidate.accounts
  FOR EACH ROW EXECUTE FUNCTION paper_account_candidate.guard_provider_genesis_seal();
CREATE TRIGGER guard_provider_journal_before_seal BEFORE UPDATE ON paper_account_candidate.signup_operations
  FOR EACH ROW EXECUTE FUNCTION paper_account_candidate.guard_provider_genesis_seal();
COMMIT;

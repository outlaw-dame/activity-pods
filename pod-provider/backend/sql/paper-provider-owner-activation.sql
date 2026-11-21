-- Disposable provider only. Run after native auth and the provider genesis sealer.
BEGIN;
CREATE ROLE paper_provider_owner_activator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

ALTER TABLE paper_account_candidate.signup_operations
  DROP CONSTRAINT signup_completion_fields_check,
  ADD CONSTRAINT signup_completion_fields_check CHECK (
    (state <> 'ready' AND num_nonnulls(completion_at,completion_account_generation,completion_app_uri,
      completion_grant_uri,completion_consent_revision,completion_proof_digest)=0)
    OR (state='ready' AND completion_at IS NOT NULL AND completion_account_generation IS NOT NULL
      AND completion_app_uri IS NOT NULL AND completion_proof_digest IS NOT NULL AND (
        (completion_grant_uri IS NOT NULL AND completion_consent_revision IS NOT NULL)
        OR (completion_grant_uri IS NULL AND completion_consent_revision IS NULL
          AND enrollment_state IS NOT DISTINCT FROM 'consent_recorded' AND provider_genesis_rdf_digest IS NOT NULL
          AND completion_proof_digest=evidence_digest AND completion_account_generation=evidence_account_generation+1))));

CREATE FUNCTION paper_account_reservation_proof.provider_owner_scope(p_reservation uuid,p_owner text)
RETURNS TABLE(operation_id uuid,did text) LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT s.operation_id,a.atproto_did FROM paper_account_reservation_proof.reservations r
    JOIN paper_account_candidate.accounts a ON a.account_id=r.v4_account_id AND a.provider_id=r.v4_provider_id
    JOIN paper_account_candidate.signup_operations s ON s.operation_id=r.v4_operation_id AND s.account_id=a.account_id
    WHERE r.reservation_id=p_reservation AND r.expected_webid=p_owner AND a.webid=p_owner
      AND s.enrollment_state='consent_recorded' AND s.state IN ('reconciliation_required','evidence_sealed')
      AND a.state='provisioning' AND r.state='side_effects_started';
$$;
REVOKE ALL ON FUNCTION paper_account_reservation_proof.provider_owner_scope(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.provider_owner_scope(uuid,text) TO paper_provider_genesis_reader;

CREATE FUNCTION paper_private_auth.owner_ready(p_reservation uuid,p_owner text,p_username text)
RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM paper_account_reservation_proof.reservations r
    JOIN paper_account_candidate.accounts a ON a.account_id=r.v4_account_id AND a.provider_id=r.v4_provider_id
    JOIN paper_account_candidate.signup_operations s ON s.account_id=a.account_id AND s.operation_id=r.v4_operation_id
    JOIN paper_private_auth.accounts n ON n.data->>'signupReservationId'=r.reservation_id::text
    WHERE r.reservation_id=p_reservation AND r.expected_webid=p_owner AND r.username=p_username
      AND r.state='completed' AND a.state='ready' AND s.state='ready' AND s.completion_grant_uri IS NULL
      AND a.generation=s.completion_account_generation AND r.evidence_hash=s.evidence_digest
      AND r.atproto_did=a.atproto_did AND a.webid=p_owner AND a.username_key=p_username
      AND n.data->>'webId'=p_owner AND n.data->>'username'=p_username
      AND coalesce(n.data->'disabled','false'::jsonb)='false'::jsonb);
$$;

CREATE FUNCTION paper_account_reservation_proof.activate_provider_owner(
  p_reservation uuid,p_operation uuid,p_owner text,p_did text,p_head text,p_root text,p_rev text,p_epoch bigint
) RETURNS boolean LANGUAGE plpgsql STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET lock_timeout='2s' AS $$
DECLARE
  a paper_account_candidate.accounts%ROWTYPE;
  s paper_account_candidate.signup_operations%ROWTYPE;
  r paper_account_reservation_proof.reservations%ROWTYPE;
BEGIN
  SELECT acc.* INTO STRICT a FROM paper_account_candidate.accounts acc
    JOIN paper_account_candidate.signup_operations op ON op.account_id=acc.account_id AND op.provider_id=acc.provider_id
    WHERE op.operation_id=p_operation AND acc.webid=p_owner AND acc.atproto_did=p_did FOR UPDATE OF acc;
  SELECT * INTO STRICT s FROM paper_account_candidate.signup_operations WHERE operation_id=p_operation AND account_id=a.account_id FOR UPDATE;
  SELECT * INTO STRICT r FROM paper_account_reservation_proof.reservations WHERE reservation_id=p_reservation
    AND v4_operation_id=s.operation_id AND v4_account_id=a.account_id AND expected_webid=p_owner FOR UPDATE;
  IF (s.evidence_commit_cid,s.evidence_root_cid,s.evidence_rev,s.evidence_fence) IS DISTINCT FROM (p_head,p_root,p_rev,p_epoch)
    THEN RETURN false; END IF;
  IF s.state='ready' THEN RETURN paper_private_auth.owner_ready(p_reservation,p_owner,r.username); END IF;
  IF a.state<>'provisioning' OR s.state<>'evidence_sealed' OR r.state<>'side_effects_started'
    OR a.generation IS DISTINCT FROM s.evidence_account_generation THEN RETURN false; END IF;
  PERFORM 1 FROM paper_private_auth.accounts n WHERE n.data->>'signupReservationId'=r.reservation_id::text
    AND n.data->>'webId'=p_owner AND n.data->>'username'=a.username_key
    AND coalesce(n.data->'disabled','false'::jsonb)='false'::jsonb FOR SHARE;
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM 1 FROM paper_atproto_repo_proof.repos repo
    JOIN paper_atproto_repo_proof.rdf_projection_jobs j ON j.account_id=repo.account_id AND j.did=repo.did
    JOIN paper_atproto_repo_proof.native_event_outbox e ON e.did=repo.did AND e.commit_cid=repo.head_cid
    JOIN paper_dataset_admin_proof.claims c ON c.reservation_id=p_reservation AND c.owner_webid=p_owner
    WHERE repo.did=p_did AND repo.account_id=p_owner AND repo.generation=1 AND j.generation=repo.generation
      AND (repo.head_cid,repo.root_cid,repo.rev)=(p_head,p_root,p_rev)
      AND (j.head_cid,j.root_cid,j.rev)=(p_head,p_root,p_rev) AND j.state='applied' AND j.lease_epoch=p_epoch
      AND e.rev=p_rev AND e.status IN ('pending','delivered') AND e.blocked_at IS NULL
      AND c.dataset=r.username AND c.state='created' FOR SHARE OF repo,j,e,c;
  IF NOT FOUND OR NOT EXISTS (SELECT 1 FROM paper_account_reservation_proof.read_provider_genesis(p_reservation,p_operation,p_did))
    OR NOT EXISTS (SELECT 1 FROM paper_account_reservation_proof.hosted_genesis_scope(p_did) h
      WHERE h.operation_id=p_operation AND h.reservation_id=p_reservation AND h.rdf_digest=s.provider_genesis_rdf_digest
        AND h.lease_epoch::bigint=p_epoch) THEN RETURN false; END IF;
  UPDATE paper_account_candidate.accounts SET state='ready',generation=generation+1,changed_at=clock_timestamp() WHERE account_id=a.account_id;
  UPDATE paper_account_candidate.signup_operations SET state='ready',generation=generation+1,changed_at=clock_timestamp(),
    completion_at=clock_timestamp(),completion_account_generation=a.generation+1,completion_app_uri=s.enrollment_app_uri,
    completion_proof_digest=s.evidence_digest WHERE operation_id=s.operation_id;
  UPDATE paper_account_reservation_proof.reservations SET state='completed',completed_at=clock_timestamp(),
    activitypub_actor_id=a.webid,atproto_did=a.atproto_did,atproto_pds_url=a.atproto_pds_url,evidence_hash=s.evidence_digest
    WHERE reservation_id=p_reservation;
  RETURN true;
EXCEPTION WHEN no_data_found THEN RETURN false;
END $$;
REVOKE ALL ON FUNCTION paper_private_auth.owner_ready(uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_private_auth.owner_ready(uuid,text,text) TO paper_private_auth_runtime;
REVOKE ALL ON FUNCTION paper_account_reservation_proof.activate_provider_owner(uuid,uuid,text,text,text,text,text,bigint) FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_account_reservation_proof TO paper_provider_owner_activator;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.activate_provider_owner(uuid,uuid,text,text,text,text,text,bigint)
  TO paper_provider_owner_activator;
COMMIT;

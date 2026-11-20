-- The loopback PDS can serve a verified signup genesis only after the
-- independent attestor committed its receipt for this exact PostgreSQL head.
BEGIN;
CREATE FUNCTION paper_account_reservation_proof.hosted_genesis_scope(p_did text)
RETURNS TABLE(reservation_id uuid,operation_id uuid,lease_epoch text,rdf_digest bytea,outbox_status text)
LANGUAGE sql STABLE STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT r.reservation_id,s.operation_id,j.lease_epoch::text,s.provider_genesis_rdf_digest,e.status
  FROM paper_atproto_repo_proof.repos repo
  JOIN paper_atproto_repo_proof.rdf_projection_jobs j ON j.account_id=repo.account_id
    AND (j.did,j.head_cid,j.root_cid,j.rev,j.generation)=(repo.did,repo.head_cid,repo.root_cid,repo.rev,repo.generation)
  JOIN paper_atproto_repo_proof.native_event_outbox e ON e.did=j.did AND e.commit_cid=j.head_cid AND e.rev=j.rev
  JOIN paper_account_candidate.accounts a ON a.atproto_did=repo.did AND a.webid=repo.account_id
  JOIN paper_account_candidate.signup_operations s ON s.account_id=a.account_id AND s.provider_id=a.provider_id
  JOIN paper_account_reservation_proof.reservations r ON r.expected_webid=a.webid AND r.v4_operation_id=s.operation_id
  WHERE repo.did=p_did AND j.state='applied' AND j.lease_epoch>0 AND e.blocked_at IS NULL
    AND a.state='provisioning' AND s.enrollment_state='consent_recorded' AND s.provider_genesis_lease IS NOT NULL
    AND s.provider_genesis_rdf_digest IS NOT NULL AND repo.generation=1;
$$;
REVOKE ALL ON FUNCTION paper_account_reservation_proof.hosted_genesis_scope(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.hosted_genesis_scope(text) TO paper_provider_genesis_reader;
COMMIT;

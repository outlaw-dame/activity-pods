-- Apply after the canonical reservation bridge and browser enrollment migration.
BEGIN;
CREATE ROLE paper_enrollment_handoff NOLOGIN NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS;

CREATE FUNCTION paper_account_reservation_proof.enrollment_handoff(
  p_reservation uuid, p_provider text, p_app text, p_username text, p_webid text
) RETURNS TABLE(account_id uuid, operation_id uuid, idempotency_hmac bytea, request_hmac bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT a.account_id, s.operation_id, s.idempotency_hmac, s.request_hmac
  FROM paper_account_reservation_proof.reservations r
  JOIN paper_account_candidate.signup_operations s
    ON s.operation_id=r.v4_operation_id AND s.account_id=r.v4_account_id
    AND s.provider_id=r.v4_provider_id AND s.app_client_id=r.v4_app_client_id
    AND s.hmac_key_version=r.v4_hmac_key_version
    AND s.idempotency_hmac=r.v4_idempotency_hmac AND s.request_hmac=r.v4_request_hmac
  JOIN paper_account_candidate.accounts a
    ON a.account_id=s.account_id AND a.provider_id=s.provider_id
  WHERE r.reservation_id=p_reservation AND r.v4_bound_at IS NOT NULL
    AND r.signup_claimed_at IS NOT NULL AND r.state='side_effects_started'
    AND r.expected_webid=p_webid AND r.username=p_username
    AND s.provider_id=p_provider AND s.app_client_id=p_app
    AND s.state='reconciliation_required' AND s.may_have_side_effects
    AND s.enrollment_state IS NULL
    AND a.state='reserved' AND a.generation=1 AND a.username_key=p_username;
$$;

REVOKE ALL ON FUNCTION paper_account_reservation_proof.enrollment_handoff(uuid,text,text,text,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_account_reservation_proof TO paper_enrollment_handoff;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.enrollment_handoff(uuid,text,text,text,text)
  TO paper_enrollment_handoff;
COMMIT;

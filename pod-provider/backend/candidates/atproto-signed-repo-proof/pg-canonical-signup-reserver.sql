-- Local-only coordinator integration. Existing account authority remains the
-- sole writer; this role can reserve/fence, never bind identities or complete.
BEGIN;
CREATE ROLE paper_account_signup_reserver NOLOGIN NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA paper_account_candidate TO paper_account_signup_reserver;
GRANT SELECT(account_id,username_key), INSERT(account_id,provider_id,username_key)
  ON paper_account_candidate.accounts TO paper_account_signup_reserver;
GRANT SELECT(operation_id,provider_id,account_id,app_client_id,hmac_key_version,
             idempotency_hmac,request_hmac,state,generation),
      INSERT(operation_id,provider_id,account_id,app_client_id,hmac_key_version,
             idempotency_hmac,request_hmac),
      UPDATE(state,may_have_side_effects,generation,changed_at)
  ON paper_account_candidate.signup_operations TO paper_account_signup_reserver;

-- Install only with the canonical coordinator. The old standalone proof
-- migrations deliberately remain usable without a canonical account journal.
CREATE FUNCTION paper_account_reservation_proof.canonical_signup_is_fenced(p_reservation uuid)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1 FROM paper_account_reservation_proof.reservations r
    JOIN paper_account_candidate.signup_operations o
      ON o.operation_id=r.v4_operation_id AND o.provider_id=r.v4_provider_id
      AND o.account_id=r.v4_account_id AND o.app_client_id=r.v4_app_client_id
      AND o.hmac_key_version=r.v4_hmac_key_version
      AND o.idempotency_hmac=r.v4_idempotency_hmac AND o.request_hmac=r.v4_request_hmac
    JOIN paper_account_candidate.accounts a
      ON a.account_id=o.account_id AND a.provider_id=o.provider_id
    WHERE r.reservation_id=p_reservation AND r.v4_bound_at IS NOT NULL
      AND o.state='reconciliation_required' AND o.may_have_side_effects
      AND a.state IN ('reserved','provisioning') AND a.username_key=r.username
      AND r.provider_id=o.provider_id||'/provider'
      AND r.expected_webid=o.provider_id||'/'||a.username_key
  );
$$;
REVOKE ALL ON FUNCTION paper_account_reservation_proof.canonical_signup_is_fenced(uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION paper_account_reservation_proof.claim_signup_once(
  p_provider text, p_app text, p_key_hash bytea, p_fingerprint bytea,
  p_reservation uuid, p_dataset text, p_webid text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE changed integer;
BEGIN
  IF p_provider IS NULL OR p_app IS NULL OR p_key_hash IS NULL OR
     p_fingerprint IS NULL OR octet_length(p_key_hash) <> 32 OR
     octet_length(p_fingerprint) <> 32 OR p_reservation IS NULL OR
     p_dataset IS NULL OR p_webid IS NULL THEN
    RETURN false;
  END IF;
  UPDATE paper_account_reservation_proof.reservations r
    SET signup_claimed_at = clock_timestamp()
    WHERE r.provider_id = p_provider AND r.app_client_id = p_app
      AND r.idempotency_hash = p_key_hash
      AND r.request_hash = p_fingerprint
      AND r.reservation_id = p_reservation
      AND r.username = p_dataset AND r.expected_webid = p_webid
      AND r.state = 'side_effects_started'
      AND paper_account_reservation_proof.canonical_signup_is_fenced(r.reservation_id)
      AND r.signup_claimed_at IS NULL
      AND r.lease_expires_at > clock_timestamp();
  GET DIAGNOSTICS changed = ROW_COUNT;
  RETURN changed = 1;
END;
$$;

CREATE OR REPLACE FUNCTION paper_account_reservation_proof.dataset_binding_is_live(
  p_provider text, p_app text, p_reservation uuid, p_fence uuid,
  p_dataset text, p_webid text
) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1 FROM paper_account_reservation_proof.reservations r
    WHERE r.provider_id = p_provider AND r.app_client_id = p_app
      AND r.reservation_id = p_reservation AND r.fence_token = p_fence
      AND r.username = p_dataset AND r.expected_webid = p_webid
      AND r.state = 'side_effects_started'
      AND paper_account_reservation_proof.canonical_signup_is_fenced(r.reservation_id)
      AND r.lease_expires_at > clock_timestamp()
  );
$$;

CREATE OR REPLACE FUNCTION paper_account_reservation_proof.dataset_claim_lease(
  p_provider text, p_app text, p_reservation uuid, p_fence uuid,
  p_dataset text, p_webid text
) RETURNS timestamptz
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT r.lease_expires_at FROM paper_account_reservation_proof.reservations r
  WHERE r.provider_id = p_provider AND r.app_client_id = p_app
    AND r.reservation_id = p_reservation AND r.fence_token = p_fence
    AND r.username = p_dataset AND r.expected_webid = p_webid
    AND r.state = 'side_effects_started'
      AND paper_account_reservation_proof.canonical_signup_is_fenced(r.reservation_id)
    AND r.lease_expires_at > clock_timestamp()
$$;
COMMIT;

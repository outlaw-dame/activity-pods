-- Disposable PostgreSQL 18 reservation authority for NEW ActivityPods accounts.
-- Never activate on production signup before verified issuer, WebID, SAI and PDS cutover.
-- Reservations and uniqueness fences are NOT automatically expired or deleted:
-- an RPC may have created a dataset, WebID or DID before losing its response.
BEGIN;
CREATE SCHEMA paper_account_reservation_proof;
REVOKE ALL ON SCHEMA paper_account_reservation_proof FROM PUBLIC;

CREATE TABLE paper_account_reservation_proof.reservations (
  provider_id text NOT NULL,
  app_client_id text NOT NULL,
  idempotency_hash bytea NOT NULL CHECK (octet_length(idempotency_hash) = 32),
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  username text NOT NULL CHECK (username ~ '^[a-z][a-z0-9_-]{1,31}$'),
  expected_webid text NOT NULL,
  reservation_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
  fence_token uuid NOT NULL DEFAULT gen_random_uuid(),
  state text NOT NULL DEFAULT 'reserved'
    CHECK (state IN ('reserved', 'side_effects_started', 'completed')),
  lease_expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  started_at timestamptz,
  completed_at timestamptz,
  activitypub_actor_id text,
  atproto_did text,
  atproto_pds_url text,
  evidence_hash bytea CHECK (evidence_hash IS NULL OR octet_length(evidence_hash) = 32),
  PRIMARY KEY (provider_id, app_client_id, idempotency_hash),
  UNIQUE (provider_id, username),
  UNIQUE (expected_webid),
  CHECK ((state = 'reserved') = (started_at IS NULL)),
  CHECK ((state = 'completed') = (completed_at IS NOT NULL)),
  CHECK ((state = 'completed') = (atproto_did IS NOT NULL)),
  CHECK ((state = 'completed') = (evidence_hash IS NOT NULL))
);
CREATE TABLE paper_account_reservation_proof.daily_usage (
  provider_id text NOT NULL,
  app_client_id text NOT NULL,
  usage_day date NOT NULL,
  reserved_count integer NOT NULL CHECK (reserved_count BETWEEN 1 AND 100000),
  PRIMARY KEY (provider_id, app_client_id, usage_day)
);
REVOKE ALL ON ALL TABLES IN SCHEMA paper_account_reservation_proof FROM PUBLIC;
CREATE ROLE paper_account_proof_worker NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE paper_account_proof_issuer NOLOGIN
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA paper_account_reservation_proof
  TO paper_account_proof_worker, paper_account_proof_issuer;

-- All mutation occurs in bounded, parameterized SECURITY DEFINER routines.
-- Only approved, independently verified callers may hold the restricted
-- worker login: SQL alone cannot authenticate an external app or user.
CREATE FUNCTION paper_account_reservation_proof.reserve(
  p_provider text, p_app text, p_key_hash bytea, p_request_hash bytea,
  p_username text, p_expected_webid text, p_daily_limit integer, p_lease_seconds integer
) RETURNS TABLE(outcome text, reservation_id uuid, fence_token uuid, lease_expires_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  existing paper_account_reservation_proof.reservations%ROWTYPE;
  inserted paper_account_reservation_proof.reservations%ROWTYPE;
  consumed integer;
BEGIN
  IF p_provider IS NULL OR length(p_provider) NOT BETWEEN 10 AND 256
     OR p_provider !~ '^https://[a-z0-9.-]+/[a-z0-9/_-]+$'
     OR p_app IS NULL OR p_app !~ '^[a-zA-Z0-9._:-]{1,128}$'
     OR octet_length(p_key_hash) <> 32 OR octet_length(p_request_hash) <> 32
     OR p_username IS NULL OR p_username !~ '^[a-z][a-z0-9_-]{1,31}$'
     OR p_expected_webid IS NULL OR length(p_expected_webid) > 512
     OR p_expected_webid !~ '^https://[a-z0-9.-]+/users/[a-z][a-z0-9_-]{1,31}$'
     OR right(p_expected_webid, length('/users/' || p_username)) <> '/users/' || p_username
     OR p_daily_limit NOT BETWEEN 1 AND 100000 OR p_lease_seconds NOT BETWEEN 1 AND 120
  THEN
    RAISE EXCEPTION 'Invalid account reservation request' USING ERRCODE = '22023';
  END IF;
  -- Serialize same-key requests across independent PostgreSQL sessions.
  -- A hash collision only reduces concurrency; it cannot grant admission.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    p_provider || ':' || p_app || ':' || encode(p_key_hash, 'hex'), 0));
  SELECT r.* INTO existing FROM paper_account_reservation_proof.reservations r
   WHERE r.provider_id = p_provider AND r.app_client_id = p_app
     AND r.idempotency_hash = p_key_hash;
  IF FOUND THEN
    IF existing.request_hash <> p_request_hash OR existing.username <> p_username
       OR existing.expected_webid <> p_expected_webid THEN
      RETURN QUERY SELECT 'idempotency_conflict'::text, NULL::uuid, NULL::uuid, NULL::timestamptz;
    ELSE
      -- Never return the original fence again. Lost ACKs need reconciliation,
      -- not an unbounded lease renewal or a second DID signer.
      RETURN QUERY SELECT
        CASE WHEN existing.state = 'completed' THEN 'completed'::text
             ELSE 'already_reserved'::text END,
        existing.reservation_id, NULL::uuid, existing.lease_expires_at;
    END IF;
    RETURN;
  END IF;

  BEGIN
    INSERT INTO paper_account_reservation_proof.daily_usage AS q
      (provider_id, app_client_id, usage_day, reserved_count)
      VALUES (p_provider, p_app, timezone('UTC', clock_timestamp())::date, 1)
      ON CONFLICT (provider_id, app_client_id, usage_day)
      DO UPDATE SET reserved_count = q.reserved_count + 1
        WHERE q.reserved_count < p_daily_limit
      RETURNING reserved_count INTO consumed;
    IF consumed IS NULL THEN
      RETURN QUERY SELECT 'quota_exceeded'::text, NULL::uuid, NULL::uuid, NULL::timestamptz;
      RETURN;
    END IF;
    INSERT INTO paper_account_reservation_proof.reservations
      (provider_id, app_client_id, idempotency_hash, request_hash,
       username, expected_webid, lease_expires_at)
      VALUES (p_provider, p_app, p_key_hash, p_request_hash, p_username,
              p_expected_webid, clock_timestamp() + make_interval(secs => p_lease_seconds))
      RETURNING * INTO inserted;
  EXCEPTION WHEN unique_violation THEN
    -- A competing request already owns the username or WebID. Rolling back
    -- this subtransaction also rolls back the quota increment.
    RETURN QUERY SELECT 'username_taken'::text, NULL::uuid, NULL::uuid, NULL::timestamptz;
    RETURN;
  END;
  RETURN QUERY SELECT 'reserved'::text, inserted.reservation_id,
    inserted.fence_token, inserted.lease_expires_at;
END;
$$;

CREATE FUNCTION paper_account_reservation_proof.start_side_effects(
  p_provider text, p_app text, p_key_hash bytea, p_reservation uuid, p_fence uuid
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE changed integer;
BEGIN
  UPDATE paper_account_reservation_proof.reservations r
    SET state = 'side_effects_started', started_at = clock_timestamp()
    WHERE r.provider_id = p_provider AND r.app_client_id = p_app
      AND r.idempotency_hash = p_key_hash AND r.reservation_id = p_reservation
      AND r.fence_token = p_fence AND r.state = 'reserved'
      AND r.lease_expires_at > clock_timestamp();
  GET DIAGNOSTICS changed = ROW_COUNT;
  RETURN changed = 1;
END;
$$;

CREATE FUNCTION paper_account_reservation_proof.complete(
  p_provider text, p_app text, p_key_hash bytea, p_reservation uuid, p_fence uuid,
  p_webid text, p_ap_actor text, p_did text, p_pds_url text, p_evidence bytea
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE changed integer;
BEGIN
  IF p_webid IS NULL OR p_ap_actor !~ '^https://'
     OR p_did !~ '^did:plc:[a-z2-7]{24}$'
     OR p_pds_url !~ '^https://'
     OR octet_length(p_evidence) <> 32 THEN
    RETURN false;
  END IF;
  UPDATE paper_account_reservation_proof.reservations r
    SET state = 'completed', completed_at = clock_timestamp(),
        activitypub_actor_id = p_ap_actor, atproto_did = p_did,
        atproto_pds_url = p_pds_url, evidence_hash = p_evidence
    WHERE r.provider_id = p_provider AND r.app_client_id = p_app
      AND r.idempotency_hash = p_key_hash AND r.reservation_id = p_reservation
      AND r.fence_token = p_fence AND r.state = 'side_effects_started'
      AND r.expected_webid = p_webid;
  GET DIAGNOSTICS changed = ROW_COUNT;
  RETURN changed = 1;
END;
$$;

-- Separate, least-privileged issuer credential. Claim signer must query the
-- authoritative reservation before issuing a short-lived dataset ticket.
-- No table enumeration, mutation or general-purpose SQL is delegated.
CREATE FUNCTION paper_account_reservation_proof.dataset_binding_is_live(
  p_provider text, p_app text, p_reservation uuid, p_fence uuid,
  p_dataset text, p_webid text
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1 FROM paper_account_reservation_proof.reservations r
    WHERE r.provider_id = p_provider AND r.app_client_id = p_app
      AND r.reservation_id = p_reservation AND r.fence_token = p_fence
      AND r.username = p_dataset AND r.expected_webid = p_webid
      AND r.state = 'side_effects_started'
      AND r.lease_expires_at > clock_timestamp()
  );
$$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA paper_account_reservation_proof FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.reserve(
  text, text, bytea, bytea, text, text, integer, integer
) TO paper_account_proof_worker;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.start_side_effects(
  text, text, bytea, uuid, uuid
) TO paper_account_proof_worker;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.complete(
  text, text, bytea, uuid, uuid, text, text, text, text, bytea
) TO paper_account_proof_worker;
GRANT EXECUTE ON FUNCTION paper_account_reservation_proof.dataset_binding_is_live(
  text, text, uuid, uuid, text, text
) TO paper_account_proof_issuer;
COMMIT;

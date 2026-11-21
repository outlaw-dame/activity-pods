-- Local integration only. Apply after account v1-v4. No production cutover.
-- Enrollment is attached to the existing signup operation, never a new account.
BEGIN;
ALTER TABLE paper_account_candidate.signup_operations
  ADD COLUMN enrollment_token_hash bytea,
  ADD COLUMN enrollment_csrf_hash bytea,
  ADD COLUMN enrollment_origin text,
  ADD COLUMN enrollment_app_uri text,
  ADD COLUMN enrollment_return_uri text,
  ADD COLUMN enrollment_requirements jsonb,
  ADD COLUMN enrollment_expires_at timestamptz,
  ADD COLUMN enrollment_state text,
  ADD COLUMN enrollment_selection jsonb,
  ADD COLUMN enrollment_registration_uri text,
  ADD CONSTRAINT enrollment_atomic CHECK (
    (enrollment_state IS NULL AND num_nonnulls(enrollment_token_hash,
      enrollment_csrf_hash,enrollment_origin,enrollment_app_uri,
      enrollment_return_uri,enrollment_requirements,enrollment_expires_at,
      enrollment_selection,enrollment_registration_uri)=0)
    OR
    (enrollment_state IS NOT NULL AND enrollment_state IN ('awaiting_consent','consent_claimed','consent_recorded','denied')
      AND num_nonnulls(enrollment_token_hash,enrollment_csrf_hash,enrollment_origin,
        enrollment_app_uri,enrollment_return_uri,enrollment_requirements,enrollment_expires_at)=7
      AND octet_length(enrollment_token_hash)=32 AND octet_length(enrollment_csrf_hash)=32
      AND length(enrollment_origin) BETWEEN 8 AND 2048
      AND length(enrollment_app_uri) BETWEEN 8 AND 2048
      AND length(enrollment_return_uri) BETWEEN 8 AND 2048
      AND jsonb_typeof(enrollment_requirements)='object'
      AND octet_length(enrollment_requirements::text)<=32768
      AND ((enrollment_state IN ('consent_claimed','consent_recorded')) = (enrollment_selection IS NOT NULL))
      AND ((enrollment_state='consent_recorded') = (enrollment_registration_uri IS NOT NULL)))
  );
-- The existing completion CAS must not be able to ignore a browser refusal
-- or an ambiguous native mutation. Its independent current-grant/PDS checks
-- still apply; this constraint alone never proves canonical completion.
ALTER TABLE paper_account_candidate.signup_operations
  ADD CONSTRAINT enrollment_completion_requires_consent CHECK (
    enrollment_state IS NULL OR state <> 'ready' OR
      (enrollment_state='consent_recorded' AND completion_app_uri=enrollment_app_uri)
  );
CREATE UNIQUE INDEX enrollment_token_unique
  ON paper_account_candidate.signup_operations(enrollment_token_hash)
  WHERE enrollment_token_hash IS NOT NULL;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_enrollment_runtime') THEN
    CREATE ROLE paper_enrollment_runtime NOLOGIN NOSUPERUSER NOCREATEDB
      NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END $$;
GRANT USAGE ON SCHEMA paper_account_candidate TO paper_enrollment_runtime;

CREATE FUNCTION paper_account_candidate.begin_enrollment(
  p_provider text,p_app text,p_operation uuid,p_key bytea,p_request bytea,
  p_token bytea,p_csrf bytea,p_origin text,p_app_uri text,p_return text,p_requirements jsonb
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE changed integer;
BEGIN
  IF p_token IS NULL OR octet_length(p_token)<>32 OR
     p_csrf IS NULL OR octet_length(p_csrf)<>32 OR
     p_origin IS NULL OR p_origin NOT LIKE 'https://%' OR
     p_app_uri IS NULL OR p_app_uri NOT LIKE 'https://%' OR
     p_return IS NULL OR p_return NOT LIKE 'https://%' OR
     p_requirements IS NULL OR jsonb_typeof(p_requirements)<>'object' THEN RETURN false; END IF;
  UPDATE paper_account_candidate.signup_operations s SET
    enrollment_token_hash=p_token,enrollment_csrf_hash=p_csrf,
    enrollment_origin=p_origin,enrollment_app_uri=p_app_uri,enrollment_return_uri=p_return,
    enrollment_requirements=p_requirements,enrollment_expires_at=clock_timestamp()+interval '10 minutes',
    enrollment_state='awaiting_consent'
  FROM paper_account_candidate.accounts a
  WHERE s.operation_id=p_operation AND s.provider_id=p_provider AND s.app_client_id=p_app
    AND s.idempotency_hmac=p_key AND s.request_hmac=p_request
    AND s.state='reconciliation_required' AND s.may_have_side_effects
    AND s.enrollment_state IS NULL
    AND a.provider_id=s.provider_id AND a.account_id=s.account_id
    AND a.state='provisioning' AND a.webid IS NOT NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

CREATE FUNCTION paper_account_candidate.read_enrollment(p_provider text,p_token bytea,p_origin text)
RETURNS TABLE(operation_id uuid,app_client_id text,webid text,username text,app_uri text,return_uri text,
  requirements jsonb,enrollment_state text,selection jsonb,registration_uri text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
  SELECT s.operation_id,s.app_client_id,a.webid,a.username_key,s.enrollment_app_uri,s.enrollment_return_uri,
    s.enrollment_requirements,CASE WHEN s.state='ready' THEN 'owner_ready' ELSE s.enrollment_state END,s.enrollment_selection,s.enrollment_registration_uri
  FROM paper_account_candidate.signup_operations s
  JOIN paper_account_candidate.accounts a ON a.provider_id=s.provider_id AND a.account_id=s.account_id
  WHERE s.provider_id=p_provider AND s.enrollment_token_hash=p_token
    AND s.enrollment_origin=p_origin AND s.enrollment_expires_at>statement_timestamp()
    AND ((s.state IN ('reconciliation_required','evidence_sealed') AND a.state='provisioning')
      OR (s.state='ready' AND a.state='ready' AND s.completion_grant_uri IS NULL
        AND s.enrollment_state='consent_recorded' AND s.completion_account_generation=a.generation));
$$;

-- Claim BEFORE any native SAI mutation. A timeout/crash never resets this state.
-- Returning false is not permission to retry registerApp with another token.
CREATE FUNCTION paper_account_candidate.claim_enrollment_consent(
  p_provider text,p_token bytea,p_csrf bytea,p_origin text,p_approve boolean,p_selection jsonb
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE changed integer;
BEGIN
  IF p_approve IS NULL OR (p_approve AND (p_selection IS NULL OR
      jsonb_typeof(p_selection)<>'object' OR octet_length(p_selection::text)>32768))
      OR (NOT p_approve AND p_selection IS NOT NULL) THEN RETURN false; END IF;
  UPDATE paper_account_candidate.signup_operations s SET
    enrollment_state=CASE WHEN p_approve THEN 'consent_claimed' ELSE 'denied' END,
    enrollment_selection=p_selection
  FROM paper_account_candidate.accounts a
  WHERE s.provider_id=p_provider AND s.enrollment_token_hash=p_token
    AND s.enrollment_csrf_hash=p_csrf AND s.enrollment_origin=p_origin
    AND s.enrollment_expires_at>clock_timestamp() AND s.enrollment_state='awaiting_consent'
    AND s.state IN ('reconciliation_required','evidence_sealed')
    AND a.provider_id=s.provider_id AND a.account_id=s.account_id AND a.state='provisioning';
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

-- Internal receipt only, not an attestation, completion CAS or login permit.
CREATE FUNCTION paper_account_candidate.record_enrollment_consent(
  p_provider text,p_token bytea,p_origin text,p_registration text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE changed integer;
BEGIN
  IF p_registration IS NULL OR length(p_registration) NOT BETWEEN 8 AND 2048 OR p_registration NOT LIKE 'https://%'
    THEN RETURN false; END IF;
  UPDATE paper_account_candidate.signup_operations SET
    enrollment_state='consent_recorded',enrollment_registration_uri=p_registration
  WHERE provider_id=p_provider AND enrollment_token_hash=p_token AND enrollment_origin=p_origin
    AND enrollment_state='consent_claimed';
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END $$;

REVOKE ALL ON FUNCTION paper_account_candidate.begin_enrollment(text,text,uuid,bytea,bytea,bytea,bytea,text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_account_candidate.read_enrollment(text,bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_account_candidate.claim_enrollment_consent(text,bytea,bytea,text,boolean,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_account_candidate.record_enrollment_consent(text,bytea,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_account_candidate.begin_enrollment(text,text,uuid,bytea,bytea,bytea,bytea,text,text,text,jsonb),
  paper_account_candidate.read_enrollment(text,bytea,text),
  paper_account_candidate.claim_enrollment_consent(text,bytea,bytea,text,boolean,jsonb),
  paper_account_candidate.record_enrollment_consent(text,bytea,text,text) TO paper_enrollment_runtime;
COMMIT;

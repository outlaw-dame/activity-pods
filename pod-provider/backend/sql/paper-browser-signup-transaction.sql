-- Disposable provider browser signup. The trusted verifier binds a signed
-- request to a browser session before identity creation. No passwords,
-- plaintext verification proofs, app bearer credentials or raw cookies are persisted.
BEGIN;
CREATE SCHEMA paper_browser_signup;
REVOKE ALL ON SCHEMA paper_browser_signup FROM PUBLIC;
CREATE ROLE paper_browser_signup_verifier NOLOGIN;
CREATE ROLE paper_browser_signup_redeemer NOLOGIN;
CREATE TABLE paper_browser_signup.transactions (
  session_hash bytea PRIMARY KEY CHECK (octet_length(session_hash)=32),
  provider_id text NOT NULL,
  app_client_id text NOT NULL,
  browser_origin text NOT NULL,
  return_uri text NOT NULL,
  idempotency_key uuid NOT NULL,
  request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint)=32),
  proof_hash bytea NOT NULL UNIQUE CHECK (octet_length(proof_hash)=32),
  sealed_proof bytea CHECK (octet_length(sealed_proof) BETWEEN 29 AND 1600),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  UNIQUE(provider_id,app_client_id,idempotency_key)
);
CREATE INDEX browser_signup_expiry ON paper_browser_signup.transactions(expires_at);
CREATE FUNCTION paper_browser_signup.bind_verified(
  session_digest bytea, provider text, app text, origin text, callback text,
  request_key uuid, fingerprint bytea, proof_digest bytea, ciphertext bytea, expiry timestamptz
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
  IF ciphertext IS NULL OR expiry IS NULL OR NOT (expiry > clock_timestamp() AND expiry <= clock_timestamp()+interval '2 minutes')
    OR EXISTS (SELECT FROM unnest(ARRAY[provider,app,origin,callback]) AS u(v)
               WHERE v IS NULL OR length(v)>2048 OR v !~ '^https://[^[:space:]]+$') THEN RETURN false; END IF;
  -- Admission bounds opportunistic expiry cleanup per verified request.
  -- Contending workers may skip rows already being cleaned.
  DELETE FROM paper_browser_signup.transactions WHERE session_hash IN (
    SELECT t.session_hash FROM paper_browser_signup.transactions t
    WHERE t.expires_at <= clock_timestamp() ORDER BY t.expires_at LIMIT 16 FOR UPDATE SKIP LOCKED
  );
  INSERT INTO paper_browser_signup.transactions
    (session_hash,provider_id,app_client_id,browser_origin,return_uri,idempotency_key,request_fingerprint,proof_hash,sealed_proof,expires_at)
    VALUES(session_digest,provider,app,origin,callback,request_key,fingerprint,proof_digest,ciphertext,expiry)
    ON CONFLICT DO NOTHING;
  RETURN FOUND;
END $$;
CREATE FUNCTION paper_browser_signup.consume_verified(
  session_digest bytea, provider text, app text, origin text, callback text,
  fingerprint bytea
) RETURNS TABLE(bound_key uuid,proof bytea) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE ciphertext bytea;
BEGIN
  SELECT idempotency_key,sealed_proof INTO bound_key,ciphertext FROM paper_browser_signup.transactions
    WHERE session_hash=session_digest AND provider_id=provider AND app_client_id=app
      AND browser_origin=origin AND return_uri=callback
      AND request_fingerprint=fingerprint
      AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  UPDATE paper_browser_signup.transactions SET consumed_at=clock_timestamp(),sealed_proof=NULL
    WHERE session_hash=session_digest AND expires_at>clock_timestamp();
  IF NOT FOUND THEN RETURN; END IF;
  proof := ciphertext;
  RETURN NEXT;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA paper_browser_signup FROM PUBLIC;
GRANT USAGE ON SCHEMA paper_browser_signup TO paper_browser_signup_verifier,paper_browser_signup_redeemer;
GRANT EXECUTE ON FUNCTION paper_browser_signup.bind_verified(bytea,text,text,text,text,uuid,bytea,bytea,bytea,timestamptz)
  TO paper_browser_signup_verifier;
GRANT EXECUTE ON FUNCTION paper_browser_signup.consume_verified(bytea,text,text,text,text,bytea)
  TO paper_browser_signup_redeemer;
COMMIT;

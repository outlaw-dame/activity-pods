\set ON_ERROR_STOP on
-- Run against a fresh disposable database after lifecycle candidate v1.
DO $$
DECLARE
  op uuid := '00000000-0000-4000-8000-000000000001';
  lease uuid := '00000000-0000-4000-8000-000000000002';
  duplicate_rejected boolean := false;
  invalid_completion_rejected boolean := false;
BEGIN
  INSERT INTO paper_account_candidate.operations (
    operation_id, provider_id, app_client_id, idempotency_digest,
    request_digest, username_key, verified_email_hmac, lease_token,
    lease_expires_at
  ) VALUES (
    op, 'provider-a', 'https://client.example',
    decode(repeat('11',32),'hex'), decode(repeat('22',32),'hex'),
    'alice', decode(repeat('33',32),'hex'), lease, clock_timestamp() + interval '10 minutes'
  );
  BEGIN
    INSERT INTO paper_account_candidate.operations (
      operation_id, provider_id, app_client_id, idempotency_digest,
      request_digest, username_key, lease_token, lease_expires_at
    ) VALUES (
      '00000000-0000-4000-8000-000000000003',
      'provider-a', 'https://client.example', decode(repeat('11',32),'hex'),
      decode(repeat('44',32),'hex'), 'bob',
      '00000000-0000-4000-8000-000000000004', clock_timestamp() + interval '1 minute'
    );
  EXCEPTION WHEN unique_violation THEN duplicate_rejected := true;
  END;
  IF NOT duplicate_rejected THEN RAISE EXCEPTION 'idempotency uniqueness not enforced'; END IF;
  duplicate_rejected := false;
  BEGIN
    INSERT INTO paper_account_candidate.operations (
      operation_id, provider_id, app_client_id, idempotency_digest,
      request_digest, username_key, lease_token, lease_expires_at
    ) VALUES (
      '00000000-0000-4000-8000-000000000005',
      'provider-a', 'https://other.example', decode(repeat('55',32),'hex'),
      decode(repeat('66',32),'hex'), 'alice',
      '00000000-0000-4000-8000-000000000006', clock_timestamp() + interval '1 minute'
    );
  EXCEPTION WHEN unique_violation THEN duplicate_rejected := true;
  END;
  IF NOT duplicate_rejected THEN RAISE EXCEPTION 'provider username uniqueness not enforced'; END IF;
  BEGIN
    UPDATE paper_account_candidate.operations SET
      state='completed', canonical_webid='https://pods.example/alice',
      activitypub_actor_id='https://pods.example/alice',
      atproto_did='did:plc:abcdefghijklmnopqrstuvwx',
      pds_repo_root_cid='bafyreigenesisplaceholder', pds_repo_rev='0',
      signed_repo_proof_digest=decode(repeat('77',32),'hex')
    WHERE operation_id=op;
  EXCEPTION WHEN check_violation THEN invalid_completion_rejected := true;
  END;
  IF NOT invalid_completion_rejected THEN RAISE EXCEPTION 'placeholder repo was incorrectly completed'; END IF;
  UPDATE paper_account_candidate.operations SET
    state='account_created', canonical_webid='https://pods.example/alice',
    activitypub_actor_id='https://pods.example/alice',
    version=version+1 WHERE operation_id=op AND lease_token=lease;
  IF NOT FOUND THEN RAISE EXCEPTION 'could not advance account lifecycle'; END IF;
  UPDATE paper_account_candidate.operations SET
    state='identities_ready',
    atproto_did='did:plc:abcdefghijklmnopqrstuvwx',
    pds_repo_root_cid='bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    pds_repo_rev='3kskdumj2wv',
    signed_repo_proof_digest=decode(repeat('77',32),'hex'),
    version=version+1
  WHERE operation_id=op AND state='account_created' AND lease_token=lease;
  IF NOT FOUND THEN RAISE EXCEPTION 'could not advance identity lifecycle'; END IF;
  UPDATE paper_account_candidate.operations SET state='completed', version=version+1
  WHERE operation_id=op AND state='identities_ready' AND lease_token=lease;
  IF NOT FOUND THEN RAISE EXCEPTION 'could not advance verified completion'; END IF;
  IF (SELECT state FROM paper_account_candidate.operations WHERE operation_id=op) <> 'completed'
  THEN RAISE EXCEPTION 'terminal state not durable'; END IF;
END $$;
SELECT 'account_postgres_candidate_sql_passed' AS result;

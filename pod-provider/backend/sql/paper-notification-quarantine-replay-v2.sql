-- Restricted operator replay, additive to paper-canonical-notification-ledger-v1.sql.
-- Execute as migration owner. Never give an HTTP or generic Moleculer login
-- the replay-only role, and never attach this function to a public API.
CREATE TABLE IF NOT EXISTS paper_notification_ledger.quarantine_replays (
  operation_id uuid PRIMARY KEY,
  intent_key bytea NOT NULL,
  recipient_key bytea NOT NULL,
  operator_login name NOT NULL,
  previous_attempts integer NOT NULL CHECK (previous_attempts BETWEEN 1 AND 8),
  replayed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY (intent_key,recipient_key)
    REFERENCES paper_notification_ledger.quarantine(intent_key,recipient_key)
);
CREATE INDEX IF NOT EXISTS paper_notification_replays_per_recipient
  ON paper_notification_ledger.quarantine_replays(intent_key,recipient_key);
REVOKE ALL ON paper_notification_ledger.quarantine_replays FROM PUBLIC;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='paper_notification_replay_operator') THEN
    CREATE ROLE paper_notification_replay_operator NOLOGIN NOSUPERUSER
      NOCREATEDB NOCREATEROLE NOREPLICATION;
  END IF;
END $roles$;
GRANT USAGE ON SCHEMA paper_notification_ledger
  TO paper_notification_replay_operator;

-- The authenticated PostgreSQL session_user, not a request body or ctx.meta,
-- is the only operator identity recorded in the audit.
CREATE OR REPLACE FUNCTION paper_notification_ledger.replay_dead_notification(
  p_intent_key bytea, p_recipient_key bytea, p_operation_id uuid)
RETURNS TABLE (was_replayed boolean, replay_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $replay$
DECLARE
  current_state text;
  current_attempts integer;
  replayed_intent bytea;
  replayed_recipient bytea;
  previous_count integer;
BEGIN
  IF p_intent_key IS NULL OR octet_length(p_intent_key) <> 32 OR
     p_recipient_key IS NULL OR octet_length(p_recipient_key) <> 32 OR
     p_operation_id IS NULL THEN
    RAISE EXCEPTION 'NOTIFICATION_REPLAY_INVALID_INPUT' USING ERRCODE='22023';
  END IF;
  -- Lock a single recipient only. Concurrent replays for the same recipient
  -- serialize in PostgreSQL; other recipients remain independent.
  SELECT d.state, d.attempts INTO current_state,current_attempts
  FROM paper_notification_ledger.deliveries AS d
  WHERE d.intent_key=p_intent_key AND d.recipient_key=p_recipient_key
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'NOTIFICATION_REPLAY_NOT_FOUND' USING ERRCODE='P0001';
  END IF;

  SELECT r.intent_key,r.recipient_key INTO replayed_intent,replayed_recipient
  FROM paper_notification_ledger.quarantine_replays AS r
  WHERE r.operation_id=p_operation_id;
  IF FOUND THEN
    IF replayed_intent<>p_intent_key OR replayed_recipient<>p_recipient_key THEN
      RAISE EXCEPTION 'NOTIFICATION_REPLAY_OPERATION_COLLISION' USING ERRCODE='P0001';
    END IF;
    SELECT count(*)::integer INTO previous_count
    FROM paper_notification_ledger.quarantine_replays AS r
    WHERE r.intent_key=p_intent_key AND r.recipient_key=p_recipient_key;
    RETURN QUERY SELECT false,previous_count;
    RETURN;
  END IF;

  IF current_state<>'dead' OR current_attempts<>8 OR
     NOT EXISTS (
       SELECT 1 FROM paper_notification_ledger.quarantine AS q
       WHERE q.intent_key=p_intent_key AND q.recipient_key=p_recipient_key
     ) THEN
    RAISE EXCEPTION 'NOTIFICATION_REPLAY_NOT_QUARANTINED' USING ERRCODE='P0001';
  END IF;
  SELECT count(*)::integer INTO previous_count
  FROM paper_notification_ledger.quarantine_replays AS r
  WHERE r.intent_key=p_intent_key AND r.recipient_key=p_recipient_key;
  IF previous_count >= 3 THEN
    RAISE EXCEPTION 'NOTIFICATION_REPLAY_LIMIT' USING ERRCODE='P0001';
  END IF;

  INSERT INTO paper_notification_ledger.quarantine_replays
    (operation_id,intent_key,recipient_key,operator_login,previous_attempts)
  VALUES (p_operation_id,p_intent_key,p_recipient_key,session_user,current_attempts);
  UPDATE paper_notification_ledger.deliveries
  SET state='pending', attempts=0, next_attempt_at=clock_timestamp(),
      lease_token=NULL, lease_until=NULL
  WHERE intent_key=p_intent_key AND recipient_key=p_recipient_key
    AND state='dead' AND attempts=8;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'NOTIFICATION_REPLAY_STATE_CHANGED' USING ERRCODE='P0001';
  END IF;
  RETURN QUERY SELECT true,previous_count+1;
END;
$replay$;
REVOKE ALL ON FUNCTION paper_notification_ledger.replay_dead_notification(bytea,bytea,uuid)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  paper_notification_ledger.replay_dead_notification(bytea,bytea,uuid)
  TO paper_notification_replay_operator;
-- The existing app runtime role does not receive execution or replay-history
-- mutation grants. Run replay only through a separately authenticated DB
-- operator using a fresh UUID operation ID, with change-ticket approval.

-- NONACTIVATED / INDEPENDENT PostgreSQL 18 WITNESS DATABASE ONLY.
-- Do NOT apply on the canonical Account/PDS PG cluster or its backup domain.
-- Deploy on a separately controlled cluster and back up with its own policy.
-- State transitions are DENIED until an independent WORM receipt attestor
-- confirms exact event digest via immutable object readback (eg locked R2).
-- A witness restore is itself a hard stop until WORM replay catches up.
BEGIN;
CREATE SCHEMA paper_oauth_restore_witness;
REVOKE ALL ON SCHEMA paper_oauth_restore_witness FROM PUBLIC;

CREATE TABLE paper_oauth_restore_witness.current_epochs (
  owner_webid text NOT NULL CHECK (length(owner_webid) BETWEEN 8 AND 2048 AND owner_webid LIKE 'https://%'),
  client_id text NOT NULL CHECK (length(client_id) BETWEEN 8 AND 2048 AND client_id LIKE 'https://%'),
  revision bigint NOT NULL CHECK (revision > 0),
  state text NOT NULL CHECK (state IN ('active','blocked')),
  grant_sha256 bytea NOT NULL CHECK (octet_length(grant_sha256)=32),
  operation_id uuid NOT NULL UNIQUE,
  event_sha256 bytea NOT NULL CHECK (octet_length(event_sha256)=32),
  sealed boolean NOT NULL DEFAULT false,
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(owner_webid,client_id)
);

CREATE TABLE paper_oauth_restore_witness.events (
  owner_webid text NOT NULL,
  client_id text NOT NULL,
  revision bigint NOT NULL CHECK (revision>0),
  state text NOT NULL CHECK (state IN ('active','blocked')),
  grant_sha256 bytea NOT NULL CHECK (octet_length(grant_sha256)=32),
  operation_id uuid NOT NULL UNIQUE,
  prev_event_sha256 bytea NOT NULL CHECK (octet_length(prev_event_sha256)=32),
  event_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(event_sha256)=32),
  sealed_at timestamptz,
  PRIMARY KEY(owner_webid,client_id,revision)
);
CREATE UNIQUE INDEX witness_active_grant_once
  ON paper_oauth_restore_witness.events(owner_webid,client_id,grant_sha256)
  WHERE state='active';
REVOKE ALL ON ALL TABLES IN SCHEMA paper_oauth_restore_witness FROM PUBLIC;

DO $roles$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paper_oauth_witness_issuer') THEN
  CREATE ROLE paper_oauth_witness_issuer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paper_oauth_witness_revoker') THEN
  CREATE ROLE paper_oauth_witness_revoker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paper_oauth_witness_attestor') THEN
  CREATE ROLE paper_oauth_witness_attestor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='paper_oauth_witness_reader') THEN
  CREATE ROLE paper_oauth_witness_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
END $roles$;
GRANT USAGE ON SCHEMA paper_oauth_restore_witness TO
 paper_oauth_witness_issuer,paper_oauth_witness_revoker,
 paper_oauth_witness_attestor,paper_oauth_witness_reader;

-- Only function-owner internal entry point. No runtime LOGIN can EXECUTE it.
-- If the WORM store is unavailable the record remains UNSEALED and cannot
-- authorize access tokens or signed PDS writes. No automatic timeout unlock.
CREATE FUNCTION paper_oauth_restore_witness.append_event(
 p_owner text,p_client text,p_grant_hash bytea,p_expected bigint,
 p_operation uuid,p_state text
) RETURNS bigint
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE prior record; next_revision bigint; previous_hash bytea;
        hash bytea; changed bigint;
BEGIN
 IF p_owner NOT LIKE 'https://%' OR p_client NOT LIKE 'https://%' OR
    length(p_owner) NOT BETWEEN 8 AND 2048 OR
    length(p_client) NOT BETWEEN 8 AND 2048 OR
    octet_length(p_grant_hash)<>32 OR
    p_expected<0 OR p_expected>=9223372036854775807 OR
    p_state NOT IN ('active','blocked')
 THEN RETURN 0; END IF;
 SELECT revision,state,grant_sha256,operation_id,event_sha256,sealed
 INTO prior FROM paper_oauth_restore_witness.current_epochs
 WHERE owner_webid=p_owner AND client_id=p_client FOR UPDATE;
 IF FOUND THEN
   IF prior.operation_id=p_operation THEN
     -- Lost ACK is idempotent only for an identical CURRENT event. It
     -- cannot report success for an earlier operation after newer revoke.
     IF prior.revision=p_expected+1 AND prior.state=p_state AND
        prior.grant_sha256=p_grant_hash THEN RETURN prior.revision; END IF;
     RETURN 0;
   END IF;
   IF prior.revision<>p_expected OR
      -- Do not advance past a transition not yet checked against WORM.
      prior.sealed=false OR
      (p_state='blocked' AND
        (prior.state<>'active' OR prior.grant_sha256<>p_grant_hash)) OR
      (p_state='active' AND prior.grant_sha256=p_grant_hash)
   THEN RETURN 0; END IF;
   previous_hash=prior.event_sha256;
 ELSE
   IF p_expected<>0 OR p_state<>'active' THEN RETURN 0; END IF;
   previous_hash=decode(repeat('00',32),'hex');
 END IF;
 -- Never reuse an earlier active grant digest, even after its revoke:
 -- a restored token with that grant ID must never become current again.
 IF p_state='active' AND EXISTS(
  SELECT 1 FROM paper_oauth_restore_witness.events e
  WHERE e.owner_webid=p_owner AND e.client_id=p_client
   AND e.grant_sha256=p_grant_hash AND e.state='active'
 ) THEN RETURN 0; END IF;
 next_revision=p_expected+1;
 hash=sha256(
   convert_to('paper:witness:epoch:v1:'||p_owner||':'||p_client||':'||
     next_revision::text||':'||p_state||':'||p_operation::text,'UTF8')
   ||p_grant_hash||previous_hash
 );
 IF p_expected=0 THEN
   INSERT INTO paper_oauth_restore_witness.current_epochs
     (owner_webid,client_id,revision,state,grant_sha256,operation_id,event_sha256)
   VALUES(p_owner,p_client,1,p_state,p_grant_hash,p_operation,hash)
   ON CONFLICT DO NOTHING RETURNING revision INTO changed;
 ELSE
   UPDATE paper_oauth_restore_witness.current_epochs SET
     revision=next_revision,state=p_state,grant_sha256=p_grant_hash,
     operation_id=p_operation,event_sha256=hash,sealed=false,
     changed_at=clock_timestamp()
   WHERE owner_webid=p_owner AND client_id=p_client AND revision=p_expected
   RETURNING revision INTO changed;
 END IF;
 IF changed IS NULL THEN RETURN 0; END IF;
 -- Same SQL transaction: any unique-op or replay error rolls back current.
 INSERT INTO paper_oauth_restore_witness.events
   (owner_webid,client_id,revision,state,grant_sha256,operation_id,
    prev_event_sha256,event_sha256)
 VALUES(p_owner,p_client,next_revision,p_state,p_grant_hash,p_operation,
        previous_hash,hash);
 RETURN changed;
END $fn$;

CREATE FUNCTION paper_oauth_restore_witness.issue(
 p_owner text,p_client text,p_grant_hash bytea,p_expected bigint,p_operation uuid
) RETURNS bigint
LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT paper_oauth_restore_witness.append_event(
   p_owner,p_client,p_grant_hash,p_expected,p_operation,'active');
$fn$;

CREATE FUNCTION paper_oauth_restore_witness.block(
 p_owner text,p_client text,p_grant_hash bytea,p_expected bigint,p_operation uuid
) RETURNS bigint
LANGUAGE sql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT paper_oauth_restore_witness.append_event(
   p_owner,p_client,p_grant_hash,p_expected,p_operation,'blocked');
$fn$;

-- WORM receipt verification occurs OUTSIDE the cluster using an isolated
-- attestor principal. Seal only the exact immutable event ID + hash after
-- independent object readback; never accept client-supplied "sealed" claims.
CREATE FUNCTION paper_oauth_restore_witness.seal(
 p_owner text,p_client text,p_revision bigint,p_operation uuid,
 p_event_hash bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET lock_timeout='2s' AS $fn$
DECLARE updated integer;
BEGIN
 IF p_event_hash IS NULL OR octet_length(p_event_hash)<>32 THEN RETURN false; END IF;
 UPDATE paper_oauth_restore_witness.current_epochs c SET sealed=true
 WHERE c.owner_webid=p_owner AND c.client_id=p_client
   AND c.revision=p_revision AND c.operation_id=p_operation
   AND c.event_sha256=p_event_hash AND c.sealed=false;
 GET DIAGNOSTICS updated=ROW_COUNT;
 IF updated=1 THEN
   UPDATE paper_oauth_restore_witness.events e SET sealed_at=clock_timestamp()
   WHERE e.owner_webid=p_owner AND e.client_id=p_client
     AND e.revision=p_revision AND e.operation_id=p_operation
     AND e.event_sha256=p_event_hash AND e.sealed_at IS NULL;
   RETURN true;
 END IF;
 RETURN EXISTS(
   SELECT 1 FROM paper_oauth_restore_witness.current_epochs c
   JOIN paper_oauth_restore_witness.events e
     ON e.owner_webid=c.owner_webid AND e.client_id=c.client_id
     AND e.revision=c.revision AND e.event_sha256=c.event_sha256
   WHERE c.owner_webid=p_owner AND c.client_id=p_client
     AND c.revision=p_revision AND c.operation_id=p_operation
     AND c.event_sha256=p_event_hash AND c.sealed=true
     AND e.sealed_at IS NOT NULL
 );
END $fn$;

CREATE FUNCTION paper_oauth_restore_witness.verify(
 p_owner text,p_client text,p_grant_hash bytea,p_revision bigint
) RETURNS boolean
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT EXISTS(
   SELECT 1 FROM paper_oauth_restore_witness.current_epochs c
   JOIN paper_oauth_restore_witness.events e
     ON e.owner_webid=c.owner_webid AND e.client_id=c.client_id
     AND e.revision=c.revision AND e.event_sha256=c.event_sha256
   WHERE c.owner_webid=p_owner AND c.client_id=p_client
     AND c.revision=p_revision AND c.grant_sha256=p_grant_hash
     AND c.state='active' AND c.sealed=true AND e.sealed_at IS NOT NULL
 );
$fn$;

-- The isolated WORM attestor may read only this exact event digest, not
-- grant-table secrets or account journal content.
CREATE FUNCTION paper_oauth_restore_witness.get_unsealed_receipt(
 p_owner text,p_client text,p_revision bigint,p_operation uuid
) RETURNS bytea
LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $fn$
 SELECT c.event_sha256 FROM paper_oauth_restore_witness.current_epochs c
 WHERE c.owner_webid=p_owner AND c.client_id=p_client
   AND c.revision=p_revision AND c.operation_id=p_operation
   AND c.sealed=false;
$fn$;

REVOKE ALL ON FUNCTION paper_oauth_restore_witness.append_event(
 text,text,bytea,bigint,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.issue(
 text,text,bytea,bigint,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.block(
 text,text,bytea,bigint,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.seal(
 text,text,bigint,uuid,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.verify(
 text,text,bytea,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION paper_oauth_restore_witness.get_unsealed_receipt(
 text,text,bigint,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.issue(
 text,text,bytea,bigint,uuid) TO paper_oauth_witness_issuer;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.block(
 text,text,bytea,bigint,uuid) TO paper_oauth_witness_revoker;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.seal(
 text,text,bigint,uuid,bytea),
 paper_oauth_restore_witness.get_unsealed_receipt(
 text,text,bigint,uuid) TO paper_oauth_witness_attestor;
GRANT EXECUTE ON FUNCTION paper_oauth_restore_witness.verify(
 text,text,bytea,bigint) TO paper_oauth_witness_reader;
COMMIT;

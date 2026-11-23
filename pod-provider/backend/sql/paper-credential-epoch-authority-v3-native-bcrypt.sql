-- NONACTIVATED disposable PostgreSQL18 integration, after:
-- paper-local-native-auth.sql,
-- paper-credential-epoch-authority-v1.sql and
-- paper-credential-epoch-authority-v2-certified-head.sql.
-- Never auto-migrate by production services or enable signup on this proof.
-- The native account store's generic UPDATE(data), INSERT and DELETE rights
-- must not bypass revocation or replace a tracked unified owner.
BEGIN;
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='paper_credential_native_writer') THEN
    CREATE ROLE paper_credential_native_writer NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='paper_credential_native_attestor') THEN
    CREATE ROLE paper_credential_native_attestor NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                 WHERE rolname='paper_credential_native_sealer') THEN
    CREATE ROLE paper_credential_native_sealer NOLOGIN NOINHERIT;
  END IF;
END
$roles$;
GRANT USAGE ON SCHEMA paper_credential_epoch TO
  paper_credential_native_writer,
  paper_credential_native_attestor,
  paper_credential_native_sealer;

CREATE TABLE paper_credential_epoch.native_writes (
  operation_id uuid PRIMARY KEY,
  webid text NOT NULL REFERENCES paper_credential_epoch.owners(webid),
  following_epoch bigint NOT NULL CHECK(following_epoch > 1),
  old_hash_sha256 bytea NOT NULL CHECK(octet_length(old_hash_sha256)=32),
  new_hash_sha256 bytea NOT NULL CHECK(octet_length(new_hash_sha256)=32),
  receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
  writing_xid xid8 NOT NULL,
  written_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(webid,following_epoch)
);
REVOKE ALL ON paper_credential_epoch.native_writes FROM PUBLIC;
REVOKE ALL ON paper_credential_epoch.native_writes FROM
  paper_credential_reader, paper_credential_coordinator,
  paper_credential_enroller, paper_private_auth_runtime;

-- Generic SemApps accounts UPDATE(data) is retained for NONcredential
-- preferences. The PostgreSQL trigger enforces the boundary even if an
-- untrusted adapter or action tries a direct bcrypt update. A writer must
-- first atomically record an op-specific receipt in THIS transaction.
CREATE FUNCTION paper_credential_epoch.guard_native_account()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog AS $guard$
BEGIN
  IF TG_OP='UPDATE' THEN
    -- An enrolled owner remains enrolled even if a physically restored
    -- SemApps JSONB record loses its marker. The independent PG owner table
    -- is authoritative for the local classification, not caller-controlled
    -- account JSON or an old database snapshot of that JSON.
    IF NOT (OLD.data ? 'signupReservationId') AND EXISTS (
      SELECT 1 FROM paper_credential_epoch.owners o
      WHERE o.webid=OLD.data->>'webId'
    ) THEN
      RAISE EXCEPTION 'Unified account enrollment is missing; recovery required'
        USING ERRCODE='42501';
    END IF;
    -- Legacy SemApps accounts must retain their old password/reset/update
    -- behavior. The independent ledger classifies a tracked unified owner;
    -- never rely on a possibly rewound enrollment marker alone.
    IF OLD.data ? 'signupReservationId' OR EXISTS (
      SELECT 1 FROM paper_credential_epoch.owners e
      WHERE e.webid=OLD.data->>'webId'
    ) THEN
      -- Credential-owner identity and its linkage to the native account are
      -- immutable, including the row UUID. Otherwise a direct JSONB update
      -- can move a canonical WebID to a different, unguarded identity.
      IF NEW.id IS DISTINCT FROM OLD.id
        OR NEW.data->'username' IS DISTINCT FROM OLD.data->'username'
        OR NEW.data->'signupReservationId' IS DISTINCT FROM
           OLD.data->'signupReservationId'
      THEN
        RAISE EXCEPTION 'Unified account canonical identity is immutable'
          USING ERRCODE='42501';
      END IF;
      IF NEW.data->'webId' IS DISTINCT FROM OLD.data->'webId' THEN
        -- SemApps legitimately binds the reserved WebID exactly ONCE
        -- after native account creation and BEFORE canonical enrollment.
        -- Its path is pinned by the already-immutable username. Never
        -- allow reassignment, removal, a second attach, or claimed-owner
        -- rebinding. This also agrees with guard_identity on the table.
        IF OLD.data ? 'webId'
          OR NOT (OLD.data ? 'signupReservationId')
          OR NEW.data->>'webId' IS DISTINCT FROM
             'https://paper.example.org/' || (OLD.data->>'username')
          OR EXISTS (
            SELECT 1 FROM paper_credential_epoch.owners e
            WHERE e.webid=NEW.data->>'webId'
          )
        THEN
          RAISE EXCEPTION 'Unified account WebID binding is immutable'
            USING ERRCODE='42501';
        END IF;
      END IF;
      -- These fields control recovery identity and terminal account state.
      -- They cannot be mutated by the general-purpose JSONB account role.
      -- A future owner-approved workflow must separately authorize them.
      IF NEW.data->'email' IS DISTINCT FROM OLD.data->'email'
        OR NEW.data->'deletedAt' IS DISTINCT FROM OLD.data->'deletedAt'
      THEN
        RAISE EXCEPTION 'Tracked owner recovery or tombstone change refused'
          USING ERRCODE='42501';
      END IF;

      -- A successful password rotation must also revoke any older reset
      -- capability in the *same* PostgreSQL transaction. Setting a new
      -- reset token is never a side effect of an approved password write.
      IF NEW.data->>'hashedPassword' IS DISTINCT FROM
           OLD.data->>'hashedPassword'
        OR NEW.data->'resetPasswordToken' IS DISTINCT FROM
           OLD.data->'resetPasswordToken'
      THEN
        IF NEW.data ? 'resetPasswordToken' OR NOT EXISTS (
          SELECT 1 FROM paper_credential_epoch.native_writes w
          JOIN paper_credential_epoch.owners e ON e.webid=w.webid
          WHERE w.webid=OLD.data->>'webId'
            AND OLD.data->>'webId'=NEW.data->>'webId'
            AND w.writing_xid=pg_catalog.pg_current_xact_id()
            AND w.new_hash_sha256=pg_catalog.sha256(
              pg_catalog.convert_to(NEW.data->>'hashedPassword','UTF8'))
            AND e.state='pending'
            AND e.operation_id=w.operation_id
            AND e.next_epoch=w.following_epoch
        ) THEN
          RAISE EXCEPTION 'Credential and reset changes require a pending operation'
            USING ERRCODE='42501';
        END IF;
      END IF;
    END IF;
    RETURN NEW;
  ELSIF TG_OP='DELETE' THEN
    -- No ordinary storage adapter may delete a fully claimed owner and
    -- reinsert a new bcrypt record under the same WebID.
    IF OLD.data ? 'signupReservationId'
       OR EXISTS (SELECT 1 FROM paper_credential_epoch.owners e
                  WHERE e.webid=OLD.data->>'webId') THEN
      RAISE EXCEPTION 'Unified account requires supervised tombstone'
        USING ERRCODE='42501';
    END IF;
    RETURN OLD;
  ELSIF TG_OP='INSERT' THEN
    IF NEW.data ? 'webId' AND EXISTS (
       SELECT 1 FROM paper_credential_epoch.owners e
       WHERE e.webid=NEW.data->>'webId'
    ) THEN
      RAISE EXCEPTION 'Existing credential owner cannot be replaced'
        USING ERRCODE='42501';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'Invalid account trigger action' USING ERRCODE='42501';
END
$guard$;
REVOKE ALL ON FUNCTION paper_credential_epoch.guard_native_account() FROM PUBLIC;
CREATE TRIGGER paper_native_epoch_guard
BEFORE INSERT OR UPDATE OR DELETE ON paper_private_auth.accounts
FOR EACH ROW EXECUTE FUNCTION paper_credential_epoch.guard_native_account();

-- Only this separate LOGIN/role may write a bcrypt credential. Upstream
-- SemApps must authenticate the actual owner BEFORE requesting a pending
-- operation. A UUID or WebID alone is never sufficient owner authority.
CREATE FUNCTION paper_credential_epoch.write_native_bcrypt(
  p_webid text,p_operation uuid,p_following_epoch bigint,p_bcrypt text
) RETURNS bytea
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $write$
DECLARE
  o paper_credential_epoch.owners%ROWTYPE;
  a_id uuid;
  old_bcrypt text;
  r bytea;
  changed integer;
BEGIN
  -- Bcrypt encoded hash only, NEVER an unhashed password or client JWT.
  -- Restrict bcrypt cost to 10..14 (avoid login CPU denial of service).
  -- The actual hash is created by SemApps, currently with work factor 10.
  IF p_bcrypt !~ E'^\\$2[aby]\\$(10|11|12|13|14)\\$[./A-Za-z0-9]{53}$'
     OR pg_catalog.octet_length(p_bcrypt)<>60 THEN RETURN NULL; END IF;
  SELECT * INTO o FROM paper_credential_epoch.owners e
    WHERE e.webid=p_webid FOR UPDATE;
  IF NOT FOUND OR o.state<>'pending' OR
     o.operation_id IS DISTINCT FROM p_operation OR
     o.next_epoch IS DISTINCT FROM p_following_epoch THEN RETURN NULL; END IF;
  SELECT a.id,a.data->>'hashedPassword' INTO a_id,old_bcrypt
  FROM paper_private_auth.accounts a
  WHERE a.data->>'webId'=p_webid AND a.data ? 'signupReservationId'
  FOR UPDATE;
  IF NOT FOUND OR old_bcrypt IS NULL OR
     old_bcrypt=p_bcrypt THEN RETURN NULL; END IF;

  r:=pg_catalog.sha256(pg_catalog.convert_to(
    pg_catalog.jsonb_build_array('paper.credential.native-write.v1',
      p_webid,p_operation::text,p_following_epoch::text,p_bcrypt)::text,
    'UTF8'));
  INSERT INTO paper_credential_epoch.native_writes
    (operation_id,webid,following_epoch,old_hash_sha256,new_hash_sha256,
      receipt_sha256,writing_xid)
  VALUES (p_operation,p_webid,p_following_epoch,
    pg_catalog.sha256(pg_catalog.convert_to(old_bcrypt,'UTF8')),
    pg_catalog.sha256(pg_catalog.convert_to(p_bcrypt,'UTF8')),
    r,pg_catalog.pg_current_xact_id());
  UPDATE paper_private_auth.accounts a
    SET data=pg_catalog.jsonb_set(a.data,'{hashedPassword}',
      pg_catalog.to_jsonb(p_bcrypt),true) - 'resetPasswordToken'
    WHERE a.id=a_id;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN
    RAISE EXCEPTION 'Native password write was not persisted'
      USING ERRCODE='55000';
  END IF;
  RETURN r;
END
$write$;

-- Reader gives a remote independent attestor *only* exact operation
-- correlation and NEVER hashes, user profiles or credentials.
CREATE FUNCTION paper_credential_epoch.confirm_native_write(
  p_webid text,p_operation uuid,p_following_epoch bigint,p_receipt bytea
) RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $confirm$
 SELECT EXISTS (
   SELECT 1 FROM paper_credential_epoch.owners o
   JOIN paper_credential_epoch.native_writes w
     ON w.webid=o.webid AND w.operation_id=o.operation_id
       AND w.following_epoch=o.next_epoch
   JOIN paper_private_auth.accounts a ON a.data->>'webId'=o.webid
   WHERE o.webid=p_webid AND o.state='pending'
     AND o.operation_id=p_operation AND o.next_epoch=p_following_epoch
     AND w.receipt_sha256=p_receipt AND pg_catalog.octet_length(p_receipt)=32
     AND w.new_hash_sha256=pg_catalog.sha256(
       pg_catalog.convert_to(a.data->>'hashedPassword','UTF8'))
     AND a.data ? 'signupReservationId'
     AND NOT (a.data ? 'resetPasswordToken')
 );
$confirm$;

-- The old general-purpose digest-only seal allowed a coordinator to
-- provide a fabricated 32-byte digest. Remove its execute privilege.
-- Native sealing now requires an operation-bound persisted bcrypt
-- readback and a distinct sealer role. The external independent signer
-- MUST acknowledge the new checkpoint before any production admission.
REVOKE EXECUTE ON FUNCTION
  paper_credential_epoch.seal_change(text,uuid,bigint,bytea)
  FROM paper_credential_coordinator;
CREATE FUNCTION paper_credential_epoch.seal_verified_native(
  p_webid text,p_operation uuid,p_following_epoch bigint,p_receipt bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE STRICT SECURITY DEFINER
SET search_path=pg_catalog AS $seal$
DECLARE
  native_ok boolean;
  changed integer;
BEGIN
  PERFORM 1 FROM paper_credential_epoch.owners o
    WHERE o.webid=p_webid FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT paper_credential_epoch.confirm_native_write(
    p_webid,p_operation,p_following_epoch,p_receipt) INTO native_ok;
  IF native_ok IS DISTINCT FROM true THEN RETURN false; END IF;
  UPDATE paper_credential_epoch.owners o SET
    epoch=o.next_epoch,state='active',operation_id=NULL,next_epoch=NULL,
    mutation_digest=p_receipt,updated_at=pg_catalog.clock_timestamp()
  WHERE o.webid=p_webid AND o.state='pending'
    AND o.operation_id=p_operation AND o.next_epoch=p_following_epoch
    AND o.next_epoch>o.epoch;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed=1;
END
$seal$;

REVOKE ALL ON FUNCTION
  paper_credential_epoch.write_native_bcrypt(text,uuid,bigint,text)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION
  paper_credential_epoch.confirm_native_write(text,uuid,bigint,bytea)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION
  paper_credential_epoch.seal_verified_native(text,uuid,bigint,bytea)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  paper_credential_epoch.write_native_bcrypt(text,uuid,bigint,text)
  TO paper_credential_native_writer;
GRANT EXECUTE ON FUNCTION
  paper_credential_epoch.confirm_native_write(text,uuid,bigint,bytea)
  TO paper_credential_native_attestor,paper_credential_native_sealer;
GRANT EXECUTE ON FUNCTION
  paper_credential_epoch.seal_verified_native(text,uuid,bigint,bytea)
  TO paper_credential_native_sealer;
COMMIT;

'use strict';

/**
 * NON-ACTIVATED provider-owned PostgreSQL 18 read proof for new accounts.
 *
 * The caller may provide only the Entryway idempotency reference and claimed
 * identity. Provider ID, app scope, approved SAI URI, HMAC secret and version
 * are immutable constructor configuration. PostgreSQL's SECURITY DEFINER
 * reader function checks the actual *current* journal, signed repo, projection,
 * owner identity and canonical SAI revocation revision in one MVCC snapshot.
 *
 * Historical readiness is never an authentication token or a live grant.
 */
const crypto = require('node:crypto');
const KEY = /^entryway:acct_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:[0-9a-f]{24}$/iu;
const DID = /^did:plc:[a-z2-7]{24}$/u;
const HANDLE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;
const MAX = 2048;

function deny(code) {
  const error = new Error('Current provider signup readiness is unavailable');
  error.code = code;
  throw error;
}

function canonicalHttps(value) {
  if (typeof value !== 'string' || value.length < 8 || value.length > MAX) return false;
  try {
    const uri = new URL(value);
    return uri.protocol === 'https:' && uri.hostname &&
      !uri.username && !uri.password && !uri.search && !uri.hash &&
      uri.href === value;
  } catch {
    return false;
  }
}

function canonicalOrigin(value) {
  if (typeof value !== 'string' || value.length < 8 || value.length > MAX) return false;
  try {
    const uri = new URL(value);
    return uri.protocol === 'https:' && uri.hostname &&
      !uri.username && !uri.password && uri.origin === value;
  } catch {
    return false;
  }
}

function newAccountProofEnabled() {
  return process.env.NODE_ENV === 'test' &&
    process.env.PAPER_ACCOUNTS_DISPOSABLE === 'confirmed' &&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE === 'confirmed' &&
    process.env.PAPER_ACCOUNT_COMPLETION_DISPOSABLE === 'confirmed';
}

function createPgBootstrapReadiness({
  pool, providerId, appClientId, appUri, hmacKey, hmacKeyVersion = 1,
  fixtureOnly = false, requireRestrictedReader = false
} = {}) {
  if (!pool || typeof pool.query !== 'function' ||
      !canonicalOrigin(providerId) || !canonicalHttps(appClientId) ||
      !canonicalHttps(appUri) ||
      !Buffer.isBuffer(hmacKey) || hmacKey.length < 32 ||
      !Number.isSafeInteger(hmacKeyVersion) ||
      hmacKeyVersion < 1 || hmacKeyVersion > 255 ||
      typeof requireRestrictedReader !== 'boolean') {
    deny('BOOTSTRAP_PG_CONFIGURATION_INVALID');
  }

  async function assertReaderRole() {
    if (fixtureOnly !== true || !newAccountProofEnabled()) {
      deny('BOOTSTRAP_PG_NOT_RELEASED');
    }
    // A shared superuser/ordinary app DSN can bypass canonical revocation
    // and read every user's account, grant and signing evidence. Fail closed
    // before accepting a bootstrap proof and recheck on every read so a
    // changed grant cannot leave a long-running service overprivileged.
    const sql =
      'SELECT r.rolsuper AS is_superuser,r.rolbypassrls AS bypass_rls,'+
      'r.rolcreatedb AS can_create_db,r.rolcreaterole AS can_create_role,'+
      'r.rolreplication AS can_replicate,r.rolcanlogin AS can_login,'+
      '(session_user=current_user) AS session_matches,'+
      "pg_catalog.pg_has_role(current_user,'paper_account_bootstrap_reader','MEMBER') AS reader_member,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer_member,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_revoker','MEMBER') AS revoker_member,"+
      "pg_catalog.pg_has_role(current_user,'pg_read_all_data','MEMBER') AS read_all_member,"+
      "pg_catalog.pg_has_role(current_user,'pg_write_all_data','MEMBER') AS write_all_member,"+
      "pg_catalog.pg_has_role(current_user,'pg_execute_server_program','MEMBER') AS exec_program_member,"+
      "pg_catalog.pg_has_role(current_user,'pg_read_server_files','MEMBER') AS read_files_member,"+
      "pg_catalog.pg_has_role(current_user,'pg_write_server_files','MEMBER') AS write_files_member,"+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace "+
      "WHERE nspname='paper_account_candidate'),'MEMBER') AS account_owner_member,"+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace "+
      "WHERE nspname='paper_atproto_authority'),'MEMBER') AS authority_owner_member,"+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace "+
      "WHERE nspname='paper_atproto_repo_proof'),'MEMBER') AS repo_owner_member,"+
      "pg_catalog.has_schema_privilege(current_user,'paper_account_candidate','USAGE') AS account_schema,"+
      "pg_catalog.has_schema_privilege(current_user,'paper_account_candidate','CREATE') AS can_create,"+
      "pg_catalog.has_database_privilege(current_user,current_database(),'CREATE') AS can_create_schema,"+
      "pg_catalog.has_schema_privilege(current_user,'paper_atproto_authority','USAGE') AS can_read_authority,"+
      "pg_catalog.has_schema_privilege(current_user,'paper_atproto_repo_proof','USAGE') AS can_read_repo,"+
      "pg_catalog.has_function_privilege(current_user,'paper_account_candidate.current_bootstrap_proof("+
      "text,text,smallint,bytea,text,text,text,text,text,text)','EXECUTE') AS can_prove,"+
      "pg_catalog.has_table_privilege(current_user,'paper_account_candidate.accounts','SELECT') AS can_select_accounts,"+
      "pg_catalog.has_table_privilege(current_user,'paper_account_candidate.signup_operations','SELECT') AS can_select_journal,"+
      "pg_catalog.has_table_privilege(current_user,'paper_account_candidate.accounts',"+
      "'INSERT,UPDATE,DELETE,TRUNCATE') AS can_write_accounts,"+
      "pg_catalog.has_table_privilege(current_user,'paper_account_candidate.signup_operations',"+
      "'INSERT,UPDATE,DELETE,TRUNCATE') AS can_write_journal "+
      'FROM pg_catalog.pg_roles r WHERE r.rolname=current_user LIMIT 2';
    let result;
    try {
      result = await pool.query(sql);
    } catch {
      deny('BOOTSTRAP_PG_ROLE_UNAVAILABLE');
    }
    const role = result?.rows?.[0];
    if (result?.rowCount !== 1 || !role ||
        role.is_superuser !== false || role.bypass_rls !== false ||
        role.can_create_db !== false || role.can_create_role !== false ||
        role.can_replicate !== false || role.can_login !== true ||
        role.session_matches !== true ||
        role.importer_member !== false || role.revoker_member !== false ||
        role.read_all_member !== false || role.write_all_member !== false ||
        role.exec_program_member !== false || role.read_files_member !== false ||
        role.write_files_member !== false ||
        role.account_owner_member !== false ||
        role.authority_owner_member !== false ||
        role.repo_owner_member !== false ||
        role.reader_member !== true || role.account_schema !== true ||
        role.can_create !== false || role.can_create_schema !== false ||
        role.can_read_authority !== false ||
        role.can_read_repo !== false || role.can_prove !== true ||
        role.can_select_accounts !== false ||
        role.can_select_journal !== false ||
        role.can_write_accounts !== false ||
        role.can_write_journal !== false) {
      deny('BOOTSTRAP_PG_ROLE_UNAUTHORIZED');
    }
    return true;
  }

  async function assertCurrent({ idempotencyKey, username, webId, actorId, atprotoDid, atprotoHandle } = {}) {
    // Check at call-time too: a test-mode object must never become a
    // production authority by changing process flags.
    if (fixtureOnly !== true || !newAccountProofEnabled()) {
      deny('BOOTSTRAP_PG_NOT_RELEASED');
    }
    if (typeof idempotencyKey !== 'string' || !KEY.test(idempotencyKey) ||
        typeof username !== 'string' ||
        !/^[a-z0-9][a-z0-9_-]{1,63}$/u.test(username) ||
        !canonicalHttps(webId) || actorId !== webId ||
        !DID.test(atprotoDid || '') ||
        typeof atprotoHandle !== 'string' || atprotoHandle.length > 253 ||
        !HANDLE.test(atprotoHandle)) {
      deny('BOOTSTRAP_PG_SCOPE_INVALID');
    }
    if (requireRestrictedReader) await assertReaderRole();

    // Domain separation means an offline hash of the request password is
    // never stored, and the raw Entryway key is never sent to PostgreSQL.
    const idempotencyHmac = crypto.createHmac('sha256', hmacKey)
      .update('account-signup-idempotency-v1\0', 'utf8')
      .update(idempotencyKey, 'utf8').digest();

    let result;
    try {
      result = await pool.query(
        'SELECT account_id,grant_uri,consent_revision,account_generation FROM ' +
        'paper_account_candidate.current_bootstrap_proof(' +
        '$1,$2,$3::smallint,$4,$5,$6,$7,$8,$9,$10)',
        [
          providerId, appClientId, hmacKeyVersion, idempotencyHmac,
          username, webId, actorId, atprotoDid, atprotoHandle, appUri
        ]
      );
    } catch {
      // Never relay SQL errors: connection strings and query diagnostics may
      // contain provider credentials, account details or HMACs.
      deny('BOOTSTRAP_PG_UNAVAILABLE');
    }

    if (result.rowCount !== 1 || !result.rows?.[0] ||
        !/^[0-9a-f-]{36}$/iu.test(result.rows[0].account_id || '') ||
        !canonicalHttps(result.rows[0].grant_uri) ||
        !/^[1-9][0-9]{0,18}$/u.test(String(result.rows[0].consent_revision)) ||
        !/^[1-9][0-9]{0,18}$/u.test(String(result.rows[0].account_generation))) {
      deny('BOOTSTRAP_PG_NOT_READY');
    }

    return Object.freeze({
      verified: true,
      accountId: result.rows[0].account_id,
      grantUri: result.rows[0].grant_uri,
      consentRevision: String(result.rows[0].consent_revision),
      accountGeneration: String(result.rows[0].account_generation),
      canAuthenticate: false,
      releaseAuthorized: false
    });
  }

  return Object.freeze({ assertCurrent, assertReaderRole });
}

module.exports = { createPgBootstrapReadiness };

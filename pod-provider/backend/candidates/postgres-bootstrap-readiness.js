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
  fixtureOnly = false
} = {}) {
  if (!pool || typeof pool.query !== 'function' ||
      !canonicalOrigin(providerId) || !canonicalHttps(appClientId) ||
      !canonicalHttps(appUri) ||
      !Buffer.isBuffer(hmacKey) || hmacKey.length < 32 ||
      !Number.isSafeInteger(hmacKeyVersion) ||
      hmacKeyVersion < 1 || hmacKeyVersion > 255) {
    deny('BOOTSTRAP_PG_CONFIGURATION_INVALID');
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

  return Object.freeze({ assertCurrent });
}

module.exports = { createPgBootstrapReadiness };

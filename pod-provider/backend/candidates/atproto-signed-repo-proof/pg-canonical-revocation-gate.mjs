'use strict';

/**
 * NON-ACTIVATED provider-only PostgreSQL revocation adapter. Its dedicated
 * login may EXECUTE only one database-owned, atomic active -> blocked CAS
 * function; it never receives direct table UPDATE or INSERT permissions.
 * External SAI owner consent must be checked BEFORE this adapter is invoked.
 */
const UINT = /^[1-9][0-9]{0,18}$/u;
const MAX_REVISION = 9223372036854775807n;
const SCHEMA = /^paper_private_auth_[0-9a-f]{16}$/u;

function fail(code) {
  const error = new Error('Canonical consent cannot be modified');
  error.code = code;
  throw error;
}
function canonicalHttps(value) {
  if (typeof value !== 'string' || value.length > 2048) fail('CANONICAL_CONSENT_INPUT');
  let url;
  try { url = new URL(value); } catch { fail('CANONICAL_CONSENT_INPUT'); }
  if (url.protocol !== 'https:' || url.href !== value || url.username ||
      url.password || url.search || url.hash) fail('CANONICAL_CONSENT_INPUT');
  return value;
}
function safeRevision(value) {
  if (typeof value !== 'string' || !UINT.test(value) ||
      BigInt(value) >= MAX_REVISION) fail('CANONICAL_CONSENT_INPUT');
  return value;
}

export function createDisposablePgCanonicalRevoker({
  client, schemaName, fixtureOnly = false
} = {}) {
  if (fixtureOnly !== true || process.env.NODE_ENV !== 'test' ||
      process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
      typeof schemaName !== 'string' || !SCHEMA.test(schemaName) ||
      !client || typeof client.query !== 'function') {
    return Object.freeze({
      revoke: async () => fail('CANONICAL_CONSENT_NOT_RELEASED')
    });
  }
  const fn = '"' + schemaName + '".block_consent';
  const statement = 'SELECT new_revision, new_state FROM ' + fn +
    ' ($1::text, $2::text, $3::text, $4::bigint)';
  return Object.freeze({
    async revoke({ ownerId, appId, grantUri, revision } = {}) {
      canonicalHttps(ownerId);
      canonicalHttps(appId);
      canonicalHttps(grantUri);
      safeRevision(revision);
      // A single indexed conditional database UPDATE; no cross-service
      // transaction, account scan, persistent JS cache or retry loop.
      const result = await client.query(statement,
        [ownerId, appId, grantUri, revision]);
      if (result?.rowCount !== 1 || result.rows[0]?.new_state !== 'blocked' ||
          String(result.rows[0]?.new_revision) !== String(BigInt(revision) + 1n)) {
        fail('CANONICAL_CONSENT_STALE');
      }
      return Object.freeze({
        state: 'blocked', revision: String(result.rows[0].new_revision)
      });
    }
  });
}

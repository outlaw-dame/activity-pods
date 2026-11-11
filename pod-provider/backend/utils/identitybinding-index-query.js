'use strict';

/**
 * Bounded server-side keyset pagination for the global identity lookup index.
 * This is an index-only view. Per-WebID protected LDP is still authoritative.
 *
 * No fallback to scanning all auth accounts or per-Pod resources is permitted
 * on API reads: such behavior causes unbounded N+1 Moleculer/Jena traffic.
 */
const APODS = 'http://activitypods.org/ns/core#';
const MAX_PAGE = 500;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;

function invalid(message) {
  const e = new Error(message);
  e.code = 'IDENTITY_BINDING_INDEX_QUERY_INVALID';
  throw e;
}
function literal(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2048) {
    invalid('Invalid index lookup literal');
  }
  return JSON.stringify(value);
}
function validCursor(cursor) {
  if (cursor === null) return null;
  if (!cursor || typeof cursor !== 'object' ||
      !ISO.test(cursor.updatedAt || '') ||
      !Number.isFinite(Date.parse(cursor.updatedAt)) ||
      typeof cursor.canonicalAccountId !== 'string') {
    invalid('Invalid identity index cursor');
  }
  const account = cursor.canonicalAccountId;
  let uri;
  try { uri = new URL(account); } catch { invalid('Invalid canonical account cursor'); }
  if (uri.protocol !== 'https:' || uri.href !== account || uri.search || uri.hash ||
      uri.username || uri.password || account.length > 2048) {
    invalid('Invalid canonical account cursor');
  }
  return { updatedAt: cursor.updatedAt, canonicalAccountId: account };
}
function boundedLimit(value) {
  if (!Number.isInteger(value) || value < 1 || value > MAX_PAGE + 1) {
    invalid('Out-of-range identity index page size');
  }
  return value;
}
function buildIndexPageQuery({ cursor = null, limit = 101 } = {}) {
  const size = boundedLimit(limit);
  const after = validCursor(cursor);
  const filter = !after ? '' :
    'FILTER(STR(?updatedAt) > ' + literal(after.updatedAt) +
    ' || (STR(?updatedAt) = ' + literal(after.updatedAt) +
    ' && STR(?canonicalAccountId) > ' + literal(after.canonicalAccountId) + '))';
  // Select ONLY the bounded page before joining optional metadata, so the
  // repository does not materialize every index record into the Node heap.
  return 'PREFIX apods: <' + APODS + '> ' +
    'SELECT ?binding ?canonicalAccountId ?webId ?activityPubActorId ?activityPubHandle ' +
      '?atprotoDid ?atprotoHandle ?atprotoSource ?atprotoManaged ?atprotoPdsUrl ' +
      '?atSigningKeyRef ?atRotationKeyRef ?status ?repoInitialized ?repoRootCid ' +
      '?repoRev ?createdAt ?updatedAt WHERE { ' +
    '{ SELECT ?binding ?canonicalAccountId ?updatedAt WHERE { ' +
      '?binding a apods:AtprotoIdentityBindingIndex ; ' +
      'apods:canonicalAccountId ?canonicalAccountId ; apods:updatedAt ?updatedAt . ' +
      filter + ' } ORDER BY STR(?updatedAt) STR(?canonicalAccountId) LIMIT ' + size + ' } ' +
    [
      'webId', 'activityPubActorId', 'activityPubHandle', 'atprotoDid',
      'atprotoHandle', 'atprotoSource', 'atprotoManaged', 'atprotoPdsUrl',
      'atSigningKeyRef', 'atRotationKeyRef', 'status', 'repoInitialized',
      'repoRootCid', 'repoRev', 'createdAt'
    ].map(key => 'OPTIONAL { ?binding apods:' + key + ' ?' + key + ' . }').join(' ') +
    ' } ORDER BY STR(?updatedAt) STR(?canonicalAccountId)';
}
module.exports = { MAX_PAGE, buildIndexPageQuery, validCursor };

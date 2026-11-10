'use strict';

/**
 * OFFLINE MAINTENANCE ONLY.
 *
 * Stop every Pod-provider process and worker first. Back up the Fuseki
 * settings dataset. Keep provider G1 release fuse CLOSED. This CLI never
 * grants SAI permissions: it discards abandoned pending mutation tokens,
 * advances the revision and leaves the consent ledger BLOCKED. A fresh user
 * consent action through the native SAI service is required after restart.
 *
 * Inspect:
 *   node backend/scripts/recover-collective-consent-offline.js inspect WEBID APP
 * Apply (after verifying revision and ALL writers stopped):
 *   COLLECTIVES_OFFLINE_MAINTENANCE_CONFIRMED=ALL_PROVIDER_WRITERS_STOPPED \
 *     node backend/scripts/recover-collective-consent-offline.js apply WEBID APP REVISION
 *
 * Uses FUSEKI_URL / FUSEKI_USER / FUSEKI_PASSWORD in the operator's secure
 * environment. No HTTP route or distributed service action is added.
 */
const assert = require('node:assert/strict');
const { queryState, resetQuery, freshNonce } =
  require('../services/utils/collective-consent-recovery');

const endpoint = (process.env.FUSEKI_URL || 'http://127.0.0.1:3040').replace(/\/+$/u, '');
const auth = 'Basic ' + Buffer.from((process.env.FUSEKI_USER || 'admin') +
  ':' + (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');

async function sparql(kind, query) {
  const response = await fetch(endpoint + '/settings/' + kind, {
    method: 'POST',
    headers: {
      authorization: auth,
      'content-type': kind === 'update' ? 'application/sparql-update' : 'application/sparql-query',
      accept: 'application/sparql-results+json'
    },
    body: query,
    signal: AbortSignal.timeout(20000)
  });
  const body = await response.text();
  if (!response.ok) throw new Error('Fuseki ' + kind + ' HTTP ' + response.status);
  return kind === 'query' ? JSON.parse(body).results.bindings : null;
}
function values(rows) {
  const revisions = new Set(rows.map(row => row.revision?.value));
  const states = new Set(rows.map(row => row.status?.value));
  if (revisions.size !== 1 || states.size !== 1) {
    throw new Error('Ambiguous/corrupt ledger; manual investigation required');
  }
  const revision = Number([...revisions][0]);
  if (!Number.isSafeInteger(revision) || revision < 1) {
    throw new Error('Invalid consent revision');
  }
  return { revision, status: [...states][0],
    pendingCount: new Set(rows.map(row => row.pending?.value).filter(Boolean)).size,
    recoveryNonces: [...new Set(rows.map(row => row.recovery?.value).filter(Boolean))] };
}
async function main() {
  const [action, principal, app, expected] = process.argv.slice(2);
  if (!['inspect', 'apply'].includes(action) || !principal || !app ||
      (action === 'inspect' && expected) || (action === 'apply' && !expected)) {
    throw new Error('Usage: inspect WEBID APP | apply WEBID APP REVISION');
  }
  // Validate identifiers BEFORE access to the backing store.
  const stateQuery = queryState(principal, app);
  const rows = await sparql('query', stateQuery);
  if (rows.length === 0) throw new Error('No consent ledger found');
  const state = values(rows);
  if (action === 'inspect') {
    console.log(JSON.stringify({ operation: 'inspect', ...state }));
    return;
  }
  if (process.env.COLLECTIVES_OFFLINE_MAINTENANCE_CONFIRMED !== 'ALL_PROVIDER_WRITERS_STOPPED' ||
      process.env.PROVIDER_COLLECTIVES_API_ENABLED === 'true' ||
      process.env.PROVIDER_COLLECTIVES_RESERVATIONS_ENABLED === 'true') {
    throw new Error('Offline maintenance acknowledgement and disabled Group routes required');
  }
  const revision = Number(expected);
  if (String(revision) !== expected || state.revision !== revision ||
      state.status !== 'blocked' || state.pendingCount === 0) {
    throw new Error('Revision mismatch, not blocked, or no pending mutation to recover');
  }
  const nonce = freshNonce();
  const query = resetQuery({ principal, app, expectedRevision: revision, nonce });
  await sparql('update', query);
  const after = values(await sparql('query', stateQuery));
  assert.equal(after.revision, revision + 1, 'failed atomic recovery revision CAS');
  assert.equal(after.status, 'blocked', 'must not reauthorize');
  assert.equal(after.pendingCount, 0, 'pending mutations not cleared');
  assert(after.recoveryNonces.includes(nonce), 'missing committed recovery nonce');
  console.log(JSON.stringify({
    operation: 'apply', result: 'blocked-requires-new-user-consent',
    revision: after.revision, recoveryNonce: nonce
  }));
}
main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});

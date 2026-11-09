'use strict';

/**
 * Isolated G1a proof of the SAME-DATASET atomic consent + reservation primitive.
 *
 * This is deliberately NOT the production SAI authorization implementation:
 * its synthetic, provider-owned authority rows do not yet track SAI changes,
 * application registration or account suspension. Therefore passing this
 * proof MUST NOT enable the public Group creation route.
 *
 * Usage:
 *   node backend/scripts/proof-collective-consent-fence.js prepare
 *   # restart the persistent Fuseki service
 *   node backend/scripts/proof-collective-consent-fence.js verify
 */
const assert = require('node:assert/strict');

const base = (process.env.FUSEKI_URL || 'http://127.0.0.1:3040').replace(/\/+$/u, '');
const auth = 'Basic ' + Buffer.from((process.env.FUSEKI_USER || 'admin') +
  ':' + (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');

const ns = 'urn:apods:proof:collective-consent-fence:v1:';
const pred = 'http://activitypods.org/ns/core#';
const consent = suffix => '<' + ns + 'consent:' + suffix + '>';
const reservation = suffix => '<' + ns + 'reservation:' + suffix + '>';
const p = local => '<' + pred + local + '>';

async function sparql(kind, query) {
  const response = await fetch(base + '/settings/' + kind, {
    method: 'POST',
    headers: {
      authorization: auth,
      'content-type': kind === 'query' ? 'application/sparql-query' : 'application/sparql-update',
      accept: 'application/sparql-results+json'
    },
    body: query,
    signal: AbortSignal.timeout(20000)
  });
  const body = await response.text();
  if (!response.ok) throw new Error('Fuseki ' + kind + ' HTTP ' + response.status + ': ' + body.slice(0, 500));
  return kind === 'query' ? JSON.parse(body).results.bindings : null;
}

// One authorization revision and its conditional reservation must share
// the SAME Fuseki settings dataset and transaction boundary. A separate
// consent lookup + a later INSERT is explicitly not a fence.
function seed(id) {
  return 'INSERT DATA { ' + consent(id) +
    ' ' + p('collectiveConsentActive') + ' "true" ; ' +
    p('collectiveConsentRevision') + ' "1" . }';
}
function revoke(id) {
  return 'DELETE { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "true" ; ' +
    p('collectiveConsentRevision') + ' "1" . }\n' +
    'INSERT { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "false" ; ' +
    p('collectiveConsentRevision') + ' "2" . }\n' +
    'WHERE { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "true" ; ' +
    p('collectiveConsentRevision') + ' "1" . }';
}
function reserve(id) {
  return 'INSERT { ' + reservation(id) + ' ' +
    p('collectiveConsentRevision') + ' "1" ; ' +
    p('collectiveReservationCommit') + ' "committed" . }\n' +
    'WHERE { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "true" ; ' +
    p('collectiveConsentRevision') + ' "1" .\n' +
    'FILTER NOT EXISTS { ' + reservation(id) + ' ' +
    p('collectiveReservationCommit') + ' ?existing . } }';
}
// A later grant must advance the revision. A stale reservation carrying an
// earlier observed revision is invalid even after consent becomes active again.
function regrant(id) {
  return 'DELETE { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "false" ; ' +
    p('collectiveConsentRevision') + ' "2" . }\\n' +
    'INSERT { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "true" ; ' +
    p('collectiveConsentRevision') + ' "3" . }\\n' +
    'WHERE { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "false" ; ' +
    p('collectiveConsentRevision') + ' "2" . }';
}
async function state(id) {
  const rows = await sparql('query', 'SELECT ?active ?rev ?committed WHERE { ' +
    consent(id) + ' ' + p('collectiveConsentActive') + ' ?active ; ' +
    p('collectiveConsentRevision') + ' ?rev . ' +
    'OPTIONAL { ' + reservation(id) + ' ' +
    p('collectiveReservationCommit') + ' ?committed . } }');
  assert.equal(rows.length, 1, 'one authoritative consent row required: ' + id);
  return {
    active: rows[0].active.value,
    rev: rows[0].rev.value,
    committed: rows[0].committed?.value || null
  };
}
async function initialize(id) {
  await sparql('update', seed(id));
}
async function prepare() {
  // A revocation committed before a reservation must prevent that reservation.
  await initialize('revoke-first');
  await sparql('update', revoke('revoke-first'));
  await sparql('update', reserve('revoke-first'));
  assert.deepEqual(await state('revoke-first'),
    { active: 'false', rev: '2', committed: null });

  // A reservation committed before revocation can exist, with its original
  // revision captured; revocation must still advance the consent revision.
  await initialize('reserve-first');
  await sparql('update', reserve('reserve-first'));
  await sparql('update', revoke('reserve-first'));
  assert.deepEqual(await state('reserve-first'),
    { active: 'false', rev: '2', committed: 'committed' });

  // Revocation followed by a regrant must not resurrect a request that
  // captured revision 1. Explicit fresh-revision reservations are handled by
  // a separate operation in the eventual production API, never by replay.
  await initialize('stale-after-regrant');
  await sparql('update', revoke('stale-after-regrant'));
  await sparql('update', regrant('stale-after-regrant'));
  await sparql('update', reserve('stale-after-regrant'));
  assert.deepEqual(await state('stale-after-regrant'),
    { active: 'true', rev: '3', committed: null });

  // Several HTTP clients contend for a same-dataset transaction. Every
  // completed run must leave a valid serialized state. It is legitimate for
  // the reservation to win before revocation; not legitimate for active=true
  // after revocation, nor a post-revoke reservation in the revoke-first case.
  for (let i = 0; i < 8; i++) {
    const id = 'contended-' + i;
    await initialize(id);
    await Promise.all([
      sparql('update', reserve(id)),
      sparql('update', revoke(id)),
      sparql('update', reserve(id))
    ]);
    const result = await state(id);
    assert.equal(result.active, 'false');
    assert.equal(result.rev, '2');
    assert([null, 'committed'].includes(result.committed));
  }
  console.log(JSON.stringify({ ok: true, proof: 'single-dataset-consent-reservation',
    phase: 'prepare', caveat: 'synthetic authority only; SAI bridge not implemented' }));
}
async function verify() {
  assert.deepEqual(await state('revoke-first'),
    { active: 'false', rev: '2', committed: null });
  assert.deepEqual(await state('reserve-first'),
    { active: 'false', rev: '2', committed: 'committed' });
  assert.deepEqual(await state('stale-after-regrant'),
    { active: 'true', rev: '3', committed: null });
  for (let i = 0; i < 8; i++) {
    const result = await state('contended-' + i);
    assert.equal(result.active, 'false');
    assert.equal(result.rev, '2');
    assert([null, 'committed'].includes(result.committed));
  }
  console.log(JSON.stringify({ ok: true, proof: 'single-dataset-consent-reservation',
    phase: 'verify', caveat: 'synthetic authority only; SAI bridge not implemented' }));
}
(async () => {
  if (process.argv[2] === 'prepare') await prepare();
  else if (process.argv[2] === 'verify') await verify();
  else throw new Error('Expected prepare or verify');
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});

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
const crypto = require('node:crypto');
const reservations = require('../services/collective-reservations.service');
const liveFence = require('../services/collective-consent-fence.service');
const recovery = require('../services/utils/collective-consent-recovery');

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
function reserveAtRevision(id, revision) {
  if (![1, 3].includes(revision)) throw new Error('Invalid synthetic proof revision');
  const version = '"' + revision + '"';
  return 'INSERT { ' + reservation(id) + ' ' +
    p('collectiveConsentRevision') + ' ' + version + ' ; ' +
    p('collectiveReservationCommit') + ' "committed" . }\n' +
    'WHERE { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "true" ; ' +
    p('collectiveConsentRevision') + ' ' + version + ' .\n' +
    'FILTER NOT EXISTS { ' + reservation(id) + ' ' +
    p('collectiveReservationCommit') + ' ?existing . } }';
}
const reserve = id => reserveAtRevision(id, 1);
// A later grant must advance the revision. A stale reservation carrying an
// earlier observed revision is invalid even after consent becomes active again.
function regrant(id) {
  return 'DELETE { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "false" ; ' +
    p('collectiveConsentRevision') + ' "2" . }\n' +
    'INSERT { ' + consent(id) + ' ' +
    p('collectiveConsentActive') + ' "true" ; ' +
    p('collectiveConsentRevision') + ' "3" . }\n' +
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
// Exercise the real deny-first service against Fuseki, not a simulated
// triplestore mock. It never marks an SAI permission as granted.
const fencePrincipal = 'https://provider-proof.example/users/alice#me';
const fenceApp = 'https://paper-proof.example/app';
const pendingPrincipal = 'https://provider-proof.example/users/bob#me';
const pendingApp = 'https://paper-proof.example/app';
async function callLiveFence(action, principal, app, token) {
  const ctx = {
    params: { principal, app, ...(token ? { token } : {}) },
    call: async (name, params) => {
      assert.equal(params.dataset, 'settings');
      assert.equal(params.webId, 'system');
      if (name === 'triplestore.update') return sparql('update', params.query);
      if (name === 'triplestore.query') return sparql('query', params.query);
      throw new Error('unexpected fence action ' + name);
    }
  };
  return liveFence.actions[action].handler.call({ settings: { enabled: true } }, ctx);
}
async function liveState(principal = fencePrincipal, app = fenceApp) {
  const rows = await sparql('query', liveFence._test.stateQuery(principal, app));
  assert.equal(rows.length, 1);
  return { status: rows[0].status.value, revision: Number(rows[0].revision.value) };
}
const reservationSecret = 's'.repeat(48);
const reservationIdentityKey = 'i'.repeat(48);
const reservationPurpose = 'provider.collective.reservation.v1';
const fencedKeyA = 'g1fencedreservationproof00000001';
const fencedKeyB = 'g1fencedreservationproof00000002';
const fencedKeyC = 'g1fencedreservationproof00000003';
const accountUri = '<urn:AuthAccount:group-fence-proof-account>';
const accountNs = 'http://semapps.org/ns/core#';
function fencedId(key) {
  return 'cg_' + crypto.createHmac('sha256', reservationIdentityKey)
    .update(JSON.stringify([pendingPrincipal, pendingApp, key])).digest('hex').slice(0, 32);
}
function fencedReservationParams(key) {
  const name = 'Fuseki Consent Fence Proof';
  const hash = crypto.createHash('sha256').update(JSON.stringify([
    pendingPrincipal, pendingApp, key, name
  ])).digest('hex');
  const issuedAt = Date.now() - 1000;
  const expiresAt = issuedAt + 60000;
  const fields = [reservationPurpose, pendingPrincipal, pendingApp,
    'reserve', hash, issuedAt, expiresAt];
  return {
    principal: pendingPrincipal, app: pendingApp, idempotencyKey: key,
    displayName: name,
    grant: {
      purpose: reservationPurpose, principal: pendingPrincipal, app: pendingApp,
      operation: 'reserve', requestHash: hash, issuedAt, expiresAt,
      mac: crypto.createHmac('sha256', reservationSecret)
        .update(JSON.stringify(fields)).digest('hex')
    }
  };
}
function reservationInstance() {
  const obj = { settings: {
    enabled: true,
    providerOrigin: 'https://provider-proof.example',
    secret: reservationSecret,
    identityKey: reservationIdentityKey,
    approvedApps: [pendingApp],
    consentBridgeEnabled: true
  } };
  obj._load = reservations.methods._load.bind(obj);
  return obj;
}
function reservationCtx(params) {
  return {
    params,
    call: async (action, args) => {
      if (action === 'auth.account.findByWebId') return { webId: args.webId };
      if (action === 'app-registrations.isRegistered') return true;
      if (action === 'access-authorizations.getSpecialRights') return ['apods:CreateGroup'];
      assert.equal(args.dataset, 'settings');
      assert.equal(args.webId, 'system');
      if (action === 'triplestore.update') return sparql('update', args.query);
      if (action === 'triplestore.query') return sparql('query', args.query);
      throw new Error('unexpected reservation action ' + action);
    }
  };
}
async function createFencedReservation(key) {
  const obj = reservationInstance();
  return reservations.actions.reserve.handler.call(obj,
    reservationCtx(fencedReservationParams(key)));
}
async function loadFencedReservation(key) {
  const obj = reservationInstance();
  return obj._load(reservationCtx({}), fencedId(key));
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

  // A newly authorized request using revision 3 *can* commit. This is
  // distinct from reviving the invalidated revision-1 request.
  await sparql('update', reserveAtRevision('stale-after-regrant', 3));
  assert.deepEqual(await state('stale-after-regrant'),
    { active: 'true', rev: '3', committed: 'committed' });

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
  // A crashed/unfinished SAI mutation must persist as blocked through restart.
  const abandonedA = await callLiveFence('begin', fencePrincipal, fenceApp);
  const abandonedB = await callLiveFence('begin', fencePrincipal, fenceApp);
  assert.notEqual(abandonedA.token, abandonedB.token);
  assert.deepEqual(await liveState(), { status: 'blocked', revision: 2 });
  // Simulate an OFFLINE operator recovery with provider writers stopped.
  // It must invalidate all abandoned tokens and leave the grant BLOCKED.
  const offlineNonce = recovery.freshNonce();
  await sparql('update', recovery.resetQuery({
    principal: fencePrincipal, app: fenceApp, expectedRevision: 2, nonce: offlineNonce
  }));
  assert.deepEqual(await liveState(), { status: 'blocked', revision: 3 });
  const recoveredRows = await sparql('query', recovery.queryState(fencePrincipal, fenceApp));
  assert(recoveredRows.every(row => !row.pending), 'offline recovery retained pending tokens');
  assert(recoveredRows.some(row => row.recovery?.value === offlineNonce));
  await assert.rejects(callLiveFence('finish', fencePrincipal, fenceApp, abandonedA.token),
    e => e.type === 'COLLECTIVE_CONSENT_FENCE_UNVERIFIED');

  // Two concurrent SAI mutations must BOTH finish before the provider
  // status may return to stable. A crash with an outstanding token remains
  // blocked, rather than assuming the user still authorized creation.
  const [first, second] = await Promise.all([
    callLiveFence('begin', pendingPrincipal, pendingApp),
    callLiveFence('begin', pendingPrincipal, pendingApp)
  ]);
  assert.notEqual(first.token, second.token);
  assert.equal((await liveState(pendingPrincipal, pendingApp)).status, 'blocked');
  assert.equal((await callLiveFence('finish', pendingPrincipal, pendingApp, first.token)).status, 'blocked');
  assert.deepEqual(await callLiveFence('finish', pendingPrincipal, pendingApp, second.token),
    { status: 'stable', revision: 2 });
  assert.deepEqual(await liveState(pendingPrincipal, pendingApp),
    { status: 'stable', revision: 2 });
  // SemApps auth.account writes to the settings dataset using this ontology.
  // Seed one active account so the real reservation transaction can join it.
  await sparql('update', 'INSERT DATA { ' + accountUri +
    ' a <' + accountNs + 'AuthAccount> ; <' + accountNs + 'webId> ' +
    JSON.stringify(pendingPrincipal) + ' . }');

  // Actual reservation code must atomically reject an in-flight SAI mutation.
  // The SAI consent and registration responses in this proof are deliberately
  // controlled fixtures; the storage transaction is REAL Fuseki.
  const third = await callLiveFence('begin', pendingPrincipal, pendingApp);
  await assert.rejects(createFencedReservation(fencedKeyA),
    e => e.type === 'COLLECTIVE_CONSENT_FENCE_REQUIRED');
  await callLiveFence('finish', pendingPrincipal, pendingApp, third.token);
  const committed = await createFencedReservation(fencedKeyA);
  assert.equal(committed.canonicalGroupId, fencedId(fencedKeyA));
  assert.equal((await loadFencedReservation(fencedKeyA)).consentRevision, '3');

  const fourth = await callLiveFence('begin', pendingPrincipal, pendingApp);
  await assert.rejects(createFencedReservation(fencedKeyB),
    e => e.type === 'COLLECTIVE_CONSENT_FENCE_REQUIRED');
  await callLiveFence('finish', pendingPrincipal, pendingApp, fourth.token);
  const newer = await createFencedReservation(fencedKeyB);
  assert.equal(newer.canonicalGroupId, fencedId(fencedKeyB));
  assert.equal((await loadFencedReservation(fencedKeyB)).consentRevision, '4');
  // Tombstoning the account is a write in the same TDB2 dataset; even
  // unchanged live SAI fixtures cannot authorize another reservation.
  await sparql('update', 'INSERT DATA { ' + accountUri +
    ' <' + accountNs + 'deletedAt> "2026-11-09T00:00:00Z" . }');
  await assert.rejects(createFencedReservation(fencedKeyC),
    e => e.type === 'COLLECTIVE_CONSENT_FENCE_REQUIRED');
  assert.equal(await loadFencedReservation(fencedKeyC), null);



  console.log(JSON.stringify({ ok: true, proof: 'single-dataset-consent-reservation',
    phase: 'prepare', caveat: 'synthetic authority only; SAI bridge not implemented' }));
}
async function verify() {
  assert.deepEqual(await state('revoke-first'),
    { active: 'false', rev: '2', committed: null });
  assert.deepEqual(await state('reserve-first'),
    { active: 'false', rev: '2', committed: 'committed' });
  assert.deepEqual(await state('stale-after-regrant'),
    { active: 'true', rev: '3', committed: 'committed' });
  for (let i = 0; i < 8; i++) {
    const result = await state('contended-' + i);
    assert.equal(result.active, 'false');
    assert.equal(result.rev, '2');
    assert([null, 'committed'].includes(result.committed));
  }
  assert.deepEqual(await liveState(), { status: 'blocked', revision: 3 });
  const recovered = await sparql('query', recovery.queryState(fencePrincipal, fenceApp));
  assert(recovered.every(row => !row.pending), 'pending mutation survived operator recovery');

  assert.deepEqual(await liveState(pendingPrincipal, pendingApp),
    { status: 'stable', revision: 4 });
  assert.equal((await loadFencedReservation(fencedKeyA)).consentRevision, '3');
  assert.equal((await loadFencedReservation(fencedKeyB)).consentRevision, '4');
  assert.equal(await loadFencedReservation(fencedKeyC), null);
  const tombstone = await sparql('query', 'SELECT ?value WHERE { ' + accountUri +
    ' <' + accountNs + 'deletedAt> ?value . }');
  assert.equal(tombstone.length, 1);

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

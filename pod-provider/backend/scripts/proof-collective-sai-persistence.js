'use strict';

/**
 * Cross-dataset G1 integration regression.
 *
 * Uses REAL Fuseki TDB2 datasets for the provider settings ledger and for
 * SAI-shaped Pod authorization/registration RDF. Invokes the actual SAI
 * lifecycle pre/post hooks, consent-fence actions and reservation service.
 * The LDP registry/container adapter and Solid-OIDC gateway are not running
 * here: their reads/callbacks use a narrow SPARQL-backed fixture. This is
 * not a deployed-provider browser-consent E2E test.
 */
const assert = require('node:assert/strict');
assert.equal(process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED, 'true',
  'SAI integration requires hooks enabled only inside disposable test process');
const crypto = require('node:crypto');
const access = require('../services/sai/access-authorizations');
const registration = require('../services/sai/app-registrations');
const fence = require('../services/collective-consent-fence.service');
const reservation = require('../services/collective-reservations.service');
const { reserveFingerprint } = require('../services/utils/collective-grant-claims');

const origin = (process.env.FUSEKI_URL || 'http://127.0.0.1:3040').replace(/\/+$/u, '');
const credentials = 'Basic ' + Buffer.from((process.env.FUSEKI_USER || 'admin') + ':' +
  (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');
const principal = 'https://provider-proof.example/profile/sai#me';
const app = 'https://paper-proof.example/sai';
const account = '<urn:AuthAccount:g1-sai-proof>';
const reg = '<https://provider-proof.example/sai/registration/proof>';
const auth = '<https://provider-proof.example/sai/authorization/proof>';
const accountNs = 'http://semapps.org/ns/core#';
const interop = 'http://www.w3.org/ns/solid/interop#';
const groupNs = 'http://activitypods.org/ns/core#';
const secret = 'g'.repeat(48), idKey = 'i'.repeat(48);
const purpose = 'provider.collective.reservation.v1';
const keyA = 'sai-persisted-proof-key-aaaaaaaa';
const keyB = 'sai-persisted-proof-key-bbbbbbbb';

async function sparql(dataset, kind, query) {
  const response = await fetch(origin + '/' + dataset + '/' + kind, {
    method: 'POST',
    headers: {
      authorization: credentials,
      'content-type': kind === 'query' ? 'application/sparql-query' : 'application/sparql-update',
      accept: 'application/sparql-results+json'
    },
    body: query,
    signal: AbortSignal.timeout(20000)
  });
  const result = await response.text();
  if (!response.ok) throw new Error('Fuseki ' + dataset + '/' + kind +
    ': HTTP ' + response.status + ': ' + result.slice(0, 600));
  return kind === 'query' ? JSON.parse(result).results.bindings : null;
}

const literal = JSON.stringify;
function saiAuthorizationResource() {
  return {
    type: 'interop:AccessAuthorization',
    'interop:grantedBy': principal,
    'interop:grantee': app,
    'interop:hasAccessNeedGroup': 'https://paper-proof.example/access-needs/groups',
    'apods:hasSpecialRights': ['apods:CreateGroup']
  };
}
function appRegistrationResource() {
  return {
    type: 'interop:ApplicationRegistration',
    'interop:registeredBy': principal,
    'interop:registeredAgent': app
  };
}
async function storeRegistration() {
  return sparql('g1_sai_fixture', 'update', 'INSERT DATA { ' + reg +
    ' a <' + interop + 'ApplicationRegistration> ; ' +
    '<' + interop + 'registeredBy> ' + literal(principal) + ' ; ' +
    '<' + interop + 'registeredAgent> ' + literal(app) + ' . }');
}
async function storeAuthorization() {
  return sparql('g1_sai_fixture', 'update', 'INSERT DATA { ' + auth +
    ' a <' + interop + 'AccessAuthorization> ; ' +
    '<' + interop + 'grantedBy> ' + literal(principal) + ' ; ' +
    '<' + interop + 'grantee> ' + literal(app) + ' ; ' +
    '<' + interop + 'hasAccessNeedGroup> ' +
    literal('https://paper-proof.example/access-needs/groups') + ' ; ' +
    '<' + groupNs + 'hasSpecialRights> "apods:CreateGroup" . }');
}
async function removeAuthorization() {
  return sparql('g1_sai_fixture', 'update', 'DELETE WHERE { ' + auth + ' ?p ?o . }');
}
async function getRegistration() {
  const rows = await sparql('g1_sai_fixture', 'query', 'SELECT ?person ?app WHERE { ' +
    reg + ' <' + interop + 'registeredBy> ?person ; <' + interop +
    'registeredAgent> ?app . }');
  if (!rows.length) return null;
  assert.equal(rows.length, 1);
  return { 'interop:registeredBy': rows[0].person.value,
    'interop:registeredAgent': rows[0].app.value };
}
async function getAuthorization() {
  const rows = await sparql('g1_sai_fixture', 'query', 'SELECT ?person ?app ?right WHERE { ' +
    auth + ' <' + interop + 'grantedBy> ?person ; <' + interop +
    'grantee> ?app ; <' + groupNs + 'hasSpecialRights> ?right . }');
  if (!rows.length) return null;
  return { ...saiAuthorizationResource(), 'interop:grantedBy': rows[0].person.value,
    'interop:grantee': rows[0].app.value,
    'apods:hasSpecialRights': rows.map(row => row.right.value) };
}

async function call(name, params) {
  if (name === 'triplestore.update' || name === 'triplestore.query') {
    assert.equal(params.dataset, 'settings');
    assert.equal(params.webId, 'system');
    return sparql('settings', name.endsWith('update') ? 'update' : 'query', params.query);
  }
  if (name === 'collective-consent-fence.begin' || name === 'collective-consent-fence.finish') {
    const method = name.slice('collective-consent-fence.'.length);
    return fence.actions[method].handler.call({ settings: { enabled: true } },
      { params, call });
  }
  if (name === 'auth.account.findByWebId') {
    const rows = await sparql('settings', 'query', 'SELECT ?webId WHERE { ' +
      account + ' a <' + accountNs + 'AuthAccount> ; <' + accountNs +
      'webId> ?webId . FILTER NOT EXISTS { ' + account +
      ' <' + accountNs + 'deletedAt> ?deleted . } }');
    return rows.length === 1 ? { webId: rows[0].webId.value } : null;
  }
  if (name === 'app-registrations.isRegistered') {
    const registered = await getRegistration();
    return !!registered &&
      registered['interop:registeredBy'] === params.podOwner &&
      registered['interop:registeredAgent'] === params.appUri;
  }
  if (name === 'access-authorizations.getSpecialRights') {
    const granted = await getAuthorization();
    return granted && granted['interop:grantedBy'] === params.podOwner &&
      granted['interop:grantee'] === params.appUri
      ? granted['apods:hasSpecialRights'] : [];
  }
  if (name === 'access-authorizations.get') return getAuthorization();
  if (name === 'app-registrations.get') return getRegistration();
  if (name === 'access-grants.getByAccessNeedGroup') return null;
  // Registry/AccessGrant and cached-resource callbacks are not the tested
  // storage adapter in this proof. Any other action is a harness error.
  if (['agent-registry.add', 'auth-registry.add', 'auth-registry.remove',
    'ldp.remote.store', 'applications.attach', 'access-grants.post'].includes(name)) return true;
  throw new Error('Unexpected SAI action ' + name);
}
const ctx = params => ({ params, meta: {}, call });
const authHooks = {
  actions: {
    addPermissionsFromSpecialRights: access.actions.addPermissionsFromSpecialRights,
    removePermissionsFromSpecialRights: access.actions.removePermissionsFromSpecialRights
  }
};
async function createRegistration() {
  const context = ctx({ resource: appRegistrationResource() });
  await registration.hooks.before.post(context);
  await storeRegistration();
  await registration.hooks.after.post(context, reg.slice(1, -1));
}
async function createAuthorization() {
  const context = ctx({ resource: saiAuthorizationResource() });
  await access.hooks.before.post(context);
  await storeAuthorization();
  await access.hooks.after.post.call(authHooks, context, auth.slice(1, -1));
}
async function revokeAuthorization({ afterBegin } = {}) {
  const context = ctx({ resourceUri: auth.slice(1, -1), webId: 'system' });
  await access.hooks.before.delete(context);
  if (afterBegin) await afterBegin();
  const oldData = await getAuthorization();
  assert(oldData);
  await removeAuthorization();
  await access.hooks.after.delete.call(authHooks, context, {
    oldData, resourceUri: auth.slice(1, -1)
  });
}
function paramsFor(key) {
  const displayName = 'SAI persistence proof';
  const issuedAt = Date.now() - 1000, expiresAt = issuedAt + 60000;
  const requestHash = reserveFingerprint(principal, app, key, displayName);
  const fields = [purpose, principal, app, 'reserve', requestHash, issuedAt, expiresAt];
  return { principal, app, idempotencyKey: key, displayName,
    grant: { purpose, principal, app, operation: 'reserve', requestHash,
      issuedAt, expiresAt, mac: crypto.createHmac('sha256', secret)
        .update(JSON.stringify(fields)).digest('hex') } };
}
function reservationInstance() {
  const instance = { settings: { enabled: true,
    consentBridgeEnabled: true, providerOrigin: 'https://provider-proof.example',
    secret, identityKey: idKey, approvedApps: [app] } };
  instance._load = reservation.methods._load.bind(instance);
  return instance;
}
async function reserve(key) {
  return reservation.actions.reserve.handler.call(reservationInstance(), ctx(paramsFor(key)));
}
async function stored(key) {
  const groupId = 'cg_' + crypto.createHmac('sha256', idKey)
    .update(JSON.stringify([principal, app, key])).digest('hex').slice(0, 32);
  return reservationInstance()._load(ctx({}), groupId);
}
async function ledger() {
  const rows = await sparql('settings', 'query', fence._test.stateQuery(principal, app));
  assert.equal(rows.length, 1);
  return { revision: Number(rows[0].revision.value), status: rows[0].status.value };
}
async function prepare() {
  await sparql('settings', 'update', 'INSERT DATA { ' + account +
    ' a <' + accountNs + 'AuthAccount> ; <' + accountNs + 'webId> ' +
    literal(principal) + ' . }');
  await createRegistration();
  assert.deepEqual(await ledger(), { revision: 1, status: 'stable' });
  await assert.rejects(reserve(keyA), err => err.type === 'COLLECTIVE_APP_CONSENT_MISSING');

  await createAuthorization();
  assert.deepEqual(await ledger(), { revision: 2, status: 'stable' });
  const first = await reserve(keyA);
  assert.equal(first.stage, 'reserved');
  assert.equal((await stored(keyA)).consentRevision, '2');

  await revokeAuthorization({ afterBegin: async () => {
    // The persisted SAI right still exists; durable pending marker must deny.
    assert.deepEqual(await ledger(), { revision: 3, status: 'blocked' });
    await assert.rejects(reserve(keyB),
      err => err.type === 'COLLECTIVE_CONSENT_FENCE_REQUIRED');
  } });
  assert.deepEqual(await ledger(), { revision: 3, status: 'stable' });
  await assert.rejects(reserve(keyB), err => err.type === 'COLLECTIVE_APP_CONSENT_MISSING');

  await createAuthorization();
  assert.deepEqual(await ledger(), { revision: 4, status: 'stable' });
  const second = await reserve(keyB);
  assert.equal(second.stage, 'reserved');
  await assert.rejects(reserve(keyA),
    err => err.type === 'COLLECTIVE_STALE_CONSENT_REVISION');
  assert.equal((await stored(keyB)).consentRevision, '4');
  console.log(JSON.stringify({ ok: true, proof: 'persisted-sai-revoke-regrant',
    phase: 'prepare', caveat: 'LDP and browser OAuth consent ceremony use fixture adapters' }));
}
async function verify() {
  assert.deepEqual(await ledger(), { revision: 4, status: 'stable' });
  assert(await getRegistration());
  assert.deepEqual((await getAuthorization())['apods:hasSpecialRights'], ['apods:CreateGroup']);
  assert.equal((await stored(keyA)).consentRevision, '2');
  assert.equal((await stored(keyB)).consentRevision, '4');
  await assert.rejects(reserve(keyA),
    err => err.type === 'COLLECTIVE_STALE_CONSENT_REVISION');
  const response = await reserve(keyB);
  assert.equal(response.stage, 'reserved');
  console.log(JSON.stringify({ ok: true, proof: 'persisted-sai-revoke-regrant',
    phase: 'verify', caveat: 'LDP and browser OAuth consent ceremony use fixture adapters' }));
}
(async () => {
  if (process.argv[2] === 'prepare') await prepare();
  else if (process.argv[2] === 'verify') await verify();
  else throw new Error('Expected prepare or verify');
})().catch(error => { console.error(error); process.exitCode = 1; });

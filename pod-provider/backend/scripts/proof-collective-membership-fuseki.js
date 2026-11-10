'use strict';
/**
 * Real isolated TDB2 proof of provider-owned Group membership CAS, keyset
 * reads and restart durability. Requires an explicitly disposable Fuseki.
 * No production datasets or credentials are ever inferred.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const rdf = require('../utils/collective-membership-rdf');

const base = process.env.FUSEKI_URL;
if (!base || !/^(?:http:\/\/127\.0\.0\.1|http:\/\/localhost):[0-9]+\/?$/u.test(base)) {
  throw new Error('Membership proof requires explicit localhost disposable FUSEKI_URL');
}
const dataset = 'settings';
const groupId = 'cg_1234567890abcdef1234567890abcdef';
const owner = 'https://paper-proof.example/users/alice#me';
const app = 'https://paper-proof.example/app';
const bob = 'https://remote-proof.example/users/bob';
const carol = 'https://remote-proof.example/users/carol';
const dan = 'https://remote-proof.example/users/dan';
const wrongOwner = 'https://paper-proof.example/users/eve#me';
const g = rdf.groupSubject(groupId);
const mutation = opts => rdf.mutateQuery({ ...opts, app, receipt: crypto.randomUUID() });
const uri = base.replace(/\/+$/u, '') + '/' + dataset;
const headers = {
  ...(process.env.FUSEKI_PASSWORD ? {
    Authorization: 'Basic ' + Buffer.from(
      (process.env.FUSEKI_USER || 'admin') + ':' + process.env.FUSEKI_PASSWORD).toString('base64')
  } : {})
};
async function request(kind, sparql) {
  const res = await fetch(uri + '/' + kind, {
    method: 'POST',
    headers: { ...headers,
      'content-type': 'application/sparql-' + (kind === 'update' ? 'update' : 'query'),
      accept: 'application/sparql-results+json' },
    body: sparql,
    signal: AbortSignal.timeout(20000)
  });
  const raw = await res.text();
  if (!res.ok) throw new Error('Fuseki ' + kind + ' returned HTTP ' + res.status + ' ' + raw.slice(0, 500));
  return kind === 'query' ? JSON.parse(raw).results.bindings : null;
}
function val(rows, field) {
  return rows[0] && rows[0][field] && rows[0][field].value;
}
async function epoch(ownerUri = owner) {
  const rows = await request('query', rdf.readEpochQuery({ groupId, owner: ownerUri, app }));
  if (rows.length === 0) return null;
  assert.equal(rows.length, 1);
  return Number(val(rows, 'epoch'));
}
async function members(cursor, limit = 100) {
  return request('query', rdf.listQuery({ groupId, owner, app, cursor, limit }));
}
async function prepare() {
  // Seed the real SemApps account ontology into the same settings dataset:
  // owner deletion, suspension and duplicate records must fence mutations.
  await request('update', 'INSERT DATA { <urn:apods:proof:g2-owner> ' +
    'a <http://semapps.org/ns/core#AuthAccount> ; ' +
    '<http://semapps.org/ns/core#webId> ' + JSON.stringify(owner) + ' . }');
  const ledger = rdf.consentSubject(owner, app);
  await request('update',
    'PREFIX apods: <http://activitypods.org/ns/core#>\n' +
    'INSERT DATA { ' + ledger + ' apods:collectiveConsentRevision "1" ; ' +
    'apods:collectiveConsentStatus "stable" . }');
  await request('update', 'PREFIX apods: <http://activitypods.org/ns/core#>\n' +
    'INSERT DATA { ' + g + ' a apods:CollectiveReservationV1 ; ' +
    'apods:collectiveOwner ' + JSON.stringify(owner) + ' ; ' +
    'apods:collectiveApp ' + JSON.stringify(app) + ' ; ' +
    'apods:canonicalGroupId ' + JSON.stringify(groupId) + ' ; ' +
    'apods:collectiveStage "reserved" . }');
  await request('update', rdf.initializeQuery({ groupId, owner, app }));
  await request('update', rdf.initializeQuery({ groupId, owner, app }));
  assert.equal(await epoch(), 1, 'Repeated initialize must not reset epoch');
  assert.equal(await epoch(wrongOwner), null, 'Foreign owner must not read registry');
  let rows = await members(null);
  assert.equal(rows.length, 1);
  assert.equal(val(rows, 'actor'), owner);
  assert.equal(val(rows, 'role'), 'owner');

  await request('update', mutation({
    groupId, owner, member: bob, role: 'member', status: 'active', expectedEpoch: 1
  }));
  assert.equal(await epoch(), 2);
  // The same optimistic epoch cannot authorize both mutations. TDB2
  // serializes updates in the authoritative settings dataset.
  await Promise.all([
    request('update', mutation({
      groupId, owner, member: carol, role: 'member', status: 'active', expectedEpoch: 2
    })),
    request('update', mutation({
      groupId, owner, member: dan, role: 'member', status: 'active', expectedEpoch: 2
    }))
  ]);
  assert.equal(await epoch(), 3);
  rows = await members(null);
  assert.equal(rows.length, 3, 'Exactly one concurrent CAS may win');
  const winner = rows.map(x => x.actor.value).find(x => x === carol || x === dan);
  assert(winner);
  // A foreign owner must not write despite knowing the Group and epoch.
  await request('update', mutation({
    groupId, owner: wrongOwner, member: dan, role: 'admin',
    status: 'active', expectedEpoch: 3
  }));
  assert.equal(await epoch(), 3);

  // Status tombstones preserve revision; banned members are excluded from
  // delivery snapshots without erasing audit/evolution semantics.
  await request('update', mutation({
    groupId, owner, member: bob, role: 'member', status: 'banned', expectedEpoch: 3
  }));
  assert.equal(await epoch(), 4);
  rows = await members(null, 1);
  assert.equal(rows.length, 2, 'Keyset LIMIT+1 must expose continuation');
  assert(rows[0].actor.value < rows[1].actor.value);
  const next = await members(rows[0].actor.value, 1);
  assert.equal(next.length, 1);
  assert.equal(next[0].actor.value, rows[1].actor.value);
  assert(!rows.some(x => x.actor.value === bob), 'Banned member leaked into active snapshot');
  // Account lifecycle invariants: deleting, suspending, disabling or
  // duplicating the owner record must DENY both reads and membership writes
  // within the same settings-dataset snapshot. Removing the test tombstone
  // simulates an authorized restoration, never a public account recovery API.
  const ownerSubject = '<urn:apods:proof:g2-owner>';
  const statusPredicate = '<http://semapps.org/ns/core#status>';
  const suspensionPredicate = '<http://semapps.org/ns/core#suspendedAt>';
  const deletionPredicate = '<http://semapps.org/ns/core#deletedAt>';
  for (const [predicate, value] of [
    [statusPredicate, '"disabled"'],
    [suspensionPredicate, '"2026-11-10T05:00:00Z"'],
    [deletionPredicate, '"2026-11-10T05:00:00Z"']
  ]) {
    await request('update', 'INSERT DATA { ' + ownerSubject + ' ' + predicate + ' ' + value + ' . }');
    assert.equal(await epoch(), null, 'Tombstoned owner must not read membership epoch');
    assert.equal((await members(null)).length, 0, 'Tombstoned owner must not enumerate members');
    await request('update', mutation({
      groupId, owner, member: dan, role: 'admin', status: 'active', expectedEpoch: 4
    }));
    await request('update', 'DELETE DATA { ' + ownerSubject + ' ' + predicate + ' ' + value + ' . }');
    assert.equal(await epoch(), 4, 'Tombstoned mutation changed the membership epoch');
  }
  // The same settings-dataset fence used by G1 consent mutation must
  // atomically block membership writes and private member enumeration.
  await request('update', 'PREFIX apods: <http://activitypods.org/ns/core#>\n' +
    'DELETE DATA { ' + ledger + ' apods:collectiveConsentStatus "stable" . }; ' +
    'INSERT DATA { ' + ledger + ' apods:collectiveConsentStatus "blocked" . }');
  assert.equal(await epoch(), null, 'Blocked SAI ledger must deny membership reads');
  assert.equal((await members(null)).length, 0, 'Blocked SAI ledger exposed members');
  await request('update', mutation({
    groupId, owner, member: dan, role: 'admin', status: 'active', expectedEpoch: 4
  }));
  await request('update', 'PREFIX apods: <http://activitypods.org/ns/core#>\n' +
    'DELETE DATA { ' + ledger + ' apods:collectiveConsentStatus "blocked" . }; ' +
    'INSERT DATA { ' + ledger + ' apods:collectiveConsentStatus "stable" . }');
  assert.equal(await epoch(), 4, 'Revoked consent still changed membership epoch');
  const duplicate = '<urn:apods:proof:g2-owner-duplicate>';
  const authAccount = '<http://semapps.org/ns/core#AuthAccount>';
  const webId = '<http://semapps.org/ns/core#webId>';
  await request('update', 'INSERT DATA { ' + duplicate + ' a ' + authAccount +
    ' ; ' + webId + ' ' + JSON.stringify(owner) + ' . }');
  assert.equal(await epoch(), null, 'Duplicated AuthAccount must block reads');
  await request('update', mutation({
    groupId, owner, member: dan, role: 'admin', status: 'active', expectedEpoch: 4
  }));
  await request('update', 'DELETE DATA { ' + duplicate + ' a ' + authAccount +
    ' ; ' + webId + ' ' + JSON.stringify(owner) + ' . }');
  assert.equal(await epoch(), 4, 'Duplicate account changed membership revision');
  assert.equal((await members(null)).length, 2);

  console.log(JSON.stringify({ ok: true, proof: 'g2-membership-tdb2-cas', phase: 'prepare',
    epoch: 4, activeMemberCount: 2, writeConflictsRejected: true }));
}
async function verify() {
  assert.equal(await epoch(), 4);
  const rows = await members(null);
  assert.equal(rows.length, 2);
  assert(!rows.some(x => x.actor.value === bob));
  assert(rows.some(x => x.actor.value === owner));
  console.log(JSON.stringify({ ok: true, proof: 'g2-membership-tdb2-cas',
    phase: 'verify-after-restart', epoch: 4 }));
}
(async () => {
  if (process.argv[2] === 'prepare') await prepare();
  else if (process.argv[2] === 'verify') await verify();
  else throw new Error('Expected prepare or verify');
})().catch(e => { console.error(e.message); process.exitCode = 1; });

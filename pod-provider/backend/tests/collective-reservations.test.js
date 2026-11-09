'use strict';

const crypto = require('node:crypto');
const service = require('../services/collective-reservations.service');

const SECRET = 'z'.repeat(48);
const WORKER_SECRET = 'w'.repeat(48);
const WORKER_PURPOSE = 'provider.collective.worker.advance.v1';
const TEST_LEASE_TOKEN = 'x'.repeat(43);
const TEST_LEASE_EPOCH = '00000000-0000-4000-8000-000000000001';
const TEST_WORKER_ID = 'worker-node-001';
const PROVIDER = 'https://social.example';
const PRINCIPAL = PROVIDER + '/users/alice';
const APP = 'https://reader.example/app';
const IDEMPOTENCY = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const PURPOSE = 'provider.collective.reservation.v1';

function sha(x) { return crypto.createHash('sha256').update(x).digest('hex'); }
function createGrant(principal, app, operation, requestHash) {
  const issuedAt = Date.now() - 500;
  const expiresAt = issuedAt + 50000;
  const fields = [PURPOSE, principal, app, operation, requestHash, issuedAt, expiresAt];
  return { purpose: PURPOSE, principal, app, operation, requestHash, issuedAt, expiresAt,
    mac: crypto.createHmac('sha256', SECRET).update(JSON.stringify(fields)).digest('hex') };
}
function reservation(overrides = {}) {
  const p = { principal: PRINCIPAL, app: APP, idempotencyKey: IDEMPOTENCY, displayName: 'Research Circle', ...overrides };
  const hash = sha(JSON.stringify([p.principal, p.app, p.idempotencyKey, p.displayName]));
  return { ...p, grant: createGrant(p.principal, p.app, 'reserve', hash) };
}
function readGrant(groupId, overrides = {}) {
  return { principal: PRINCIPAL, app: APP, canonicalGroupId: groupId,
    grant: createGrant(PRINCIPAL, APP, 'read', groupId), ...overrides };
}
function advanceGrant(groupId, expectedRevision, nextStage, overrides = {}) {
  const issuedAt = Date.now() - 500;
  const expiresAt = issuedAt + 50000;
  const workerId = overrides.workerId || TEST_WORKER_ID;
  const leaseToken = overrides.leaseToken || TEST_LEASE_TOKEN;
  const leaseEpoch = overrides.leaseEpoch || TEST_LEASE_EPOCH;
  const leaseHash = sha(leaseToken);
  const fields = [WORKER_PURPOSE, groupId, expectedRevision, nextStage,
    workerId, leaseEpoch, leaseHash, issuedAt, expiresAt];
  const workerGrant = { purpose: WORKER_PURPOSE, groupId,
    revision: expectedRevision, nextStage, workerId, leaseEpoch, leaseHash,
    issuedAt, expiresAt,
    mac: crypto.createHmac('sha256', WORKER_SECRET).update(JSON.stringify(fields)).digest('hex') };
  return { principal: PRINCIPAL, app: APP, canonicalGroupId: groupId, expectedRevision, nextStage,
    workerId, leaseToken, leaseEpoch, workerGrant, ...overrides };
}
function materialize(query) {
  const id = /<urn:apods:collective:([^>]+)> a <http:\/\/activitypods\.org\/ns\/core#CollectiveReservationV1>/u.exec(query)?.[1];
  if (!id) throw new Error('Unexpected reservation SPARQL syntax');
  const fields = {};
  for (const m of query.matchAll(/<http:\/\/activitypods\.org\/ns\/core#([A-Za-z]+)> ("(?:\\.|[^"])*")/gu)) {
    fields[m[1]] = JSON.parse(m[2]);
  }
  return { id, owner: fields.collectiveOwner, app: fields.collectiveApp,
    actorUri: fields.activityPubActorId, requestHash: fields.collectiveRequestHash,
    displayName: fields.collectiveDisplayName, stage: fields.collectiveStage,
    revision: Number(fields.collectiveRevision) };
}
function harness(db = new Map()) {
  const calls = [];
  let failWrite = false;
  let onBeforeWrite = null;
  let registered = true;
  let rights = ['apods:CreateGroup', 'apods:ReadGroups'];
  const instance = { settings: { enabled: true, providerOrigin: PROVIDER, secret: SECRET, identityKey: 'i'.repeat(48), workerSecret: WORKER_SECRET, approvedApps: [APP, 'https://forum.example/app'] } };
  instance._load = service.methods._load.bind(instance);
  const ctx = params => ({
    params, call: async (name, args) => {
      calls.push({ name, args });
      if (name === 'auth.account.findByWebId') return { webId: args.webId };
      if (name === 'app-registrations.isRegistered') return registered;
      if (name === 'access-authorizations.getSpecialRights') return rights;
      if (!['triplestore.query', 'triplestore.update'].includes(name)) throw new Error('Unexpected service call');
      expect(args.dataset).toBe('settings');
      expect(args.webId).toBe('system');
      if (name === 'triplestore.query') {
        const id = /<urn:apods:collective:([^>]+)> a apods:CollectiveReservationV1/u.exec(args.query)?.[1];
        if (!id) throw new Error('Unexpected query');
        const row = db.get(id);
        return row ? [Object.fromEntries(Object.entries(row).filter(([k]) => k !== 'id').map(([k, v]) => [k, { value: String(v) }]))] : [];
      }
      if (failWrite) throw new Error('Fuseki write unavailable');
      if (onBeforeWrite) {
        const hook = onBeforeWrite;
        onBeforeWrite = null;
        await hook();
      }
      if (args.query.startsWith('INSERT { ')) {
        const row = materialize(args.query);
        if (!db.has(row.id)) db.set(row.id, {
          ...row,
          // A worker lease is pre-acquired in the stage unit fixture.
          // Actual lease contention is exercised against live Fuseki separately.
          leaseOwner: TEST_WORKER_ID,
          leaseHash: sha(TEST_LEASE_TOKEN),
          leaseEpoch: TEST_LEASE_EPOCH,
          leaseUntil: Date.now() + 30000
        }); // Jena conditional INSERT semantics
      } else if (args.query.includes('DELETE {')) {
        const id = /<urn:apods:collective:([^>]+)> apods:collectiveStage/u.exec(args.query)?.[1];
        const m = /DELETE \{ [^\n]+ apods:collectiveStage ("[^"]+")\s+; apods:collectiveRevision ("[^"]+")/u.exec(args.query);
        const insert = /INSERT \{ [^\n]+ apods:collectiveStage ("[^"]+")\s+; apods:collectiveRevision ("[^"]+")/u.exec(args.query);
        if (!id || !m || !insert) throw new Error('Unexpected CAS SPARQL syntax');
        const row = db.get(id);
        if (row && row.stage === JSON.parse(m[1]) && row.revision === Number(JSON.parse(m[2])) &&
            row.leaseOwner === TEST_WORKER_ID && row.leaseHash === sha(TEST_LEASE_TOKEN) &&
            row.leaseEpoch === TEST_LEASE_EPOCH && row.leaseUntil > Date.now() &&
            args.query.includes('apods:collectiveLeaseOwner ' + JSON.stringify(row.leaseOwner)) &&
            args.query.includes('apods:collectiveLeaseHash ' + JSON.stringify(row.leaseHash)) &&
            args.query.includes('apods:collectiveLeaseEpoch ' + JSON.stringify(row.leaseEpoch))) {
          const nonce = /apods:collectiveLastTransition ("[^"]+")/u.exec(args.query);
          if (!nonce) throw new Error('Missing transition nonce');
          db.set(id, { ...row, stage: JSON.parse(insert[1]),
            revision: Number(JSON.parse(insert[2])), lastTransition: JSON.parse(nonce[1]) });
        }
      } else throw new Error('Unexpected update');
    }
  });
  async function action(name, params) {
    return service.actions[name].handler.call(instance, ctx(params));
  }
  return { db, calls, instance, action, setFailWrite(v) { failWrite = v; },
    setBeforeWrite(fn) { onBeforeWrite = fn; },
    setRegistration(v) { registered = v; }, setRights(v) { rights = v; } };
}
async function expectError(promise, code) {
  try { await promise; } catch (err) { expect(err.type).toBe(code); return; }
  throw new Error('Expected error ' + code);
}

describe('G1 durable collective reservations — provider authority', () => {
  test('reserves a deterministic opaque Group URI and persists it in provider Fuseki', async () => {
    const h = harness();
    const first = await h.action('reserve', reservation());
    const second = await h.action('reserve', reservation());
    expect(first).toEqual(second);
    expect(first.canonicalGroupId).toMatch(/^cg_[a-f0-9]{32}$/);
    expect(first.actorUri).toBe(PROVIDER + '/groups/' + first.canonicalGroupId);
    expect(first.stage).toBe('reserved');
    expect(h.db.size).toBe(1);
    expect([...h.db.values()][0]).toMatchObject({ owner: PRINCIPAL, app: APP, revision: 1 });
    expect(h.calls.some(c => c.args.query?.includes('FILTER NOT EXISTS'))).toBe(true);
    expect(h.calls.filter(c => c.name === 'triplestore.update').every(c => c.args.dataset === 'settings')).toBe(true);
  });

  test('mid-flight SAI revocation denies success, even if an inactive record was written', async () => {
    const h = harness();
    h.setBeforeWrite(() => h.setRights([]));
    await expectError(h.action('reserve', reservation()), 'COLLECTIVE_APP_CONSENT_MISSING');
    // Cross-store writes are not atomic: the inert reservation may exist. It
    // must never be confused with an activated actor or production fencing.
    expect(h.db.size).toBe(1);
    expect([...h.db.values()][0].stage).toBe('reserved');
    expect(h.calls.filter(x => x.name === 'access-authorizations.getSpecialRights'))
      .toHaveLength(2);
    h.setRights(['apods:CreateGroup', 'apods:ReadGroups']);
    const retry = await h.action('reserve', reservation());
    expect(retry.stage).toBe('reserved');
    expect(h.db.size).toBe(1);
  });

  test('different payload with same principal, app and idempotency key fails closed', async () => {
    const h = harness();
    await h.action('reserve', reservation());
    await expectError(h.action('reserve', reservation({ displayName: 'Hijacked' })), 'COLLECTIVE_RESERVATION_CONFLICT');
    expect(h.db.size).toBe(1);
    expect([...h.db.values()][0].displayName).toBe('Research Circle');
  });

  test('independent apps have independent operation and idempotency scopes', async () => {
    const h = harness();
    const a = await h.action('reserve', reservation());
    const b = await h.action('reserve', reservation({ app: 'https://forum.example/app' }));
    expect(a.canonicalGroupId).not.toBe(b.canonicalGroupId);
    const throughOtherApp = await h.action('get', readGrant(a.canonicalGroupId, {
      app: 'https://forum.example/app',
      grant: createGrant(PRINCIPAL, 'https://forum.example/app', 'read', a.canonicalGroupId)
    }));
    expect(throughOtherApp.canonicalGroupId).toBe(a.canonicalGroupId);
    // An app-specific provider grant remains required for each operation.
    await expectError(h.action('get', readGrant(a.canonicalGroupId, {
      app: 'https://forum.example/app'
    })), 'COLLECTIVE_UNAUTHORIZED');
  });

  test('simultaneous identical reservations converge on one durable record', async () => {
    const h = harness();
    const [a, b] = await Promise.all([h.action('reserve', reservation()), h.action('reserve', reservation())]);
    expect(a).toEqual(b);
    expect(h.db.size).toBe(1);
  });

  test('fenced worker refuses legacy or revoked SAI consent before stage write', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    h.instance.settings.consentBridgeEnabled = true;
    const next = advanceGrant(id, 1, 'ap-key-pending');

    // Legacy reservations without a recorded consent revision cannot be
    // activated by flipping deployment flags.
    await expectError(h.action('advance', next), 'COLLECTIVE_CONSENT_FENCE_REQUIRED');
    expect(h.db.get(id).stage).toBe('reserved');

    h.db.get(id).consentRevision = '1';
    h.setRights([]);
    await expectError(h.action('advance', next), 'COLLECTIVE_APP_CONSENT_MISSING');
    expect(h.db.get(id).stage).toBe('reserved');

    h.setRights(['apods:CreateGroup', 'apods:ReadGroups']);
    // The storage CAS must check the owner/app ledger and the original
    // revision in the *same* Fuseki update as the stage transition.
    await h.action('advance', next);
    const writes = h.calls.filter(c => c.name === 'triplestore.update');
    expect(writes[writes.length - 1].args.query).toContain('collectiveConsentRevision ?liveConsentRevision');
    expect(writes[writes.length - 1].args.query).toContain('collectivePendingMutation ?pending');
  });

  test('different authorized app can advance the same provider-owned group', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    const secondary = 'https://forum.example/app';
    const grant = advanceGrant(id, 1, 'ap-key-pending', {
      app: secondary,
      // The provider worker authorizes the stage; app identity is not the signer.
    });
    const updated = await h.action('advance', grant);
    expect(updated).toMatchObject({ canonicalGroupId: id, stage: 'ap-key-pending', revision: 2 });
    expect(h.db.get(id).app).toBe(APP); // Creator provenance, not governing authority.
  });

  test('valid token for another user cannot read or advance the creator group', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    const bob = PROVIDER + '/users/bob';
    await expectError(h.action('get', readGrant(id, {
      principal: bob, grant: createGrant(bob, APP, 'read', id)
    })), 'COLLECTIVE_NOT_FOUND');
    await expectError(h.action('advance', advanceGrant(id, 1, 'ap-key-pending', {
      principal: bob,
      // A legitimate worker credential still cannot impersonate the owner.
    })), 'COLLECTIVE_NOT_FOUND');
  });

  test('supports canonical Solid WebIDs ending in #me without accepting fragment app URIs', async () => {
    const h = harness();
    const webId = PROVIDER + '/profile/card#me';
    const reserved = await h.action('reserve', reservation({ principal: webId }));
    const result = await h.action('get', readGrant(reserved.canonicalGroupId, {
      principal: webId,
      grant: createGrant(webId, APP, 'read', reserved.canonicalGroupId)
    }));
    expect(result.canonicalGroupId).toBe(reserved.canonicalGroupId);
    expect(h.db.get(reserved.canonicalGroupId).owner).toBe(webId);
    await expectError(h.action('reserve', reservation({
      principal: webId, app: APP + '#impersonated'
    })), 'COLLECTIVE_INVALID_URI');
  });

  test('normalizes one provider-origin trailing slash without changing the actor path', async () => {
    const h = harness();
    h.instance.settings.providerOrigin = PROVIDER + '/';
    const record = await h.action('reserve', reservation());
    expect(record.actorUri).toBe(PROVIDER + '/groups/' + record.canonicalGroupId);
    expect(record.actorUri).not.toContain('.example//groups/');
  });

  test('fails closed on a provider origin that contains a path or credentials', async () => {
    for (const bad of [PROVIDER + '/path', 'https://alice:password@social.example']) {
      const h = harness();
      h.instance.settings.providerOrigin = bad;
      await expectError(h.action('reserve', reservation()), 'COLLECTIVE_INVALID_PROVIDER');
      expect(h.calls).toHaveLength(0);
    }
  });

  test('rotating grant signer secret must not change canonical Group IDs', async () => {
    const h = harness();
    const first = await h.action('reserve', reservation());
    // Identity key remains stable across grant signing key rotation.
    const savedSecret = h.instance.settings.secret;
    h.instance.settings.secret = 'r'.repeat(48);
    const p = reservation();
    const issuedAt = Date.now() - 500;
    const expiresAt = issuedAt + 50000;
    // Re-sign the same request fingerprint with the rotated grant key.
    p.grant = {
      purpose: PURPOSE, principal: p.principal, app: p.app,
      operation: 'reserve',
      requestHash: sha(JSON.stringify([p.principal, p.app, p.idempotencyKey, p.displayName])),
      issuedAt, expiresAt
    };
    p.grant.mac = crypto.createHmac('sha256', h.instance.settings.secret)
      .update(JSON.stringify([PURPOSE, p.principal, p.app, 'reserve', p.grant.requestHash, issuedAt, expiresAt]))
      .digest('hex');
    expect((await h.action('reserve', p)).canonicalGroupId).toBe(first.canonicalGroupId);
    expect(h.db.size).toBe(1);
    h.instance.settings.secret = savedSecret;
  });

  test('restart of the service retains the source-of-truth state', async () => {
    const persistent = new Map();
    const first = harness(persistent);
    const result = await first.action('reserve', reservation());
    const restarted = harness(persistent);
    const loaded = await restarted.action('get', readGrant(result.canonicalGroupId));
    expect(loaded).toMatchObject({ canonicalGroupId: result.canonicalGroupId, stage: 'reserved', revision: 1 });
  });

  test('does not reserve anything on missing, spoofed or tampered authorization', async () => {
    const h = harness();
    const good = reservation();
    for (const bad of [
      { ...good, grant: {} },
      { ...good, grant: undefined },
      { ...good, grant: { ...good.grant, principal: PROVIDER + '/users/bob' } },
      { ...good, grant: { ...good.grant, mac: 'a'.repeat(64) } },
      { ...good, grant: { ...good.grant, mac: 'é'.repeat(64) } },
      { ...good, grant: { ...good.grant, mac: '🚫'.repeat(32) } },
      { ...good, grant: { ...good.grant, expiresAt: Date.now() - 1 } },
      { ...good, grant: { ...good.grant, operation: 'read' } }
    ]) await expectError(h.action('reserve', bad), 'COLLECTIVE_UNAUTHORIZED');
    expect(h.db.size).toBe(0);
    expect(h.calls.length).toBe(0);
  });

  test('revoking SAI permissions rejects new operations despite still-valid HMAC grants', async () => {
    const h = harness();
    const first = await h.action('reserve', reservation());
    h.setRights([]);
    await expectError(h.action('get', readGrant(first.canonicalGroupId)), 'COLLECTIVE_APP_CONSENT_MISSING');
    await expectError(h.action('reserve', reservation({ idempotencyKey: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' })),
      'COLLECTIVE_APP_CONSENT_MISSING');
    expect(h.db.size).toBe(1);
  });

  test('removing app registration prevents new Group reads and reservations', async () => {
    const h = harness();
    const first = await h.action('reserve', reservation());
    h.setRegistration(false);
    await expectError(h.action('get', readGrant(first.canonicalGroupId)), 'COLLECTIVE_APP_NOT_REGISTERED');
    await expectError(h.action('reserve', reservation({ idempotencyKey: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' })),
      'COLLECTIVE_APP_NOT_REGISTERED');
  });

  test('provider-approved app allowlist is enforced independently of signed grant', async () => {
    const h = harness();
    h.instance.settings.approvedApps = [];
    await expectError(h.action('reserve', reservation()), 'COLLECTIVE_APP_NOT_APPROVED');
    expect(h.db.size).toBe(0);
  });

  test('provider policy disabled and missing issuer secret fail before database access', async () => {
    const h = harness();
    h.instance.settings.enabled = false;
    await expectError(h.action('reserve', reservation()), 'COLLECTIVE_DISABLED');
    h.instance.settings.enabled = true;
    h.instance.settings.secret = '';
    await expectError(h.action('reserve', reservation()), 'COLLECTIVE_DISABLED');
    h.instance.settings.secret = SECRET;
    h.instance.settings.identityKey = '';
    await expectError(h.action('reserve', reservation()), 'COLLECTIVE_DISABLED');
    expect(h.calls).toHaveLength(0);
  });

  test('rejects spoofed URI and insufficient idempotency input before DB access', async () => {
    const h = harness();
    for (const bad of [
      { ...reservation(), principal: 'http://social.example/users/alice' },
      { ...reservation(), principal: 'https://evil.example\\@social.example/a' },
      { ...reservation(), app: 'https://reader.example/app#spoof' },
      { ...reservation(), idempotencyKey: '1' }
    ]) {
      await expect(h.action('reserve', bad)).rejects.toBeTruthy();
    }
    expect(h.calls).toHaveLength(0);
  });

  test('failure of authoritative write never produces success and can be retried', async () => {
    const h = harness();
    h.setFailWrite(true);
    await expect(h.action('reserve', reservation())).rejects.toThrow('Fuseki write unavailable');
    expect(h.db.size).toBe(0);
    h.setFailWrite(false);
    const record = await h.action('reserve', reservation());
    expect(record.stage).toBe('reserved');
    expect(h.db.size).toBe(1);
  });

  test('CAS stage progression is revision-fenced and cannot jump or become active', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    await expectError(h.action('advance', advanceGrant(id, 1, 'did-pending')), 'COLLECTIVE_INVALID_TRANSITION');
    const progress = await h.action('advance', advanceGrant(id, 1, 'ap-key-pending'));
    expect(progress).toMatchObject({ canonicalGroupId: id, revision: 2, stage: 'ap-key-pending' });
    await expectError(h.action('advance', advanceGrant(id, 1, 'did-pending')), 'COLLECTIVE_STALE_REVISION');
    const next = await h.action('advance', advanceGrant(id, 2, 'did-pending'));
    expect(next.revision).toBe(3);
    expect(next.stage).toBe('did-pending');
    await expectError(h.action('advance', advanceGrant(id, 3, 'ap-key-pending')), 'COLLECTIVE_INVALID_TRANSITION');
    expect(h.db.get(id).stage).not.toBe('active');
  });

  test('transition signing cannot be transplanted between two worker leases', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    const original = advanceGrant(id, 1, 'ap-key-pending');
    const transplanted = {
      ...original, workerId: 'another-worker-id',
      leaseToken: 'y'.repeat(43),
      leaseEpoch: '00000000-0000-4000-8000-000000000002'
    };
    await expectError(h.action('advance', transplanted), 'COLLECTIVE_WORKER_UNAUTHORIZED');
    expect(h.db.get(id).stage).toBe('reserved');
  });

  test('stage mutation cannot bypass a missing, expired or transferred worker lease', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    const row = h.db.get(id);
    row.leaseUntil = Date.now() - 1000;
    await expectError(h.action('advance', advanceGrant(id, 1, 'ap-key-pending')),
      'COLLECTIVE_STALE_REVISION');
    row.leaseUntil = Date.now() + 30000;
    await expectError(h.action('advance', advanceGrant(id, 1, 'ap-key-pending', {
      leaseToken: 'y'.repeat(43)
    })), 'COLLECTIVE_STALE_REVISION');
    await expectError(h.action('advance', advanceGrant(id, 1, 'ap-key-pending', {
      leaseEpoch: '00000000-0000-4000-8000-000000000002'
    })), 'COLLECTIVE_STALE_REVISION');
    await expectError(h.action('advance', advanceGrant(id, 1, 'ap-key-pending', {
      workerId: 'wrong-worker-id'
    })), 'COLLECTIVE_STALE_REVISION');
    delete row.leaseOwner;
    await expectError(h.action('advance', advanceGrant(id, 1, 'ap-key-pending')),
      'COLLECTIVE_STALE_REVISION');
    expect(row.revision).toBe(1);
    expect(row.stage).toBe('reserved');
  });

  test('two workers with the same revision cannot both perform a CAS transition', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    const results = await Promise.allSettled([
      h.action('advance', advanceGrant(id, 1, 'ap-key-pending')),
      h.action('advance', advanceGrant(id, 1, 'ap-key-pending'))
    ]);
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(r => r.status === 'rejected')).toHaveLength(1);
    expect(h.db.get(id).revision).toBe(2);
  });

  test('read and advance are scoped independently from reservation grant', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    await expectError(h.action('get', { ...readGrant(id), grant: reservation().grant }), 'COLLECTIVE_UNAUTHORIZED');
    await expectError(h.action('advance', { ...advanceGrant(id, 1, 'ap-key-pending'),
      workerGrant: readGrant(id).grant }), 'COLLECTIVE_WORKER_UNAUTHORIZED');
    await expectError(h.action('advance', { ...advanceGrant(id, 1, 'ap-key-pending'),
      workerGrant: { ...advanceGrant(id, 1, 'ap-key-pending').workerGrant,
        mac: 'é'.repeat(64) } }), 'COLLECTIVE_WORKER_UNAUTHORIZED');
  });

  test('app-level HMAC grant cannot advance a provider-only lifecycle', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    const proper = advanceGrant(id, 1, 'ap-key-pending');
    await expectError(h.action('advance', { ...proper, workerGrant: createGrant(PRINCIPAL, APP,
      'advance', sha(JSON.stringify([id, 1, 'ap-key-pending']))) }), 'COLLECTIVE_WORKER_UNAUTHORIZED');
    await expectError(h.action('advance', { ...proper, workerGrant: {
      ...proper.workerGrant, mac: '0'.repeat(64)
    } }), 'COLLECTIVE_WORKER_UNAUTHORIZED');
    expect(h.db.get(id).revision).toBe(1);
  });

  test('missing worker secret disables transitions even with otherwise valid credentials', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    h.instance.settings.workerSecret = '';
    await expectError(h.action('advance', advanceGrant(id, 1, 'ap-key-pending')),
      'COLLECTIVE_WORKER_DISABLED');
    expect(h.db.get(id).revision).toBe(1);
  });

  test('corrupt or duplicate source records fail closed', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    h.db.get(id).revision = 0;
    await expectError(h.action('get', readGrant(id)), 'COLLECTIVE_CORRUPT_STATE');
  });
});

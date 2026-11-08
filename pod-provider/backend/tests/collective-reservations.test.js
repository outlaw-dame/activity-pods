'use strict';

const crypto = require('node:crypto');
const service = require('../services/collective-reservations.service');

const SECRET = 'z'.repeat(48);
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
  return { principal: PRINCIPAL, app: APP, canonicalGroupId: groupId, expectedRevision, nextStage,
    grant: createGrant(PRINCIPAL, APP, 'advance',
      sha(JSON.stringify([groupId, expectedRevision, nextStage]))), ...overrides };
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
  const instance = { settings: { enabled: true, providerOrigin: PROVIDER, secret: SECRET } };
  instance._load = service.methods._load.bind(instance);
  const ctx = params => ({
    params, call: async (name, args) => {
      calls.push({ name, args });
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
      if (args.query.startsWith('INSERT { ')) {
        const row = materialize(args.query);
        if (!db.has(row.id)) db.set(row.id, row); // Jena conditional INSERT semantics
      } else if (args.query.includes('DELETE {')) {
        const id = /<urn:apods:collective:([^>]+)> apods:collectiveStage/u.exec(args.query)?.[1];
        const m = /DELETE \{ [^\n]+ apods:collectiveStage ("[^"]+")\s+; apods:collectiveRevision ("[^"]+")/u.exec(args.query);
        const insert = /INSERT \{ [^\n]+ apods:collectiveStage ("[^"]+")\s+; apods:collectiveRevision ("[^"]+")/u.exec(args.query);
        if (!id || !m || !insert) throw new Error('Unexpected CAS SPARQL syntax');
        const row = db.get(id);
        if (row && row.stage === JSON.parse(m[1]) && row.revision === Number(JSON.parse(m[2]))) {
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
  return { db, calls, instance, action, setFailWrite(v) { failWrite = v; } };
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
    await expectError(h.action('get', readGrant(a.canonicalGroupId, {
      app: 'https://forum.example/app',
      grant: createGrant(PRINCIPAL, 'https://forum.example/app', 'read', a.canonicalGroupId)
    })), 'COLLECTIVE_NOT_FOUND');
  });

  test('simultaneous identical reservations converge on one durable record', async () => {
    const h = harness();
    const [a, b] = await Promise.all([h.action('reserve', reservation()), h.action('reserve', reservation())]);
    expect(a).toEqual(b);
    expect(h.db.size).toBe(1);
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
      { ...good, grant: { ...good.grant, expiresAt: Date.now() - 1 } },
      { ...good, grant: { ...good.grant, operation: 'read' } }
    ]) await expectError(h.action('reserve', bad), 'COLLECTIVE_UNAUTHORIZED');
    expect(h.db.size).toBe(0);
    expect(h.calls.length).toBe(0);
  });

  test('provider policy disabled and missing issuer secret fail before database access', async () => {
    const h = harness();
    h.instance.settings.enabled = false;
    await expectError(h.action('reserve', reservation()), 'COLLECTIVE_DISABLED');
    h.instance.settings.enabled = true;
    h.instance.settings.secret = '';
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
      grant: readGrant(id).grant }), 'COLLECTIVE_UNAUTHORIZED');
  });

  test('corrupt or duplicate source records fail closed', async () => {
    const h = harness();
    const { canonicalGroupId: id } = await h.action('reserve', reservation());
    h.db.get(id).revision = 0;
    await expectError(h.action('get', readGrant(id)), 'COLLECTIVE_CORRUPT_STATE');
  });
});

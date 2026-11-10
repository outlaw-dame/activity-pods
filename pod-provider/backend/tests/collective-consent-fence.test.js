'use strict';

const crypto = require('node:crypto');
const fence = require('../services/collective-consent-fence.service');
const authorizations = require('../services/sai/access-authorizations');
const registrations = require('../services/sai/app-registrations');

const principal = 'https://provider.example/users/alice#me';
const app = 'https://paper.example/app';
const groupRights = ['apods:CreateGroup'];

function fenceCtx({ rows = [{ status: { value: 'blocked' }, revision: { value: '2' } }],
  throwOn = null } = {}) {
  const calls = [];
  const ctx = {
    params: { principal, app },
    async call(name, params) {
      calls.push({ name, params });
      if (throwOn === name) throw new Error('storage unavailable');
      if (name === 'triplestore.query') return rows;
      return {};
    }
  };
  return { ctx, calls };
}

describe('operator-signed initial SAI bootstrap', () => {
  const secret = 'b'.repeat(48);
  const authorized = (overrides = {}) => {
    const issuedAt = Date.now() - 1000;
    const expiresAt = issuedAt + 30000;
    const purpose = 'provider.collective.consent.bootstrap.v1';
    const grant = { purpose, principal, app, issuedAt, expiresAt };
    grant.mac = crypto.createHmac('sha256', secret)
      .update(JSON.stringify([purpose, principal, app, issuedAt, expiresAt])).digest('hex');
    const calls = [];
    const ctx = {
      params: { principal, app, grant: { ...grant, ...overrides } },
      async call(name, params) {
        calls.push(name);
        if (name === 'auth.account.findByWebId') return { webId: principal };
        if (name === 'app-registrations.isRegistered') return true;
        if (name === 'access-authorizations.getSpecialRights') return ['apods:CreateGroup'];
        if (name === 'triplestore.query') {
          return [{ revision: { value: '1' }, status: { value: 'stable' } }];
        }
        return true;
      }
    };
    const settings = { enabled: true, bootstrapEnabled: true,
      bootstrapSecret: secret, approvedApps: [app] };
    return { ctx, settings, calls };
  };
  test('requires a signed, app- and WebID-bound operator grant', async () => {
    const h = authorized();
    await expect(fence.actions.bootstrap.handler.call({ settings: h.settings }, h.ctx))
      .resolves.toEqual({ revision: 1, status: 'stable' });
    expect(h.calls).toEqual([
      'auth.account.findByWebId', 'app-registrations.isRegistered',
      'access-authorizations.getSpecialRights', 'triplestore.update',
      'triplestore.query', 'auth.account.findByWebId',
      'app-registrations.isRegistered', 'access-authorizations.getSpecialRights'
    ]);
  });
  test('wrong grant is rejected without any storage or SAI read', async () => {
    const h = authorized({ mac: '0'.repeat(64) });
    await expect(fence.actions.bootstrap.handler.call({ settings: h.settings }, h.ctx))
      .rejects.toMatchObject({ type: 'COLLECTIVE_BOOTSTRAP_UNAUTHORIZED' });
    expect(h.calls).toHaveLength(0);
  });
  test('a prior blocked or advanced ledger cannot be revived by bootstrap', async () => {
    const h = authorized();
    const old = h.ctx.call;
    h.ctx.call = async (name, params) => {
      if (name === 'triplestore.query') return [
        { revision: { value: '2' }, status: { value: 'blocked' } }
      ];
      return old(name, params);
    };
    await expect(fence.actions.bootstrap.handler.call({ settings: h.settings }, h.ctx))
      .rejects.toMatchObject({ type: 'COLLECTIVE_CONSENT_FENCE_UNVERIFIED' });
  });
  test('bridge/bootstrap gates default to denied', async () => {
    const h = authorized();
    await expect(fence.actions.bootstrap.handler.call({
      settings: { ...h.settings, bootstrapEnabled: false }
    }, h.ctx)).rejects.toMatchObject({ type: 'COLLECTIVE_BOOTSTRAP_DISABLED' });
  });
  test('SPARQL initializes virgin identity only, never clears existing markers', () => {
    const sql = fence._test.bootstrapQuery(principal, app);
    expect(sql).toContain('FILTER NOT EXISTS');
    expect(sql).not.toContain('DELETE');
    expect(sql).toContain('collectiveConsentStatus "stable"');
  });
});

describe('durable deny-first collective consent fence', () => {
  test('canonical per-person/app hashed identity; do not place URLs in SPARQL', () => {
    const a = fence._test.subject(principal, app);
    expect(a).toMatch(/^<urn:apods:collective-consent:[a-f0-9]{64}>$/u);
    expect(a).toBe(fence._test.subject(principal, app));
    expect(a).not.toBe(fence._test.subject(principal, 'https://other.example/app'));
  });
  test.each([
    ['http://provider.example/alice', app],
    ['https://provider.example/alice', 'http://paper.example/app'],
    ['https://provider.example/alice', 'https://paper.example/app#fragment'],
    ['https://provider.example/alice', 'https://user:pass@paper.example/app'],
    ['https://provider.example/alice', 'https://paper.example/app?secret=yes'],
    ['not-a-webid', app]
  ])('rejects invalid principal/app identifiers (%s, %s)', (person, client) => {
    expect(() => fence._test.subject(person, client)).toThrow();
  });
  test('begin allocates a durable pending token and increments revision', async () => {
    const f = fenceCtx();
    const result = await fence.actions.begin.handler.call({ settings: { enabled: true } }, f.ctx);
    expect(result.status).toBe('blocked');
    expect(result.revision).toBe(2);
    expect(result.token).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
    expect(f.calls.map(x => x.name)).toEqual(['triplestore.update', 'triplestore.query']);
    expect(f.calls[0].params.query).toContain('collectivePendingMutation');
    expect(f.calls[1].params.query).toContain(result.token);
  });
  test('finish requires a proven completed-token marker; no other pending writes', async () => {
    const token = '11111111-1111-4111-8111-111111111111';
    const f = fenceCtx({ rows: [{ status: { value: 'stable' }, revision: { value: '3' } }] });
    const result = await fence.actions.finish.handler.call({ settings: { enabled: true } }, {
      ...f.ctx, params: { principal, app, token }
    });
    expect(result).toEqual({ status: 'stable', revision: 3 });
    expect(f.calls[0].params.query).toContain('collectiveCompletedMutation');
    expect(f.calls[0].params.query).toContain('FILTER NOT EXISTS');
    expect(f.calls[1].params.query).toContain(token);
  });
  test('finish cannot accept forged/non-UUID tokens', async () => {
    const f = fenceCtx();
    await expect(fence.actions.finish.handler.call({ settings: { enabled: true } }, {
      ...f.ctx, params: { principal, app, token: 'bogus' }
    })).rejects.toMatchObject({ type: 'COLLECTIVE_INVALID_MUTATION_TOKEN' });
    expect(f.calls).toHaveLength(0);
  });
  test('unknown finish token remains unverified, never accepted', async () => {
    const f = fenceCtx({ rows: [] });
    await expect(fence.actions.finish.handler.call({ settings: { enabled: true } }, {
      ...f.ctx, params: { principal, app, token: '11111111-1111-4111-8111-111111111111' }
    })).rejects.toMatchObject({ type: 'COLLECTIVE_CONSENT_FENCE_UNVERIFIED' });
  });

  test('disabled configuration cannot write a fence', async () => {
    const f = fenceCtx();
    await expect(fence.actions.begin.handler.call({ settings: { enabled: false } }, f.ctx))
      .rejects.toMatchObject({ type: 'COLLECTIVE_CONSENT_BRIDGE_DISABLED' });
    expect(f.calls).toHaveLength(0);
  });
  test('begin blocks before acknowledging; reads back committed revision', async () => {
    const f = fenceCtx();
    const result = await fence.actions.begin.handler.call({ settings: { enabled: true } }, f.ctx);
    expect(result).toMatchObject({ status: 'blocked', revision: 2 });
    expect(f.calls.map(x => x.name)).toEqual(['triplestore.update', 'triplestore.query']);
    expect(f.calls.every(x => x.params.dataset === 'settings' && x.params.webId === 'system')).toBe(true);
    expect(f.calls[0].params.query).toContain('collectiveConsentStatus "blocked"');
    expect(f.calls[0].params.query).toContain('xsd:integer(?oldRevision) + 1');
  });
  test.each([
    { rows: [] },
    { rows: [{ status: { value: 'active' }, revision: { value: '2' } }] },
    { rows: [{ status: { value: 'blocked' }, revision: { value: '0' } }] },
    { rows: [{ status: { value: 'blocked' }, revision: { value: '2' } },
      { status: { value: 'blocked' }, revision: { value: '3' } }] }
  ])('rejects unverifiable state rather than acknowledging SAI mutation', async fixture => {
    await expect(fence.actions.begin.handler.call({ settings: { enabled: true } }, fenceCtx(fixture).ctx))
      .rejects.toMatchObject({ type: 'COLLECTIVE_CONSENT_FENCE_UNVERIFIED' });
  });
  test.each(['triplestore.update', 'triplestore.query'])('fails closed on %s error', async name => {
    await expect(fence.actions.begin.handler.call({ settings: { enabled: true } },
      fenceCtx({ throwOn: name }).ctx)).rejects.toThrow('storage unavailable');
  });
});

const testBegin = () => ({ token: '11111111-1111-4111-8111-111111111111',
  status: 'blocked', revision: 1 });

describe('SAI authorization and app-registration pre-mutation barriers', () => {
  const original = process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED;
  const previousApps = process.env.PROVIDER_COLLECTIVES_APPROVED_APPS;
  beforeEach(() => {
    process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED = 'true';
    process.env.PROVIDER_COLLECTIVES_APPROVED_APPS = app;
  });
  afterAll(() => {
    if (original === undefined) delete process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED;
    else process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED = original;
    if (previousApps === undefined) delete process.env.PROVIDER_COLLECTIVES_APPROVED_APPS;
    else process.env.PROVIDER_COLLECTIVES_APPROVED_APPS = previousApps;
  });

  test('Group right creation is fenced before LDP write; not personal WebACL', async () => {
    const actions = [];
    const ctx = {
      params: { resource: {
        'interop:grantedBy': principal, 'interop:grantee': app,
        'apods:hasSpecialRights': groupRights
      } },
      async call(name, args) { actions.push({ name, args }); return testBegin(); }
    };
    await authorizations.hooks.before.post(ctx);
    expect(actions).toEqual([{
      name: 'collective-consent-fence.begin', args: { principal, app }
    }]);
    await expect(authorizations.hooks.before.post({
      ...ctx, call: async () => { throw new Error('fence offline'); }
    })).rejects.toThrow('fence offline');
  });

  test('unrelated rights do not trigger Group invalidation', async () => {
    let called = false;
    await authorizations.hooks.before.post({
      params: { resource: { 'apods:hasSpecialRights': ['apods:ReadInbox'] } },
      call: async () => { called = true; }
    });
    expect(called).toBe(false);
  });

  test('delete reads persisted SAI rights, not user-supplied rights', async () => {
    const calls = [];
    await authorizations.hooks.before.delete({
      params: { resourceUri: 'https://provider.example/authorizations/1' },
      async call(name, args) {
        calls.push({ name, args });
        if (name === 'access-authorizations.get') return {
          'interop:grantedBy': principal, 'interop:grantee': app,
          // Native persisted SAI resources expose expanded JSON-LD IRIs.
          'apods:hasSpecialRights': ['http://activitypods.org/ns/core#CreateGroup']
        };
        return testBegin();
      }
    });
    expect(calls.map(c => c.name)).toEqual([
      'access-authorizations.get', 'collective-consent-fence.begin'
    ]);
  });

  test('app removal invalidates prior to deleting its grants and registration', async () => {
    const seen = [];
    await registrations.hooks.before.delete({
      params: { resourceUri: 'https://provider.example/registration/1' },
      async call(name, args) {
        seen.push(name);
        if (name === 'app-registrations.get') return {
          'interop:registeredBy': principal, 'interop:registeredAgent': app
        };
        return testBegin();
      }
    });
    expect(seen).toEqual(['app-registrations.get', 'collective-consent-fence.begin']);
  });

  test('unrelated SAI apps never add Group broker calls or Fuseki mutations', async () => {
    const calls = [];
    const other = 'https://unrelated.example/app';
    const ctx = {
      params: { resource: {
        'interop:registeredBy': principal, 'interop:registeredAgent': other
      } },
      async call(name) {
        calls.push(name);
        return true;
      }
    };
    await registrations.hooks.before.post(ctx);
    await registrations.hooks.after.post(ctx, 'https://provider.example/reg/unrelated');
    expect(calls).toEqual([
      'ldp.remote.store', 'applications.attach', 'agent-registry.add'
    ]);
    const puts = [];
    const putCtx = {
      params: {
        resourceUri: 'https://provider.example/reg/unrelated',
        resource: { 'interop:registeredBy': principal, 'interop:registeredAgent': other }
      },
      async call(name) {
        puts.push(name);
        if (name === 'app-registrations.get') return putCtx.params.resource;
        return true;
      }
    };
    await registrations.hooks.before.put(putCtx);
    await registrations.hooks.after.put(putCtx, true);
    expect(puts).toEqual(['app-registrations.get', 'ldp.remote.store']);
  });

  test('new app registration is fenced before LDP POST and only finished after registry update', async () => {
    const seen = [];
    const ctx = {
      params: { resource: {
        'interop:registeredBy': principal, 'interop:registeredAgent': app
      } },
      async call(name) {
        seen.push(name);
        if (name === 'collective-consent-fence.begin') return testBegin();
        return true;
      }
    };
    await registrations.hooks.before.post(ctx);
    expect(seen).toEqual(['collective-consent-fence.begin']);
    await registrations.hooks.after.post(ctx, 'https://provider.example/registrations/new');
    expect(seen).toEqual([
      'collective-consent-fence.begin',
      'ldp.remote.store',
      'applications.attach',
      'agent-registry.add',
      'collective-consent-fence.finish'
    ]);
  });

  test('registration update finishes only after authoritative identity check and cache update', async () => {
    const seen = [];
    const ctx = {
      params: {
        resourceUri: 'https://provider.example/registrations/1',
        resource: { 'interop:registeredBy': principal, 'interop:registeredAgent': app }
      },
      async call(name) {
        seen.push(name);
        if (name === 'app-registrations.get') return {
          'interop:registeredBy': principal, 'interop:registeredAgent': app
        };
        if (name === 'collective-consent-fence.begin') return testBegin();
        return true;
      }
    };
    await registrations.hooks.before.put(ctx);
    await registrations.hooks.after.put(ctx, {});
    expect(seen).toEqual([
      'app-registrations.get', 'collective-consent-fence.begin',
      'ldp.remote.store', 'collective-consent-fence.finish'
    ]);
  });
  test('registration PUT cannot retarget another application or owner', async () => {
    const calls = [];
    await expect(registrations.hooks.before.put({
      params: {
        resourceUri: 'https://provider.example/registrations/1',
        resource: { 'interop:registeredBy': principal,
          'interop:registeredAgent': 'https://attacker.example/app' }
      },
      async call(name) {
        calls.push(name);
        return { 'interop:registeredBy': principal, 'interop:registeredAgent': app };
      }
    })).rejects.toThrow('SAI_REGISTRATION_IDENTITY_IMMUTABLE');
    expect(calls).toEqual(['app-registrations.get']);
  });
  test('registration cleanup keeps provider blocked until related grants are removed', async () => {
    const seen = [];
    const ctx = {
      params: { resourceUri: 'https://provider.example/registrations/1' },
      async call(name) {
        seen.push(name);
        if (name === 'app-registrations.get') return {
          'interop:registeredBy': principal, 'interop:registeredAgent': app
        };
        if (name === 'collective-consent-fence.begin') return testBegin();
        if (name === 'access-authorizations.getForApp') return [];
        return true;
      }
    };
    await registrations.hooks.before.delete(ctx);
    await registrations.hooks.after.delete(ctx, {
      oldData: { 'interop:registeredBy': principal, 'interop:registeredAgent': app },
      resourceUri: ctx.params.resourceUri
    });
    expect(seen.indexOf('collective-consent-fence.finish')).toBe(seen.length - 1);
    expect(seen).toContain('agent-registry.remove');
  });
  test('mutation cleanup failure leaves fence blocked (no finish callback)', async () => {
    const seen = [];
    const ctx = {
      params: { resourceUri: 'https://provider.example/registrations/1',
        resource: { 'interop:registeredBy': principal, 'interop:registeredAgent': app } },
      async call(name) {
        seen.push(name);
        if (name === 'app-registrations.get') return {
          'interop:registeredBy': principal, 'interop:registeredAgent': app
        };
        if (name === 'collective-consent-fence.begin') return testBegin();
        if (name === 'ldp.remote.store') throw new Error('cache write failed');
        return true;
      }
    };
    await registrations.hooks.before.put(ctx);
    await expect(registrations.hooks.after.put(ctx, {})).rejects.toThrow('cache write failed');
    expect(seen).not.toContain('collective-consent-fence.finish');
  });

  test('app registration update acquires a barrier before writing', async () => {
    const seen = [];
    await registrations.hooks.before.put({
      params: {
        resourceUri: 'https://provider.example/registrations/1',
        resource: { 'interop:registeredBy': principal, 'interop:registeredAgent': app }
      },
      call: async name => {
        seen.push(name);
        if (name === 'app-registrations.get') return {
          'interop:registeredBy': principal, 'interop:registeredAgent': app
        };
        return testBegin();
      }
    });
    expect(seen).toEqual(['app-registrations.get', 'collective-consent-fence.begin']);
  });
});

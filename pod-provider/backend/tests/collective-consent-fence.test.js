'use strict';

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
  test('disabled configuration cannot write a fence', async () => {
    const f = fenceCtx();
    await expect(fence.actions.invalidate.handler.call({ settings: { enabled: false } }, f.ctx))
      .rejects.toMatchObject({ type: 'COLLECTIVE_CONSENT_BRIDGE_DISABLED' });
    expect(f.calls).toHaveLength(0);
  });
  test('invalidates before acknowledging; reads back committed revision', async () => {
    const f = fenceCtx();
    const result = await fence.actions.invalidate.handler.call({ settings: { enabled: true } }, f.ctx);
    expect(result).toEqual({ status: 'blocked', revision: 2 });
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
    await expect(fence.actions.invalidate.handler.call({ settings: { enabled: true } }, fenceCtx(fixture).ctx))
      .rejects.toMatchObject({ type: 'COLLECTIVE_CONSENT_FENCE_UNVERIFIED' });
  });
  test.each(['triplestore.update', 'triplestore.query'])('fails closed on %s error', async name => {
    await expect(fence.actions.invalidate.handler.call({ settings: { enabled: true } },
      fenceCtx({ throwOn: name }).ctx)).rejects.toThrow('storage unavailable');
  });
});

describe('SAI authorization and app-registration pre-mutation barriers', () => {
  const original = process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED;
  beforeEach(() => { process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED = 'true'; });
  afterAll(() => {
    if (original === undefined) delete process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED;
    else process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED = original;
  });

  test('Group right creation is fenced before LDP write; not personal WebACL', async () => {
    const actions = [];
    const ctx = {
      params: { resource: {
        'interop:grantedBy': principal, 'interop:grantee': app,
        'apods:hasSpecialRights': groupRights
      } },
      async call(name, args) { actions.push({ name, args }); return true; }
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
          'apods:hasSpecialRights': groupRights
        };
        return true;
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
        return true;
      }
    });
    expect(seen).toEqual(['app-registrations.get', 'collective-consent-fence.begin']);
  });

  test('app registration update invalidates before updating grant links', async () => {
    const seen = [];
    await registrations.hooks.before.put({
      params: { resource: {
        'interop:registeredBy': principal, 'interop:registeredAgent': app
      } },
      call: async name => { seen.push(name); }
    });
    expect(seen).toEqual(['collective-consent-fence.begin']);
  });
});

'use strict';
const api = require('../services/collective-reservations-api.service');
const membership = require('../services/collective-memberships.service');
const { CONSENT_BRIDGE_RELEASED } = require('../services/utils/collective-release-gate');

const groupId = 'cg_' + 'a'.repeat(32);
const owner = 'https://provider.example/users/alice#me';
const app = 'https://client.example/app';
const issuer = 'https://provider.example';
const secret = 'm'.repeat(48);
const signed = Object.freeze({ iss: issuer, sub: owner, webid: owner, azp: app, aud: app });
function fixture({ claims = signed, enabled = true, membershipApiEnabled = true,
  input = {}, header = 'Bearer signed.solid.token', gateway = {} } = {}) {
  const calls = [];
  const ctx = {
    params: { canonicalGroupId: groupId, limit: 100, ...input },
    meta: {
      webId: app, impersonatedUser: owner, tokenPayload: { ...signed },
      $collectivesAuthHeader: header, ...gateway
    },
    async call(name, params) {
      calls.push({ name, params });
      if (name === 'jwk.verifyToken') return claims;
      if (name === 'collective-memberships.list') {
        membership._test.authenticate({
          enabled: true, secret, approvedApps: [app]
        }, params, 'list');
        return { groupId, members: [], membershipRevision: 2 };
      }
      if (name === 'collective-memberships.change') {
        membership._test.authenticate({
          enabled: true, secret, approvedApps: [app]
        }, params, 'change');
        return { groupId, membershipRevision: 3 };
      }
      throw new Error('unexpected call ' + name);
    }
  };
  const instance = { settings: {
    enabled, membershipApiEnabled, providerOrigin: issuer,
    membershipGrantSecret: secret, allowedOriginsConfig: ''
  } };
  return { calls, ctx, instance,
    list: () => api.actions.listMembers.handler.call(instance, ctx),
    change: () => api.actions.changeMember.handler.call(instance, ctx)
  };
}
describe('G2 provider native membership issuer (release fenced)', () => {
  test('immutable release fuse remains closed', () => {
    expect(CONSENT_BRIDGE_RELEASED).toBe(false);
    expect(api.settings.membershipApiEnabled).toBe(false);
  });
  test('optional routes require separate membership gate', async () => {
    const captured = [];
    await api.started.call({
      settings: { enabled: true, membershipApiEnabled: false,
        providerOrigin: issuer, allowedOriginsConfig: '' },
      broker: { call: async (...args) => captured.push(args) }
    });
    expect(Object.keys(captured[0][1].route.aliases)).not.toContain(
      'POST /:canonicalGroupId/members/change'
    );
    const enabled = [];
    await api.started.call({
      settings: { enabled: true, membershipApiEnabled: true,
        providerOrigin: issuer, allowedOriginsConfig: '' },
      broker: { call: async (...args) => enabled.push(args) }
    });
    expect(enabled[0][1].route.aliases).toMatchObject({
      'GET /:canonicalGroupId/members': 'collective-reservations-api.listMembers',
      'POST /:canonicalGroupId/members/change': 'collective-reservations-api.changeMember'
    });
    expect(enabled[0][1].route.authentication).toBe(true);
    expect(enabled[0][1].route.authorization).toBe(true);
  });
  test('list binds owner and app to verified signed token and keeps grant server-side', async () => {
    const f = fixture();
    expect((await f.list()).membershipRevision).toBe(2);
    expect(f.calls.map(x => x.name)).toEqual([
      'jwk.verifyToken', 'collective-memberships.list'
    ]);
    expect(f.calls[1].params).toMatchObject({
      groupId, owner, app, limit: 100, grant: {
        purpose: 'provider.collective.membership.v1',
        operation: 'list', groupId, owner, app
      }
    });
    expect(f.ctx.meta).not.toHaveProperty('$collectivesAuthHeader');
    expect(f.ctx.meta.$responseHeaders['Cache-Control']).toBe('no-store');
  });
  test('change binds input, revision and exact signed capability', async () => {
    const f = fixture({ input: { member: 'https://remote.example/actor/bob',
      role: 'member', status: 'banned', expectedEpoch: 2 } });
    expect((await f.change()).membershipRevision).toBe(3);
    const params = f.calls[1].params;
    expect(params).toMatchObject({
      owner, app, status: 'banned', expectedEpoch: 2,
      grant: { operation: 'change', owner, app }
    });
    expect(f.ctx.meta.$responseHeaders['Cache-Control']).toBe('no-store');
  });
  test.each([
    ['disabled base', { enabled: false }],
    ['disabled membership', { membershipApiEnabled: false }]
  ])('%s fails before token verification or storage', async (_label, options) => {
    const f = fixture(options);
    await expect(f.list()).rejects.toMatchObject({ type: 'GROUP_MEMBERSHIP_ISSUER_DISABLED' });
    expect(f.calls).toHaveLength(0);
    expect(f.ctx.meta).not.toHaveProperty('$collectivesAuthHeader');
  });
  test.each([
    ['forged gateway owner', { gateway: { impersonatedUser: 'https://evil.example#me' } }],
    ['forged gateway app', { gateway: { webId: 'https://evil.example/app' } }],
    ['wrong issuer', { claims: { ...signed, iss: 'https://evil.example' } }],
    ['wrong subject', { claims: { ...signed, sub: 'https://evil.example#me' } }],
    ['wrong audience', { claims: { ...signed, aud: 'https://evil.example' } }],
    ['missing bearer', { header: null }]
  ])('%s does not issue a capability', async (_label, options) => {
    const f = fixture(options);
    await expect(f.list()).rejects.toMatchObject({ type: 'COLLECTIVE_AUTHENTICATION_REQUIRED' });
    expect(f.calls.some(x => x.name === 'collective-memberships.list')).toBe(false);
  });
  test.each([
    [{ canonicalGroupId: '../escape' }, 'list'],
    [{ limit: 1001 }, 'list'],
    [{ cursor: 'http://not-https.example' }, 'list'],
    [{ member: owner, role: 'superadmin', status: 'active', expectedEpoch: 1 }, 'change'],
    [{ member: 'http://example.test', role: 'member', status: 'active', expectedEpoch: 1 }, 'change'],
    [{ member: 'https://remote.example/b', role: 'member', status: 'banned', expectedEpoch: 0 }, 'change']
  ])('invalid params %j fail before membership broker dispatch', async (input, operation) => {
    const f = fixture({ input });
    await expect(f[operation]()).rejects.toMatchObject({ type: 'GROUP_MEMBERSHIP_INVALID_INPUT' });
    expect(f.calls.some(x => x.name.startsWith('collective-memberships.'))).toBe(false);
  });
});

'use strict';

const crypto = require('node:crypto');
const api = require('../services/collective-reservations-api.service');

const principal = 'https://social.example/users/alice';
const app = 'https://client.example/app';
const issuer = 'https://social.example';
const secret = 'g'.repeat(48);
const fingerprint = (p, a, k, d) => crypto.createHash('sha256')
  .update(JSON.stringify([p, a, k, d])).digest('hex');

function harness({
  enabled = true, header = 'Bearer valid.token.proof',
  key = 'q'.repeat(32), displayName = 'Community Hub',
  verified = { azp: app, webid: principal, aud: app, iss: issuer },
  metadata = {}, failReservation = false
} = {}) {
  const seen = [];
  const ctx = {
    params: { displayName, principal: 'https://evil.example/users/mallory',
      app: 'https://evil.example/fake-app' },
    meta: {
      webId: app, impersonatedUser: principal,
      tokenPayload: { azp: app, webid: principal },
      $collectivesAuthHeader: header,
      $collectivesIdempotencyKey: key,
      ...metadata
    },
    async call(action, params) {
      seen.push({ action, params });
      if (action === 'jwk.verifyToken') return verified;
      if (action === 'collective-reservations.reserve') {
        if (failReservation) throw new Error('authoritative store unavailable');
        return { canonicalGroupId: 'cg_00000000000000000000000000000000', stage: 'reserved' };
      }
      throw new Error('unexpected action ' + action);
    }
  };
  const instance = {
    settings: { enabled, providerOrigin: issuer, grantSecret: secret }
  };
  return { ctx, instance, seen,
    reserve() { return api.actions.reserve.handler.call(instance, ctx); } };
}
async function denied(promise, type) {
  await expect(promise).rejects.toMatchObject({ type });
}

describe('G1 Solid-OIDC authenticated reservation ingress', () => {
  test('default-off endpoint does not register any route', async () => {
    const calls = [];
    await api.started.call({
      settings: { enabled: false },
      broker: { call: async (...args) => calls.push(args) }
    });
    expect(calls).toEqual([]);
    await denied(harness({ enabled: false }).reserve(), 'COLLECTIVE_API_DISABLED');
  });
  test('enabled route requires both gateway authentication and authorization', async () => {
    const calls = [];
    await api.started.call({
      settings: { enabled: true },
      broker: { call: async (...args) => calls.push(args) }
    });
    expect(calls).toHaveLength(1);
    const route = calls[0][1].route;
    expect(route.path).toBe('/api/collectives');
    expect(route.authentication).toBe(true);
    expect(route.authorization).toBe(true);
    expect(route.aliases).toEqual({ 'POST /reserve': 'collective-reservations-api.reserve' });
  });
  test('derives user and app ONLY from verified OIDC claims, never the request body', async () => {
    const h = harness();
    const result = await h.reserve();
    expect(result.stage).toBe('reserved');
    expect(h.ctx.meta.$statusCode).toBe(202);
    expect(h.ctx.meta.$responseHeaders['Cache-Control']).toBe('no-store');
    const actions = h.seen.map(x => x.action);
    expect(actions).toEqual(['jwk.verifyToken', 'collective-reservations.reserve']);
    expect(h.seen[0].params.token).toBe('valid.token.proof');
    const op = h.seen[1].params;
    expect(op.principal).toBe(principal);
    expect(op.app).toBe(app);
    expect(op).not.toHaveProperty('ownerWebId');
    expect(op.grant.operation).toBe('reserve');
    expect(op.grant.principal).toBe(principal);
    expect(op.grant.app).toBe(app);
    const hash = fingerprint(principal, app, 'q'.repeat(32), 'Community Hub');
    expect(op.grant.requestHash).toBe(hash);
    const fields = ['provider.collective.reservation.v1', principal, app, 'reserve',
      hash, op.grant.issuedAt, op.grant.expiresAt];
    const mac = crypto.createHmac('sha256', secret).update(JSON.stringify(fields)).digest('hex');
    expect(op.grant.mac).toBe(mac);
    expect(op.grant.expiresAt - op.grant.issuedAt).toBe(60000);
    expect(result).not.toHaveProperty('grant');
    expect(JSON.stringify(result)).not.toContain(secret);
  });
  test.each([
    ['missing bearer', { header: undefined }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['malformed bearer', { header: 'Basic abcdef' }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['missing idempotency', { key: undefined }, 'COLLECTIVE_INVALID_IDEMPOTENCY'],
    ['short idempotency', { key: '123' }, 'COLLECTIVE_INVALID_IDEMPOTENCY'],
    ['missing token subject', { verified: { azp: app, aud: app, iss: issuer } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['custom JWT no app', { verified: { webid: principal, aud: app, iss: issuer } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['wrong app signed', { verified: { azp: 'https://evil.example/app', webid: principal, aud: 'https://evil.example/app', iss: issuer } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['wrong person signed', { verified: { azp: app, webid: 'https://evil.example/user', aud: app, iss: issuer } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['wrong audience', { verified: { azp: app, webid: principal, aud: 'https://evil.example/app', iss: issuer } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['missing issuer', { verified: { azp: app, webid: principal, aud: app } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['wrong issuer', { verified: { azp: app, webid: principal, aud: app, iss: 'https://evil.example' } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['invalid signature', { verified: null }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['injected gateway app', { metadata: { webId: 'https://evil.example/app' } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['injected gateway user', { metadata: { impersonatedUser: 'https://evil.example/user' } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['injected gateway token claims', { metadata: { tokenPayload: { azp: 'https://evil.example/app', webid: principal } } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED']
  ])('fails closed for %s', async (_case, input, expected) => {
    const h = harness(input);
    await denied(h.reserve(), expected);
    expect(h.seen.some(x => x.action === 'collective-reservations.reserve')).toBe(false);
  });
  test('does not issue a successful HTTP status when authoritative persistence fails', async () => {
    const h = harness({ failReservation: true });
    await expect(h.reserve()).rejects.toThrow('authoritative store unavailable');
    expect(h.ctx.meta.$statusCode).toBeUndefined();
  });
  test('does not silently sign when provider secret is misconfigured', async () => {
    const h = harness();
    h.instance.settings.grantSecret = '';
    await denied(h.reserve(), 'COLLECTIVE_API_DISABLED');
    expect(h.seen).toHaveLength(0);
  });
});

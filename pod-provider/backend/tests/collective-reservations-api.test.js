'use strict';

const crypto = require('node:crypto');
const api = require('../services/collective-reservations-api.service');

const principal = 'https://social.example/users/alice';
const app = 'https://client.example/app';
const issuer = 'https://social.example';
const secret = 'g'.repeat(48);
const JKT = 'd'.repeat(43);
const TOKEN = 'stepup.group.credential';
const DPOP = 'cHJvb2Y.c2lnbmVk.c2lnbmF0dXJl';
const fingerprint = (p, a, k, d) => crypto.createHash('sha256')
  .update(JSON.stringify([p, a, k, d])).digest('hex');

function harness({
  enabled = true, header = 'DPoP ' + TOKEN,
  key = 'q'.repeat(32), displayName = 'Community Hub',
  verified = { principal, app, jkt: JKT },
  metadata = {}, failReservation = false
} = {}) {
  const seen = [];
  const ctx = {
    params: { displayName, principal: 'https://evil.example/users/mallory',
      app: 'https://evil.example/fake-app' },
    meta: {
      $collectivesAuthHeader: header,
      $collectivesIdempotencyKey: key,
      $collectivesDpopProof: DPOP,
      ...metadata
    },
    async call(action, params) {
      seen.push({ action, params });
      if (action === 'collective-stepup-credentials.verify') return verified;
      if (action === 'oauth-dpop-nonce.verifyProof') return { jkt: JKT, jti: 'random' };
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
describe('G1 purpose-bound reservation ingress', () => {
  test('route is disabled by default', async () => {
    const calls = [];
    await api.started.call({
      settings: { enabled: false },
      broker: { call: async (...args) => calls.push(args) }
    });
    expect(calls).toEqual([]);
    await denied(harness({ enabled: false }).reserve(), 'COLLECTIVE_API_DISABLED');
  });

  test('Group-only route is NOT a generic Solid-OIDC login route', async () => {
    const calls = [];
    await api.started.call({
      settings: { enabled: true, providerOrigin: issuer, allowedOriginsConfig: '' },
      broker: { call: async (...args) => calls.push(args) }
    });
    expect(calls).toHaveLength(1);
    const route = calls[0][1].route;
    expect(route.path).toBe('/api/collectives');
    expect(route.authentication).toBe(false);
    expect(route.authorization).toBe(false);
    expect(route.aliases).toEqual({ 'POST /reserve': 'collective-reservations-api.reserve' });
    // Authentication is explicitly enforced by the distinct Group credential
    // verifier, so an ordinary ID token cannot get mistaken for a login.
  });

  test('derives Group principal and app ONLY from signed step-up credential', async () => {
    const h = harness();
    const result = await h.reserve();
    expect(result.stage).toBe('reserved');
    expect(h.ctx.meta.$statusCode).toBe(202);
    expect(h.ctx.meta.$responseHeaders['Cache-Control']).toBe('no-store');
    expect(h.seen.map(x => x.action)).toEqual([
      'collective-stepup-credentials.verify',
      'oauth-dpop-nonce.verifyProof',
      'collective-reservations.reserve'
    ]);
    expect(h.seen[0].params.token).toBe(TOKEN);
    expect(h.seen[1].params).toMatchObject({
      expectedJkt: JKT, htm: 'POST', htu: issuer + '/api/collectives/reserve'
    });
    expect(h.seen[1].params.expectedAth).toBe(
      crypto.createHash('sha256').update(TOKEN).digest('base64url')
    );
    const op = h.seen[2].params;
    expect(op.principal).toBe(principal);
    expect(op.app).toBe(app);
    expect(op).not.toHaveProperty('ownerWebId');
    expect(op.grant.operation).toBe('reserve');
    expect(op.grant.principal).toBe(principal);
    expect(op.grant.app).toBe(app);
    const hash = fingerprint(principal, app, 'q'.repeat(32), 'Community Hub');
    expect(op.grant.requestHash).toBe(hash);
    const fields = ['provider.collective.reservation.v1', principal, app,
      'reserve', hash, op.grant.issuedAt, op.grant.expiresAt];
    expect(op.grant.mac).toBe(
      crypto.createHmac('sha256', secret).update(JSON.stringify(fields)).digest('hex')
    );
    expect(op.grant.expiresAt - op.grant.issuedAt).toBe(60000);
    expect(result).not.toHaveProperty('grant');
  });

  test.each([
    ['ordinary Solid bearer', { header: 'Bearer ' + TOKEN }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['missing DPoP authorization', { header: null }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['malformed authorization', { header: 'Basic abcdef' }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['missing idempotency', { key: null }, 'COLLECTIVE_INVALID_IDEMPOTENCY'],
    ['short idempotency', { key: '123' }, 'COLLECTIVE_INVALID_IDEMPOTENCY'],
    ['missing stepup subject', { verified: { app, jkt: JKT } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['missing stepup app', { verified: { principal, jkt: JKT } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['missing bound key', { verified: { principal, app } }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['missing Group stepup credential', { verified: null }, 'COLLECTIVE_AUTHENTICATION_REQUIRED'],
    ['malformed DPoP', { metadata: { $collectivesDpopProof: 'invalid' } }, 'COLLECTIVE_DPOP_REQUIRED'],
    ['missing DPoP', { metadata: { $collectivesDpopProof: null } }, 'COLLECTIVE_DPOP_REQUIRED']
  ])('fails closed for %s', async (_label, params, type) => {
    const h = harness(params);
    await denied(h.reserve(), type);
    expect(h.seen.some(x => x.action === 'collective-reservations.reserve')).toBe(false);
  });

  test('rejects a cryptographically verified proof from a different sender key', async () => {
    const h = harness({ verified: { principal, app, jkt: 'z'.repeat(43) } });
    await denied(h.reserve(), 'COLLECTIVE_DPOP_REQUIRED');
    expect(h.seen.some(x => x.action === 'collective-reservations.reserve')).toBe(false);
  });

  test('does not report success when authoritative reservation write fails', async () => {
    const h = harness({ failReservation: true });
    await expect(h.reserve()).rejects.toThrow('authoritative store unavailable');
    expect(h.ctx.meta.$statusCode).toBeUndefined();
  });

  test('does not authorize requests with missing grant secret', async () => {
    const h = harness();
    h.instance.settings.grantSecret = '';
    await denied(h.reserve(), 'COLLECTIVE_API_DISABLED');
    expect(h.seen).toHaveLength(0);
  });
});

'use strict';

const crypto = require('node:crypto');
const api = require('../services/collective-reservations-api.service');

const principal = 'https://provider.example/users/alice#me';
const app = 'https://client.example/app';
const issuer = 'https://provider.example';
const secret = 'g'.repeat(48);
const token = 'signed.solid.idtoken';
const idempotencyKey = 'q'.repeat(32);
const signedClaims = Object.freeze({
  iss: issuer, sub: principal, webid: principal, azp: app, aud: app
});

function harness({
  enabled = true, claims = signedClaims, header = 'Bearer ' + token,
  key = idempotencyKey, gateway = {}, name = 'Community Hub', failWrite = false
} = {}) {
  const calls = [];
  const ctx = {
    // Input cannot set the principal or application: the provider owns both.
    params: { displayName: name },
    meta: {
      webId: app, impersonatedUser: principal, tokenPayload: { ...signedClaims },
      $collectivesAuthHeader: header, $collectivesIdempotencyKey: key,
      ...gateway
    },
    async call(action, params) {
      calls.push({ action, params });
      if (action === 'jwk.verifyToken') return claims;
      if (action === 'collective-reservations.get') {
        if (failWrite) throw new Error('Fuseki unavailable');
        return { canonicalGroupId: 'cg_' + 'a'.repeat(32), stage: 'reserved', revision: 1 };
      }
      if (action === 'collective-reservations.reserve') {
        if (failWrite) throw new Error('Fuseki unavailable');
        return { canonicalGroupId: 'cg_' + 'a'.repeat(32), stage: 'reserved' };
      }
      throw Error('unexpected action ' + action);
    }
  };
  const instance = {
    settings: {
      enabled, providerOrigin: issuer, grantSecret: secret, allowedOriginsConfig: ''
    }
  };
  return { calls, ctx, instance,
    run: () => api.actions.reserve.handler.call(instance, ctx),
    read: (groupId = 'cg_' + 'a'.repeat(32)) => {
      ctx.params = { canonicalGroupId: groupId };
      return api.actions.get.handler.call(instance, ctx);
    } };
}

async function denied(run, code) {
  await expect(run()).rejects.toMatchObject({ type: code });
}

describe('Provider-native Solid-OIDC Group reservation', () => {
  test('route stays disabled without deployment feature flag', async () => {
    const calls = [];
    await api.started.call({
      settings: { enabled: false },
      broker: { call: async (...a) => calls.push(a) }
    });
    expect(calls).toEqual([]);
    await denied(harness({ enabled: false }).run, 'COLLECTIVE_API_DISABLED');
  });

  test('reuses existing gateway authentication and authorization', async () => {
    const calls = [];
    await api.started.call({
      settings: { enabled: true, providerOrigin: issuer, allowedOriginsConfig: '' },
      broker: { call: async (...args) => calls.push(args) }
    });
    expect(calls).toHaveLength(1);
    const route = calls[0][1].route;
    expect(route.path).toBe('/api/collectives');
    expect(route.authentication).toBe(true);
    expect(route.authorization).toBe(true);
    expect(route.aliases).toEqual({
      'POST /reserve': 'collective-reservations-api.reserve',
      'GET /:canonicalGroupId': 'collective-reservations-api.get'
    });
    expect(route.cors.credentials).toBe(false);
    expect(route.cors.allowedHeaders).not.toContain('DPoP');
  });

  test('reverifies signed Solid identity and holds internal operation grant server-side', async () => {
    const h = harness();
    expect((await h.run()).stage).toBe('reserved');
    expect(h.calls.map(x => x.action)).toEqual([
      'jwk.verifyToken', 'collective-reservations.reserve'
    ]);
    expect(h.calls[0].params.token).toBe(token);
    const params = h.calls[1].params;
    expect(params.principal).toBe(principal);
    expect(params.app).toBe(app);
    expect(params.idempotencyKey).toBe(idempotencyKey);
    expect(params.grant).toMatchObject({
      principal, app, purpose: 'provider.collective.reservation.v1',
      operation: 'reserve'
    });
    const hash = crypto.createHash('sha256').update(JSON.stringify([
      principal, app, idempotencyKey, 'Community Hub'
    ])).digest('hex');
    expect(params.grant.requestHash).toBe(hash);
    const fields = [params.grant.purpose, principal, app, 'reserve', hash,
      params.grant.issuedAt, params.grant.expiresAt];
    expect(params.grant.mac).toBe(
      crypto.createHmac('sha256', secret).update(JSON.stringify(fields)).digest('hex')
    );
    expect(params.grant.expiresAt - params.grant.issuedAt).toBe(60000);
    expect(h.ctx.meta.$statusCode).toBe(202);
    expect(h.ctx.meta.$responseHeaders['Cache-Control']).toBe('no-store');
    expect(h.ctx.meta).not.toHaveProperty('$collectivesAuthHeader');
  });

  test.each([
    ['missing bearer', { header: null }],
    ['wrong scheme', { header: 'Basic ' + token }],
    ['DPoP credential scheme', { header: 'DPoP ' + token }],
    ['invalid bearer syntax', { header: 'Bearer a b' }],
    ['invalid signature', { claims: null }],
    ['missing app', { claims: { ...signedClaims, azp: undefined } }],
    ['missing person', { claims: { ...signedClaims, webid: undefined } }],
    ['subject substitution', { claims: { ...signedClaims,
      sub: 'https://attacker.example#me' } }],
    ['issuer substitution', { claims: { ...signedClaims, iss: 'https://attacker.example' } }],
    ['audience substitution', { claims: { ...signedClaims, aud: 'https://attacker.example' } }],
    ['gateway-app substitution', { gateway: { webId: 'https://attacker.example' } }],
    ['gateway-user substitution', { gateway: {
      impersonatedUser: 'https://attacker.example#me' } }],
    ['gateway-claims substitution', { gateway: {
      tokenPayload: { ...signedClaims, webid: 'https://attacker.example#me' } } }]
  ])('denies %s without issuing a provider grant', async (_case, options) => {
    const h = harness(options);
    await denied(h.run, 'COLLECTIVE_AUTHENTICATION_REQUIRED');
    expect(h.calls.some(x => x.action === 'collective-reservations.reserve')).toBe(false);
  });

  test.each([
    ['absent', null], ['short', 'x'], ['invalid', '../evil']
  ])('rejects %s idempotency key', async (_case, key) => {
    const h = harness({ key });
    await denied(h.run, 'COLLECTIVE_INVALID_IDEMPOTENCY');
    expect(h.calls.map(x => x.action)).toEqual(['jwk.verifyToken']);
  });

  test('read uses the existing Solid login with a distinct, Group-bound ReadGroups grant', async () => {
    const h = harness();
    const id = 'cg_' + 'a'.repeat(32);
    const result = await h.read(id);
    expect(result).toEqual({ canonicalGroupId: id, stage: 'reserved', revision: 1 });
    expect(h.calls.map(x => x.action)).toEqual([
      'jwk.verifyToken', 'collective-reservations.get'
    ]);
    const params = h.calls[1].params;
    expect(params).toMatchObject({ canonicalGroupId: id, principal, app,
      grant: { purpose: 'provider.collective.reservation.v1', operation: 'read',
        requestHash: id } });
    const fields = [params.grant.purpose, principal, app, 'read', id,
      params.grant.issuedAt, params.grant.expiresAt];
    expect(params.grant.mac).toBe(crypto.createHmac('sha256', secret)
      .update(JSON.stringify(fields)).digest('hex'));
    expect(h.ctx.meta.$responseHeaders['Cache-Control']).toBe('no-store');
    expect(h.ctx.meta).not.toHaveProperty('$collectivesAuthHeader');
  });

  test('read denies forged gateway identity and never invokes the reservation store', async () => {
    const h = harness({ gateway: { impersonatedUser: 'https://attacker.example#me' } });
    await denied(() => h.read(), 'COLLECTIVE_AUTHENTICATION_REQUIRED');
    expect(h.calls.some(x => x.action === 'collective-reservations.get')).toBe(false);
  });

  test('read refuses missing or malformed Group IDs before issuing storage calls', async () => {
    const h = harness();
    for (const id of ['../secret', 'cg_bad', '', 'cg_' + 'x'.repeat(32)]) {
      await expect(h.read(id)).rejects.toBeDefined();
    }
    expect(h.calls.some(x => x.action === 'collective-reservations.get')).toBe(false);
  });

  test('does not report success if provider persistence fails', async () => {
    const h = harness({ failWrite: true });
    await expect(h.run()).rejects.toThrow('Fuseki unavailable');
    expect(h.ctx.meta.$statusCode).toBeUndefined();
  });

  test('disabled or misconfigured signing key fails before verification', async () => {
    const h = harness();
    h.instance.settings.grantSecret = '';
    await denied(h.run, 'COLLECTIVE_API_DISABLED');
    expect(h.calls).toHaveLength(0);
  });
});

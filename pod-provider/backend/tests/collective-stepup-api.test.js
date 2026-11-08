'use strict';

const crypto = require('node:crypto');
const service = require('../services/collective-stepup-api.service');

const origin = 'https://provider.example';
const app = 'https://client.example/app';
const person = origin + '/profile/card#me';
const token = 'ordinary.signed.solidtoken';
const proof = 'encoded.header.signature';
const ticket = 'a'.repeat(80);
const jkt = 'z'.repeat(43);

function harness({
  enabled = true, rights = ['apods:CreateGroup'], registered = true,
  allowlist = [app], assertedWebId = person,
  claims = { webid: person, sub: person, azp: app, aud: app, iss: origin,
    exp: Math.floor(Date.now()/1000) + 3600 },
  failAssertion = false
} = {}) {
  const keys = new Set();
  const rateCounters = new Map();
  const calls = [];
  let currentRights = rights, currentRegistered = registered;
  const instance = {
    settings: { enabled, origin, approvedApps: allowlist,
      ticketPrefix: 'test:ticket', ticketTtlSeconds: 600,
      ratePrefix: 'test:rate', maxAttemptsPerMinute: 8 },
    redis: {
      async eval(lua, numKeys, key, seconds) {
        expect(numKeys).toBe(1);
        expect(seconds).toBe(60);
        const count = (rateCounters.get(key) || 0) + 1;
        rateCounters.set(key, count);
        return count;
      },
      async set(key, val, ex, ttl, nx) {
        expect(ex).toBe('EX'); expect(ttl).toBe(600); expect(nx).toBe('NX');
        if (keys.has(key)) return null;
        keys.add(key); return 'OK';
      }
    }
  };
  const ctx = {
    params: { ticket, response: { id: 'example-passkey-credential' } },
    meta: { $stepupAuthorization: 'Bearer ' + token, $stepupDpop: proof },
    async call(action, params) {
      calls.push({ action, params });
      if (action === 'jwk.verifyToken') return claims;
      if (action === 'auth.account.findByWebId') return { webId: person };
      if (action === 'app-registrations.isRegistered') return currentRegistered;
      if (action === 'access-authorizations.getSpecialRights') return currentRights;
      if (action === 'oauth-dpop-nonce.verifyProof') return { jkt };
      if (action === 'passkeys-api.verifyAssertion') {
        if (failAssertion) throw new Error('WebAuthn challenge invalid');
        return { webId: assertedWebId };
      }
      if (action === 'collective-stepup-credentials.mint') {
        return { token: 'group-only.stepup.credential', tokenType: 'DPoP',
          expiresIn: 300 };
      }
      throw Error('Unexpected service action: ' + action);
    }
  };
  return { ctx, calls, keys, rateCounters, instance,
    setRights(v) { currentRights = v; },
    setRegistered(v) { currentRegistered = v; },
    verify() { return service.actions.verify.handler.call(instance, ctx); } };
}
async function denied(promise, type) {
  await expect(promise).rejects.toMatchObject({ type });
}
describe('existing Solid-OIDC + SAI + passkey Group step-up bridge', () => {
  test('off means no registration and no issued tokens', async () => {
    const calls = [];
    await service.started.call({
      settings: { enabled: false },
      broker: { call: async (...args) => calls.push(args) }
    });
    expect(calls).toHaveLength(0);
    await denied(harness({ enabled: false }).verify(), 'COLLECTIVE_STEPUP_DISABLED');
  });

  test('registered route verifies Solid-OIDC token internally (not via a Group token)', async () => {
    const calls = [];
    await service.started.call({
      settings: { enabled: true, origin, allowedOriginsConfig: '' },
      broker: { call: async (...args) => calls.push(args) }
    });
    expect(calls[0][1].route).toMatchObject({
      path: '/api/collectives/stepup',
      authentication: false,
      authorization: false,
      aliases: { 'POST /verify': 'collective-stepup-api.verify' }
    });
  });

  test('existing OIDC + current SAI + correct WebAuthn assertion issues Group-only token', async () => {
    const h = harness();
    const issued = await h.verify();
    expect(issued).toMatchObject({
      tokenType: 'DPoP', expiresIn: 300
    });
    expect(h.calls.map(x => x.action)).toEqual([
      'jwk.verifyToken',
      'auth.account.findByWebId',
      'app-registrations.isRegistered',
      'access-authorizations.getSpecialRights',
      'oauth-dpop-nonce.verifyProof',
      'passkeys-api.verifyAssertion',
      'auth.account.findByWebId',
      'app-registrations.isRegistered',
      'access-authorizations.getSpecialRights',
      'collective-stepup-credentials.mint'
    ]);
    const dpop = h.calls.find(x => x.action === 'oauth-dpop-nonce.verifyProof').params;
    expect(dpop).toMatchObject({
      htu: origin + '/api/collectives/stepup/verify',
      htm: 'POST', audience: app
    });
    expect(dpop.expectedAth).toBe(crypto.createHash('sha256').update(token).digest('base64url'));
    const grant = h.calls.find(x => x.action === 'collective-stepup-credentials.mint').params;
    expect(grant).toMatchObject({ principal: person, app, jkt });
    expect(h.ctx.meta.$responseHeaders['Cache-Control']).toBe('no-store');
    expect(h.keys.size).toBe(1);
    await denied(h.verify(), 'COLLECTIVE_STEPUP_REPLAY');
  });

  test('revoking consent during WebAuthn verification prevents token mint', async () => {
    const h = harness();
    const original = h.ctx.call;
    h.ctx.call = async (action, params) => {
      if (action === 'passkeys-api.verifyAssertion') {
        h.setRights([]);
        return { webId: person };
      }
      return original.call(h.ctx, action, params);
    };
    await denied(h.verify(), 'COLLECTIVE_APP_CONSENT_MISSING');
    expect(h.calls.some(x => x.action === 'collective-stepup-credentials.mint')).toBe(false);
  });

  test('signed OIDC tokens with an audience array must still include the exact app', async () => {
    const now = Math.floor(Date.now()/1000);
    const valid = { webid: person, sub: person, azp: app,
      aud: [app, 'https://unrelated.example'], iss: origin, exp: now + 3600 };
    expect((await harness({ claims: valid }).verify()).tokenType).toBe('DPoP');
    const bad = harness({ claims: { ...valid, aud: ['https://unrelated.example'] } });
    await denied(bad.verify(), 'COLLECTIVE_OIDC_AUTH_REQUIRED');
    expect(bad.keys.size).toBe(0);
  });

  test('revoked app consent and unregistered app cannot initiate step-up', async () => {
    for (const opts of [
      { rights: [] }, { registered: false }, { allowlist: [] }
    ]) {
      const h = harness(opts);
      await expect(h.verify()).rejects.toMatchObject({ code: 403 });
      expect(h.keys.size).toBe(0);
      expect(h.calls.some(x => x.action === 'passkeys-api.verifyAssertion')).toBe(false);
    }
  });

  test('distributed rate limit fails closed before consuming passkey tickets', async () => {
    const h = harness();
    for (let i = 0; i < 8; i += 1) {
      // DPoP syntax denial occurs after rate counter increments.
      h.ctx.meta.$stepupDpop = 'not-a-jws';
      await denied(h.verify(), 'COLLECTIVE_STEPUP_DPOP_REQUIRED');
    }
    await denied(h.verify(), 'COLLECTIVE_STEPUP_RATE_LIMITED');
    expect(h.keys.size).toBe(0);
    expect([...h.rateCounters.values()]).toEqual([9]);
  });

  test('WebAuthn account mismatch cannot mint credentials even with valid OIDC and DPoP', async () => {
    const h = harness({ assertedWebId: origin + '/users/mallory' });
    await denied(h.verify(), 'COLLECTIVE_STEPUP_USER_MISMATCH');
    expect(h.calls.some(x => x.action === 'collective-stepup-credentials.mint')).toBe(false);
  });

  test('failed WebAuthn cannot mint; ticket remains consumed to prevent replay', async () => {
    const h = harness({ failAssertion: true });
    await expect(h.verify()).rejects.toThrow('WebAuthn challenge invalid');
    expect(h.keys.size).toBe(1);
    await denied(h.verify(), 'COLLECTIVE_STEPUP_REPLAY');
  });

  test.each([
    ['missing bearer', 'Authorization', null],
    ['wrong bearer scheme', 'Authorization', 'DPoP ' + token],
    ['missing proof', 'DPoP', null],
    ['invalid proof syntax', 'DPoP', 'invalid'],
  ])('rejects %s', async (_label, which, value) => {
    const h = harness();
    if (which === 'Authorization') h.ctx.meta.$stepupAuthorization = value;
    else h.ctx.meta.$stepupDpop = value;
    await expect(h.verify()).rejects.toMatchObject({ code: 401 });
    expect(h.calls.some(x => x.action === 'collective-stepup-credentials.mint')).toBe(false);
  });

  test('verifier rejects mismatched signed principal, client, issuer and audience', async () => {
    const valid = harness().ctx;
    const base = { webid: person, sub: person, azp: app, aud: app, iss: origin,
      exp: Math.floor(Date.now()/1000) + 3600 };
    for (const modified of [
      { webid: origin + '/users/mallory' }, { azp: 'https://evil.example/app' },
      { iss: 'https://evil.example' }, { aud: 'https://evil.example/client' },
      { sub: origin + '/users/mallory' }, { exp: 1 }
    ]) {
      const h = harness({ claims: { ...base, ...modified } });
      await denied(h.verify(), 'COLLECTIVE_OIDC_AUTH_REQUIRED');
      expect(h.keys.size).toBe(0);
    }
  });
});

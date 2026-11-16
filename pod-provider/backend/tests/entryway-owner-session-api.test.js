const crypto = require('node:crypto');
const { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, jwtVerify } = require('jose');

const service = require('../services/entryway-owner-session-api.service');

describe('Entryway Solid-OIDC owner-session proof', () => {
  let privateJwk;
  let publicJwk;
  let publicKey;
  let instance;
  const issuer = 'https://pods.example.org';
  const webId = 'https://pods.example.org/alice/profile/card#me';
  const appClientId = 'https://memory.example.org/app';

  beforeAll(async () => {
    const pair = await generateKeyPair('ES256');
    privateJwk = await exportJWK(pair.privateKey);
    privateJwk.alg = 'ES256';
    publicJwk = await exportJWK(pair.publicKey);
    publicKey = await importJWK(publicJwk, 'ES256');
  });

  beforeEach(async () => {
    instance = {
      settings: { enabled: true, issuer, audience: service._test.AUDIENCE, ttlSeconds: 90 },
      signingKey: await importJWK(privateJwk, 'ES256'),
      keyId: await calculateJwkThumbprint(publicJwk),
      publicJwks: { keys: [{ ...publicJwk, alg: 'ES256', use: 'sig' }] }
    };
    process.env.APODS_SOLID_OIDC_DPOP_ENFORCE_ENABLED = 'true';
  });

  afterEach(() => {
    delete process.env.APODS_SOLID_OIDC_DPOP_ENFORCE_ENABLED;
  });

  function context(overrides = {}) {
    const now = Math.floor(Date.now() / 1000);
    return {
      params: {
        accountId: 'acct_11111111-1111-4111-8111-111111111111',
        username: 'alice', webId, appClientId,
        ...overrides.params
      },
      meta: {
        dpopVerified: true,
        tokenPayload: {
          iss: issuer, sub: webId, webid: webId, azp: appClientId,
          aud: [appClientId, 'solid'], iat: now, exp: now + 300,
          cnf: { jkt: crypto.randomBytes(32).toString('base64url') },
          ...overrides.claims
        }
      },
      call: jest.fn(async () => ({ username: 'alice', disabled: false }))
    };
  }

  test('issues a short-lived assertion bound to owner, app and exact account route', async () => {
    const ctx = context();
    const result = await service.actions.issue.handler.call(instance, ctx);
    const verified = await jwtVerify(result.proof, publicKey, {
      issuer, audience: service._test.AUDIENCE, algorithms: ['ES256']
    });
    expect(verified.payload).toMatchObject({
      purpose: service._test.PURPOSE,
      account_id: ctx.params.accountId,
      username: 'alice', webid: webId, app_client_id: appClientId,
      sub: webId
    });
    expect(verified.payload).not.toHaveProperty('idempotency_sha256');
    expect(verified.protectedHeader.kid).toBe(instance.keyId);
    expect(result.expiresIn).toBe(90);
    expect(ctx.call).toHaveBeenCalledWith('auth.account.findByWebId', { webId });
  });

  test('publishes only the public ES256 verification key while enabled', () => {
    const result = service.actions.jwks.handler.call(instance);
    expect(result.keys).toHaveLength(1);
    expect(result.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' });
    expect(result.keys[0]).not.toHaveProperty('d');
    instance.settings.enabled = false;
    expect(() => service.actions.jwks.handler.call(instance))
      .toThrow(expect.objectContaining({ type: 'ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID' }));
  });

  test('starts only with a matching signing pair and registers separate authenticated and public routes', async () => {
    const runtime = {
      settings: { enabled: true, issuer, audience: service._test.AUDIENCE, ttlSeconds: 90 },
      signingKey: null,
      keyId: null,
      publicJwks: null,
      broker: {
        call: jest.fn(async name => name === 'jwk.get' ? { privateJwk, publicJwk } : undefined)
      }
    };
    await service.started.call(runtime);
    const routes = runtime.broker.call.mock.calls
      .filter(([name]) => name === 'api.addRoute')
      .map(([, input]) => input.route);
    expect(routes).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: '/api/entryway-owner-session/jwks', authentication: false }),
      expect.objectContaining({ path: '/api/entryway-owner-session', authentication: true })
    ]));
    expect(runtime.publicJwks.keys[0]).toMatchObject({ kid: runtime.keyId, use: 'sig' });
    expect(runtime.publicJwks.keys[0]).not.toHaveProperty('d');
  });

  test('fails closed before route registration when public and private signing keys differ', async () => {
    const other = await generateKeyPair('ES256');
    const mismatchedPublicJwk = await exportJWK(other.publicKey);
    const runtime = {
      settings: { enabled: true, issuer, audience: service._test.AUDIENCE, ttlSeconds: 90 },
      broker: {
        call: jest.fn(async name => name === 'jwk.get'
          ? { privateJwk, publicJwk: mismatchedPublicJwk }
          : undefined)
      }
    };
    await expect(service.started.call(runtime)).rejects.toMatchObject({
      type: 'ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID', code: 503
    });
    expect(runtime.broker.call).not.toHaveBeenCalledWith('api.addRoute', expect.anything());
  });

  test.each([
    { claims: { webid: 'https://pods.example.org/bob/profile/card#me' } },
    { claims: { azp: 'https://evil.example/app' } },
    { claims: { aud: [appClientId] } },
    { claims: { cnf: undefined } },
    { claims: { iat: Math.floor(Date.now() / 1000) - 301 } },
    { claims: { iss: 'https://evil.example' } }
  ])('rejects stale or incorrectly scoped Solid-OIDC claims %#', async bad => {
    await expect(service.actions.issue.handler.call(instance, context(bad)))
      .rejects.toMatchObject({ type: 'ENTRYWAY_OWNER_SESSION_AUTH_INVALID', code: 401 });
  });

  test('rejects a non-owner', async () => {
    const wrong = context();
    wrong.call.mockResolvedValueOnce({ username: 'bob', disabled: false });
    await expect(service.actions.issue.handler.call(instance, wrong))
      .rejects.toMatchObject({ type: 'ENTRYWAY_OWNER_SESSION_ACCOUNT_INVALID', code: 403 });
  });

  test('cannot mint a proof while DPoP verification or the route gate is disabled', async () => {
    delete process.env.APODS_SOLID_OIDC_DPOP_ENFORCE_ENABLED;
    await expect(service.actions.issue.handler.call(instance, context()))
      .rejects.toMatchObject({ type: 'ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID', code: 503 });
    process.env.APODS_SOLID_OIDC_DPOP_ENFORCE_ENABLED = 'true';
    instance.settings.enabled = false;
    await expect(service.actions.issue.handler.call(instance, context()))
      .rejects.toMatchObject({ type: 'ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID', code: 503 });
    instance.settings.enabled = true;
    const unbound = context();
    unbound.meta.dpopVerified = false;
    await expect(service.actions.issue.handler.call(instance, unbound))
      .rejects.toMatchObject({ type: 'ENTRYWAY_OWNER_SESSION_CONFIGURATION_INVALID', code: 503 });
  });
});

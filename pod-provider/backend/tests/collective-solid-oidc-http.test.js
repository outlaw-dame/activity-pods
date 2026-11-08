'use strict';

/**
 * Running HTTP/Moleculer-Web gateway with the provider's existing Solid-OIDC
 * authenticate/authorize actions, real ES256 signed ID tokens and SAI policy.
 * Account/SAI records and reservation persistence are fixtures; the separate
 * Fuseki workflow verifies actual data transactions and concurrency.
 *
 * No passkeys, fresh-login ceremony, new credential service or DPoP required.
 */
const { ServiceBroker } = require('moleculer');
const Gateway = require('moleculer-web');
const { SignJWT, generateKeyPair, jwtVerify } = require('jose');
const solidOidc = require('../services/solid/solid-oidc');
const groupApi = require('../services/collective-reservations-api.service');
const { assertLiveCollectiveConsent } = require('../services/utils/collective-access-policy');

const ORIGIN = 'https://provider.example';
const APP = 'https://paper.example/app';
const PERSON = ORIGIN + '/profile/card#me';
const GROUP_SECRET = 'trusted-provider-operation-key-'.repeat(3);

describe('native Solid-OIDC → SAI consent → Group reservation over HTTP', () => {
  let broker, port, issuerKey, rights, registered;
  const idempotency = 'z'.repeat(32);

  async function request(token, key = idempotency, extra = {}) {
    const result = await fetch('http://127.0.0.1:' + port + '/api/collectives/reserve', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token,
        'Idempotency-Key': key,
        'Origin': 'https://paper.example',
        ...extra
      },
      body: JSON.stringify({ displayName: 'Community' }),
      signal: AbortSignal.timeout(15000)
    });
    return { response: result, text: await result.text() };
  }
  async function token(overrides = {}, key = issuerKey) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ webid: PERSON, azp: APP, ...overrides })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(ORIGIN).setSubject(PERSON).setAudience(APP)
      .setIssuedAt(now - 60).setExpirationTime(now + 3600)
      .sign(key.privateKey);
  }

  beforeAll(async () => {
    issuerKey = await generateKeyPair('ES256');
    rights = [];
    registered = true;
    broker = new ServiceBroker({ logger: false, transporter: null, requestTimeout: 15000 });
    broker.createService({
      name: 'api', mixins: [Gateway],
      settings: {
        port: 0, routes: [],
        cors: { origin: '*', methods: ['POST', 'OPTIONS'] }
      },
      methods: {
        async authenticate(ctx, route, req, res) {
          return ctx.call('solid-oidc.authenticate', { route, req, res });
        },
        async authorize(ctx, route, req, res) {
          return ctx.call('solid-oidc.authorize', { route, req, res });
        }
      }
    });
    broker.createService({
      name: 'jwk',
      actions: {
        async verifyToken(ctx) {
          try {
            const { payload } = await jwtVerify(ctx.params.token, issuerKey.publicKey, {
              issuer: ORIGIN, algorithms: ['ES256']
            });
            return payload;
          } catch {
            return undefined;
          }
        }
      }
    });
    broker.createService({
      name: 'solid-oidc',
      actions: {
        authenticate: solidOidc.actions.authenticate,
        authorize: solidOidc.actions.authorize
      }
    });
    broker.createService({
      name: 'auth.account',
      actions: { findByWebId: ctx => ctx.params.webId === PERSON ? { webId: PERSON } : null }
    });
    broker.createService({ name: 'app-registrations', actions: { isRegistered: () => registered } });
    broker.createService({
      name: 'access-authorizations',
      actions: { getSpecialRights: () => rights }
    });
    broker.createService({
      name: 'collective-reservations',
      actions: {
        async reserve(ctx) {
          await assertLiveCollectiveConsent(ctx, {
            principal: ctx.params.principal, app: ctx.params.app,
            operation: 'reserve', approvedApps: [APP]
          });
          return {
            canonicalGroupId: 'cg_' + 'c'.repeat(32),
            stage: 'reserved', actorUri: ORIGIN + '/groups/cg_' + 'c'.repeat(32)
          };
        }
      }
    });
    broker.createService(groupApi, {
      settings: {
        enabled: true, providerOrigin: ORIGIN,
        grantSecret: GROUP_SECRET, allowedOriginsConfig: 'https://paper.example'
      }
    });
    await broker.start();
    port = broker.getLocalService('api').server.address().port;
  }, 30000);

  afterAll(async () => {
    if (broker) await broker.stop();
  }, 30000);

  test('rejects a signed-in user until their app has explicitly accepted the Group right', async () => {
    rights = [];
    const denied = await request(await token());
    expect(denied.response.status).toBeGreaterThanOrEqual(400);
    expect(denied.response.status).toBeLessThan(500);
    expect(denied.text).not.toContain('"stage":"reserved"');
  });

  test('after consent, the existing Solid-OIDC ID token can reserve, and revoked consent denies reuse', async () => {
    rights = ['apods:CreateGroup'];
    const solid = await token();
    const granted = await request(solid);
    expect(granted.response.status).toBe(202);
    expect(JSON.parse(granted.text).stage).toBe('reserved');
    expect(granted.response.headers.get('access-control-allow-origin'))
      .toBe('https://paper.example');

    rights = [];
    const revoked = await request(solid, 'y'.repeat(32));
    expect(revoked.response.status).toBeGreaterThanOrEqual(400);
    expect(revoked.response.status).toBeLessThan(500);
    expect(revoked.text).not.toContain('"stage":"reserved"');
  });

  test('unregistering an application denies Group creation even when it retains a valid token', async () => {
    rights = ['apods:CreateGroup'];
    registered = false;
    const denied = await request(await token(), 'x'.repeat(32));
    expect(denied.response.status).toBeGreaterThanOrEqual(400);
    expect(denied.response.status).toBeLessThan(500);
    registered = true;
  });

  test('rejects a user token signed by a different issuer key', async () => {
    rights = ['apods:CreateGroup'];
    const another = await generateKeyPair('ES256');
    const denied = await request(await token({}, another), 't'.repeat(32));
    expect(denied.response.status).toBeGreaterThanOrEqual(400);
    expect(denied.response.status).toBeLessThan(500);
  });

  test('does not allow a different browser origin through CORS', async () => {
    const response = await fetch('http://127.0.0.1:' + port + '/api/collectives/reserve', {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://malicious.example',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'authorization,content-type,idempotency-key'
      },
      signal: AbortSignal.timeout(10000)
    });
    expect(response.headers.get('access-control-allow-origin')).not.toBe('*');
    expect(response.headers.get('access-control-allow-origin')).not.toBe('https://malicious.example');
  });
});

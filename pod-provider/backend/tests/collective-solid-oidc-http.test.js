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
// Supply the instance config normally injected by ActivityPods. The gateway
// and Solid-OIDC authenticate/authorize actions themselves remain real.
jest.mock('../config/config', () => ({
  BASE_URL: 'https://provider.example',
  FRONTEND_URL: 'https://provider.example',
  REDIS_OIDC_PROVIDER_URL: 'redis://127.0.0.1:6379',
  COOKIE_SECRET: 'test-only-solid-cookie-secret',
  SEMAPPS_AVAILABLE_LOCALES: 'en'
}));
const solidOidc = require('../services/solid/solid-oidc');
const groupApi = require('../services/collective-reservations-api.service');
const membershipAuthority = require('../services/collective-memberships.service');
const { assertLiveCollectiveConsent } = require('../services/utils/collective-access-policy');

const ORIGIN = 'https://provider.example';
const APP = 'https://paper.example/app';
const PERSON = ORIGIN + '/profile/card#me';
const GROUP_SECRET = 'trusted-provider-operation-key-'.repeat(3);
const MEMBER_SECRET = 'membership-operation-secret-'.repeat(3);
const GROUP_ID = 'cg_' + 'c'.repeat(32);

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
  async function requestRead(token, id = 'cg_' + 'c'.repeat(32)) {
    const response = await fetch('http://127.0.0.1:' + port + '/api/collectives/' + id, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Origin': 'https://paper.example'
      },
      signal: AbortSignal.timeout(15000)
    });
    return { response, text: await response.text() };
  }
  async function requestMembers(solid, suffix = '', method = 'GET', payload = null) {
    const response = await fetch('http://127.0.0.1:' + port +
      '/api/collectives/' + GROUP_ID + '/members' + suffix, {
      method, headers: {
        'Authorization': 'Bearer ' + solid, 'Content-Type': 'application/json',
        'Origin': 'https://paper.example'
      },
      ...(payload ? { body: JSON.stringify(payload) } : {}),
      signal: AbortSignal.timeout(15000)
    });
    return { response, text: await response.text() };
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
        cors: { origin: '*', methods: ['GET', 'POST', 'OPTIONS'] }
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
        },
        async get(ctx) {
          await assertLiveCollectiveConsent(ctx, {
            principal: ctx.params.principal, app: ctx.params.app,
            operation: 'read', approvedApps: [APP]
          });
          if (ctx.params.principal !== PERSON || ctx.params.canonicalGroupId !== 'cg_' + 'c'.repeat(32)) {
            const { MoleculerError } = require('moleculer').Errors;
            throw new MoleculerError('COLLECTIVE_NOT_FOUND', 404, 'COLLECTIVE_NOT_FOUND');
          }
          return { canonicalGroupId: ctx.params.canonicalGroupId, stage: 'reserved', revision: 1 };
        }
      }
    });
    broker.createService({
      name: 'collective-memberships',
      actions: {
        async list(ctx) {
          membershipAuthority._test.authenticate({
            enabled: true, secret: MEMBER_SECRET, approvedApps: [APP]
          }, ctx.params, 'list');
          await assertLiveCollectiveConsent(ctx, {
            principal: ctx.params.owner, app: ctx.params.app,
            operation: 'members', approvedApps: [APP]
          });
          if (ctx.params.groupId !== GROUP_ID) {
            const { MoleculerError } = require('moleculer').Errors;
            throw new MoleculerError('GROUP_MEMBERSHIP_NOT_FOUND', 404, 'GROUP_MEMBERSHIP_NOT_FOUND');
          }
          return { groupId: GROUP_ID, membershipRevision: 7, members: [] };
        },
        async change(ctx) {
          membershipAuthority._test.authenticate({
            enabled: true, secret: MEMBER_SECRET, approvedApps: [APP]
          }, ctx.params, 'change');
          await assertLiveCollectiveConsent(ctx, {
            principal: ctx.params.owner, app: ctx.params.app,
            operation: 'members', approvedApps: [APP]
          });
          if (ctx.params.groupId !== GROUP_ID) {
            const { MoleculerError } = require('moleculer').Errors;
            throw new MoleculerError('GROUP_MEMBERSHIP_NOT_FOUND', 404, 'GROUP_MEMBERSHIP_NOT_FOUND');
          }
          return { groupId: GROUP_ID, membershipRevision: ctx.params.expectedEpoch + 1 };
        }
      }
    });
    broker.createService(groupApi, {
      settings: {
        enabled: true, providerOrigin: ORIGIN,
        grantSecret: GROUP_SECRET, membershipApiEnabled: true,
        membershipGrantSecret: MEMBER_SECRET,
        allowedOriginsConfig: 'https://paper.example'
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

  test('GET needs ReadGroups separately; revocation and IDOR fail closed', async () => {
    const solid = await token();
    rights = ['apods:CreateGroup'];
    const withoutRead = await requestRead(solid);
    expect(withoutRead.response.status).toBeGreaterThanOrEqual(400);
    expect(withoutRead.response.status).toBeLessThan(500);

    rights = ['apods:ReadGroups'];
    const permitted = await requestRead(solid);
    expect(permitted.response.status).toBe(200);
    expect(JSON.parse(permitted.text)).toMatchObject({
      canonicalGroupId: 'cg_' + 'c'.repeat(32),
      stage: 'reserved', revision: 1
    });
    expect(permitted.response.headers.get('cache-control')).toBe('no-store');

    const wrongId = await requestRead(solid, 'cg_' + 'b'.repeat(32));
    expect(wrongId.response.status).toBe(404);
    const malformed = await requestRead(solid, 'cg_invalid');
    expect(malformed.response.status).toBeGreaterThanOrEqual(400);

    rights = [];
    const revoked = await requestRead(solid);
    expect(revoked.response.status).toBeGreaterThanOrEqual(400);
    expect(revoked.response.status).toBeLessThan(500);
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

  test('membership HTTP access requires distinct live ManageMembers consent', async () => {
    const solid = await token();
    rights = ['apods:CreateGroup', 'apods:ReadGroups'];
    const noRight = await requestMembers(solid, '?limit=2');
    expect(noRight.response.status).toBeGreaterThanOrEqual(400);
    expect(noRight.response.status).toBeLessThan(500);
    rights = ['apods:ManageMembers'];
    const allowed = await requestMembers(solid, '?limit=2');
    expect(allowed.response.status).toBe(200);
    expect(JSON.parse(allowed.text)).toEqual({
      groupId: GROUP_ID, membershipRevision: 7, members: []
    });
    expect(allowed.response.headers.get('cache-control')).toBe('no-store');
    rights = [];
    const revoked = await requestMembers(solid, '?limit=2');
    expect(revoked.response.status).toBeGreaterThanOrEqual(400);
    expect(revoked.response.status).toBeLessThan(500);
  });

  test('membership HTTP change is bound to Solid owner, app, and epoch', async () => {
    rights = ['apods:ManageMembers'];
    const solid = await token();
    const member = 'https://remote.example/actors/bob';
    const payload = { member, role: 'member', status: 'active', expectedEpoch: 7 };
    const accepted = await requestMembers(solid, '/change', 'POST', payload);
    expect(accepted.response.status).toBe(200);
    expect(JSON.parse(accepted.text).membershipRevision).toBe(8);

    registered = false;
    const unregistered = await requestMembers(solid, '/change', 'POST', payload);
    expect(unregistered.response.status).toBeGreaterThanOrEqual(400);
    registered = true;

    const injected = await requestMembers(solid, '/change', 'POST', {
      ...payload, owner: 'https://evil.example#me', app: 'https://evil.example/app'
    });
    // Whether ignored or rejected by the gateway validator, client-supplied
    // owner/app must never replace the signed identity used for authorization.
    expect([200, 400, 422]).toContain(injected.response.status);
    if (injected.response.status === 200) {
      expect(JSON.parse(injected.text).membershipRevision).toBe(8);
    }
  });

  test('membership HTTP denies invalid page, actor and forged-issuer bearer', async () => {
    rights = ['apods:ManageMembers'];
    const solid = await token();
    const unbounded = await requestMembers(solid, '?limit=1001');
    expect(unbounded.response.status).toBeGreaterThanOrEqual(400);
    const badActor = await requestMembers(solid, '/change', 'POST', {
      member: 'http://insecure.example/bob', role: 'member',
      status: 'active', expectedEpoch: 7
    });
    expect(badActor.response.status).toBeGreaterThanOrEqual(400);
    const otherKey = await generateKeyPair('ES256');
    const forged = await requestMembers(await token({}, otherKey), '?limit=2');
    expect(forged.response.status).toBeGreaterThanOrEqual(400);
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

'use strict';

/**
 * HTTP-facing integration with actual Moleculer-Web gateway, actual ES256
 * OIDC/DPoP and isolated HS256 step-up credential; live HTTP middleware.
 * SAI records and Group persistence are test doubles; the virtual WebAuthn
 * authenticator signs real assertions validated by the provider's verifier.
 * Separate CI exercises actual Fuseki persistence.
 */
const crypto = require('node:crypto');
const { ServiceBroker } = require('moleculer');
const Gateway = require('moleculer-web');
const { SignJWT, jwtVerify, generateKeyPair, exportJWK } = require('jose');
const apiStepup = require('../services/collective-stepup-api.service');
const creds = require('../services/collective-stepup-credentials.service');
const apiReserve = require('../services/collective-reservations-api.service');
const { assertLiveCollectiveConsent } = require('../services/utils/collective-access-policy');
const dpopService = require('../services/oauth/oauth-dpop-nonce.service');
// The real provider injects these values from instance configuration.
jest.mock('../config/config', () => ({
  BASE_URL: 'https://provider.example',
  FRONTEND_URL: 'https://provider.example',
  COOKIE_SECRET: 'test-only-provider-passkey-cookie-secret'
}));
const passkeysService = require('../services/passkeys-api.service');

const ORIGIN = 'https://provider.example';
const APP = 'https://client.example/app';
const PERSON = ORIGIN + '/profile/card#me';
const SECRET = 'isolated-purpose-specific-secret-'.repeat(3);
const ISSUER_SECRET = 'separate-verified-passkey-issuer-secret-'.repeat(3);

function mockRedis() {
  const store = new Map();
  return {
    async set(k, v, _ex, _ttl, nx) {
      if (nx === 'NX' && store.has(k)) return null;
      store.set(k, v); return 'OK';
    },
    async eval(_code, _n, key) {
      const count = Number(store.get(key) || 0) + 1;
      store.set(key, String(count)); return count;
    },
    async call(command, key) {
      if (command !== 'GETDEL') throw Error('Unexpected Redis command');
      const value = store.get(key) || null;
      store.delete(key);
      return value;
    },
    async quit() {}, disconnect() {}
  };
}

describe('running Moleculer-Web G1 sign-in, consent, reserve and revocation', () => {
  let broker, identityKey, deviceKey, deviceJwk, personRights;
  let passkeyKey, passkeyRecord;
  let port, nonceCounter = 0;
  const groupKey = 'r'.repeat(32);

  function passkeyCose(publicJwk) {
    return Buffer.concat([
      Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
      Buffer.from(publicJwk.x, 'base64url'),
      Buffer.from([0x22, 0x58, 0x20]),
      Buffer.from(publicJwk.y, 'base64url')
    ]);
  }
  async function webauthnAssertion() {
    const { options, ticket } = await broker.call('passkeys-api.authenticationOptions');
    const challenge = options.challenge;
    const clientData = Buffer.from(JSON.stringify({
      type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false
    }));
    const authData = Buffer.alloc(37);
    crypto.createHash('sha256').update('provider.example').digest().copy(authData, 0);
    authData[32] = 0x05; // user present and verified
    authData.writeUInt32BE(passkeyRecord.counter + 1, 33);
    const signable = Buffer.concat([
      authData, crypto.createHash('sha256').update(clientData).digest()
    ]);
    const signature = crypto.sign('sha256', signable, passkeyKey.privateKey);
    return {
      ticket,
      response: {
        id: passkeyRecord.credentialId,
        rawId: passkeyRecord.credentialId, type: 'public-key',
        response: {
          clientDataJSON: clientData.toString('base64url'),
          authenticatorData: authData.toString('base64url'),
          signature: signature.toString('base64url')
        },
        clientExtensionResults: {}
      }
    };
  }

  async function proof(token, htu) {
    nonceCounter += 1;
    return new SignJWT({
      htm: 'POST', htu, iat: Math.floor(Date.now()/1000),
      ath: crypto.createHash('sha256').update(token).digest('base64url'),
      jti: 'test-' + nonceCounter + '-' + crypto.randomUUID()
    }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: deviceJwk })
      .sign(deviceKey.privateKey);
  }
  async function request(path, token, bearerType, dpop, body, extras = {}) {
    const response = await fetch('http://127.0.0.1:' + port + path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: bearerType + ' ' + token,
        DPoP: dpop,
        ...extras
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000)
    });
    return { response, body: await response.json() };
  }

  beforeAll(async () => {
    identityKey = await generateKeyPair('ES256');
    deviceKey = await generateKeyPair('ES256');
    deviceJwk = await exportJWK(deviceKey.publicKey);
    passkeyKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    passkeyRecord = {
      credentialId: crypto.randomBytes(20).toString('base64url'),
      webId: PERSON,
      publicKey: passkeyCose(passkeyKey.publicKey.export({ format: 'jwk' })).toString('base64url'),
      counter: 0, transports: [], userHandle: 'dGVzdC11c2Vy'
    };
    personRights = new Set(['apods:CreateGroup']);
    const redis = mockRedis();

    broker = new ServiceBroker({
      logger: false, transporter: null, requestTimeout: 15000
    });
    broker.createService({
      name: 'api',
      mixins: [Gateway],
      settings: {
        port: 0,
        routes: [],
        cors: { origin: '*', methods: ['POST', 'OPTIONS'] }
      }
    });
    broker.createService({
      name: 'jwk',
      actions: {
        async verifyToken(ctx) {
          try {
            const { payload } = await jwtVerify(ctx.params.token, identityKey.publicKey, {
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
      ...passkeysService,
      // auth.jwt is not involved in the Group-only assertion verification;
      // do not introduce the unrelated account-login dependency in this proof.
      dependencies: [],
      // Keep the independent passkey HTTP routes out of this focused test.
      started() {},
      methods: {
        ...passkeysService.methods,
        getExpectedOrigin: () => ORIGIN,
        getRpId: () => 'provider.example',
        ticketSecret: () => 'test-passkey-ticket-signing-secret-'.repeat(3),
        async getCredentialByCredentialId(_ctx, id) {
          return id === passkeyRecord.credentialId ? passkeyRecord : null;
        },
        async touchCredential(_ctx, id, updates) {
          if (id !== passkeyRecord.credentialId) throw new Error('Incorrect passkey');
          passkeyRecord.counter = updates.counter;
          return passkeyRecord;
        }
      }
    }, { settings: { ticketTtlSec: 300, challengeTimeoutMs: 60000 } });
    broker.createService({
      name: 'auth.account',
      actions: { findByWebId: ctx => ctx.params.webId === PERSON ?
        { webId: PERSON } : null }
    });
    broker.createService({
      name: 'app-registrations',
      actions: { isRegistered: () => true }
    });
    broker.createService({
      name: 'access-authorizations',
      actions: { getSpecialRights: () => [...personRights] }
    });
    broker.createService({
      ...dpopService,
      created() { this.redis = redis; },
      stopped() {}
    });
    broker.createService(creds, { settings: {
      enabled: true, secret: SECRET, issuer: ORIGIN,
      issuerSecret: ISSUER_SECRET, approvedApps: [APP]
    } });
    broker.createService({
      name: 'collective-reservations',
      actions: {
        async reserve(ctx) {
          // Exercise the actual, production consent enforcement function
          // inside the running HTTP path—not a generic mocked server error.
          await assertLiveCollectiveConsent(ctx, {
            principal: ctx.params.principal, app: ctx.params.app,
            operation: 'reserve', approvedApps: [APP]
          });
          return { canonicalGroupId: 'cg_' + groupKey, stage: 'reserved',
            actorUri: ORIGIN + '/groups/cg_' + groupKey };
        }
      }
    });
    broker.createService({
      ...apiStepup,
      created() { this.redis = redis; },
      stopped() {}
    }, {
      settings: {
        enabled: true, origin: ORIGIN, approvedApps: [APP],
        issuerSecret: ISSUER_SECRET,
        allowedOriginsConfig: 'https://paper.example',
        ticketPrefix: 'test:stepup:ticket', ticketTtlSeconds: 600,
        ratePrefix: 'test:stepup:rate', maxAttemptsPerMinute: 8
      }
    });
    broker.createService(apiReserve, { settings: {
      enabled: true, providerOrigin: ORIGIN,
      grantSecret: 'trusted-operation-secret-'.repeat(3),
      allowedOriginsConfig: 'https://paper.example'
    } });
    await broker.start();
    port = broker.getLocalService('api').server.address().port;
  }, 30000);

  afterAll(async () => {
    if (broker) await broker.stop();
  }, 30000);

  test('browser preflight does not allow an unapproved origin or wildcard', async () => {
    const headers = {
      Origin: 'https://malicious.example',
      'Access-Control-Request-Method': 'POST',
      'Access-Control-Request-Headers': 'authorization,dpop,content-type'
    };
    for (const path of ['/api/collectives/stepup/verify', '/api/collectives/reserve']) {
      const response = await fetch('http://127.0.0.1:' + port + path, {
        method: 'OPTIONS', headers, signal: AbortSignal.timeout(10000)
      });
      expect(response.headers.get('access-control-allow-origin')).not.toBe('*');
      expect(response.headers.get('access-control-allow-origin')).not.toBe('https://malicious.example');
    }
  });

  test('running provider rejects invalid virtual WebAuthn signatures before issuance', async () => {
    const now = Math.floor(Date.now()/1000);
    const solid = await new SignJWT({ webid: PERSON, azp: APP })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(ORIGIN).setAudience(APP).setSubject(PERSON)
      .setIssuedAt(now - 60).setExpirationTime(now + 3600)
      .sign(identityKey.privateKey);
    const assertion = await webauthnAssertion();
    assertion.response.response.signature = crypto.randomBytes(70).toString('base64url');
    const rejected = await request('/api/collectives/stepup/verify', solid, 'Bearer',
      await proof(solid, ORIGIN + '/api/collectives/stepup/verify'),
      assertion, { Origin: 'https://paper.example' });
    expect(rejected.response.status).toBeGreaterThanOrEqual(400);
    expect(rejected.response.status).toBeLessThan(500);
    expect(rejected.body.token).toBeUndefined();
    expect(passkeyRecord.counter).toBe(0);
  });

  test('real HTTP flow: signed Solid token + consent + passkey proof → scoped credential → reservation', async () => {
    const now = Math.floor(Date.now()/1000);
    const solid = await new SignJWT({ webid: PERSON, azp: APP })
      .setProtectedHeader({ alg: 'ES256' })
      .setIssuer(ORIGIN).setAudience(APP).setSubject(PERSON)
      .setIssuedAt(now - 600).setExpirationTime(now + 3600)
      .sign(identityKey.privateKey);

    const stepup = await request('/api/collectives/stepup/verify', solid, 'Bearer',
      await proof(solid, ORIGIN + '/api/collectives/stepup/verify'),
      await webauthnAssertion(),
      { Origin: 'https://paper.example' });
    expect(stepup.response.status).toBe(200);
    expect(stepup.body.tokenType).toBe('DPoP');
    expect(stepup.response.headers.get('access-control-allow-origin')).toBe('https://paper.example');
    expect(stepup.response.headers.get('cache-control')).toBe('no-store');
    const token = stepup.body.token;

    const created = await request('/api/collectives/reserve', token, 'DPoP',
      await proof(token, ORIGIN + '/api/collectives/reserve'),
      { displayName: 'Community' }, { 'Idempotency-Key': 'i'.repeat(32) });
    expect(created.response.status).toBe(202);
    expect(created.body.stage).toBe('reserved');

    // A token signed by the Group-only secret is never a Solid-OIDC token.
    await expect(jwtVerify(token, identityKey.publicKey,
      { algorithms: ['ES256'] })).rejects.toThrow();

    // Withdraw SAI permission while the short-lived Group credential remains
    // cryptographically valid. The provider must still reject reservation.
    personRights.clear();
    const blocked = await request('/api/collectives/reserve', token, 'DPoP',
      await proof(token, ORIGIN + '/api/collectives/reserve'),
      { displayName: 'Should not exist' }, { 'Idempotency-Key': 'j'.repeat(32) });
    expect(blocked.response.status).toBeGreaterThanOrEqual(400);
    expect(blocked.response.status).toBeLessThan(500);
    expect(blocked.body.stage).not.toBe('reserved');
  }, 30000);
});

'use strict';

/**
 * End-to-end service-chain test with ACTUAL ES256 Solid JWT, actual DPoP JWS
 * verification and ACTUAL HS256 Group-only credential signing/verification.
 * Mocked: HTTP router, WebAuthn hardware authenticator, SAI persistence and
 * database mutations. It is not a running-provider/browser E2E claim.
 */
const crypto = require('node:crypto');
const { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } = require('jose');
const jwkService = require('../services/core/jwk');
const dpopService = require('../services/oauth/oauth-dpop-nonce.service');
const stepupApi = require('../services/collective-stepup-api.service');
const stepupCredentials = require('../services/collective-stepup-credentials.service');
const reservationApi = require('../services/collective-reservations-api.service');

const ISSUER = 'https://provider.example';
const APP = 'https://reader.example/client';
const PERSON = ISSUER + '/users/alice#me';
const GRANT_SECRET = 'g'.repeat(48);
const STEPUP_SECRET = 'isolation-secret-'.repeat(4);
const ISSUER_SECRET = 'distinct-passkey-issuer-attestation-key-'.repeat(3);
const REQUEST_KEY = 'a'.repeat(32);

function dpopHash(token) {
  return crypto.createHash('sha256').update(token).digest('base64url');
}

async function makeClient() {
  const providerKeys = await generateKeyPair('ES256');
  const deviceKeys = await generateKeyPair('ES256');
  const providerJwk = await exportJWK(providerKeys.publicKey);
  const deviceJwk = await exportJWK(deviceKeys.publicKey);
  const jkt = await calculateJwkThumbprint(deviceJwk, 'sha256');
  const now = Math.floor(Date.now()/1000);
  const solidToken = await new SignJWT({ webid: PERSON, azp: APP })
    .setProtectedHeader({ alg: 'ES256' })
    .setSubject(PERSON).setIssuer(ISSUER).setAudience(APP)
    .setIssuedAt(now - 200).setExpirationTime(now + 3600)
    .sign(providerKeys.privateKey);
  async function proof(token, url) {
    return new SignJWT({
      htm: 'POST', htu: url, jti: crypto.randomUUID(),
      ath: dpopHash(token), iat: Math.floor(Date.now()/1000)
    }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: deviceJwk })
      .sign(deviceKeys.privateKey);
  }
  return { providerJwk, solidToken, jkt, proof };
}

function testBroker(client, { rights = ['apods:CreateGroup'] } = {}) {
  const keys = new Map(), calls = [], issuedTokens = [];
  let currentRights = rights;
  const jwtInst = { publicJwk: client.providerJwk, settings: { alg: 'ES256' } };
  const groupCredentials = {
    settings: { enabled: true, secret: STEPUP_SECRET, issuer: ISSUER,
      issuerSecret: ISSUER_SECRET, approvedApps: [APP] }
  };
  const dpopInst = {
    settings: { replayPrefix: 'test:dpop', replayTtlSec: 300 },
    redis: {
      async set(key, value, ex, ttl, nx) {
        if (nx !== 'NX') throw new Error('Expected atomic NX');
        if (keys.has(key)) return null;
        keys.set(key, value);
        return 'OK';
      }
    }
  };
  const stepupInst = {
    settings: { enabled: true, origin: ISSUER, approvedApps: [APP],
      issuerSecret: ISSUER_SECRET,
      ticketPrefix: 'test:stepup', ticketTtlSeconds: 600,
      ratePrefix: 'test:stepup:rate', maxAttemptsPerMinute: 8 },
    redis: {
      ...dpopInst.redis,
      async eval(lua, numKeys, key, seconds) {
        expect(numKeys).toBe(1);
        expect(seconds).toBe(60);
        return 1;
      }
    }
  };
  const reserveInst = {
    settings: { enabled: true, providerOrigin: ISSUER, grantSecret: GRANT_SECRET }
  };

  async function call(action, params) {
    calls.push({ action, params });
    if (action === 'jwk.verifyToken') {
      return jwkService.actions.verifyToken.call(jwtInst, { params });
    }
    if (action === 'oauth-dpop-nonce.verifyProof') {
      return dpopService.actions.verifyProof.handler.call(dpopInst, { params });
    }
    if (action === 'auth.account.findByWebId') return { webId: PERSON };
    if (action === 'app-registrations.isRegistered') return true;
    if (action === 'access-authorizations.getSpecialRights') return currentRights;
    if (action === 'passkeys-api.verifyAssertion') return { webId: PERSON };
    if (action === 'collective-stepup-credentials.mint') {
      const credential = await stepupCredentials.actions.mint.handler.call(groupCredentials, { params, call });
      issuedTokens.push(credential.token);
      return credential;
    }
    if (action === 'collective-stepup-credentials.verify') {
      return stepupCredentials.actions.verify.handler.call(groupCredentials, { params });
    }
    if (action === 'collective-reservations.reserve') {
      if (!currentRights.includes('apods:CreateGroup')) {
        throw new Error('SAI revoked before authoritative commit');
      }
      return { canonicalGroupId: 'cg_' + 'c'.repeat(32), stage: 'reserved',
        actorUri: ISSUER + '/groups/cg_' + 'c'.repeat(32) };
    }
    throw new Error('Unexpected action: ' + action);
  }
  async function performStepup() {
    const proof = await client.proof(client.solidToken,
      ISSUER + '/api/collectives/stepup/verify');
    const ctx = {
      params: { ticket: 'signed-web-authn-ticket-'.repeat(4),
        response: { id: 'example-passkey' } },
      meta: { $stepupAuthorization: 'Bearer ' + client.solidToken,
        $stepupDpop: proof },
      call
    };
    return stepupApi.actions.verify.handler.call(stepupInst, ctx);
  }
  async function performReservation(credential, { proof = null } = {}) {
    const dpop = proof || await client.proof(credential.token,
      ISSUER + '/api/collectives/reserve');
    const ctx = {
      params: { displayName: 'Cryptographic Integration Group' },
      meta: { $collectivesAuthHeader: 'DPoP ' + credential.token,
        $collectivesDpopProof: dpop, $collectivesIdempotencyKey: REQUEST_KEY },
      call
    };
    return reservationApi.actions.reserve.handler.call(reserveInst, ctx);
  }
  return { calls, keys, issuedTokens, performStepup, performReservation,
    revoke() { currentRights = []; },
    jwtVerify(token) { return jwkService.actions.verifyToken.call(jwtInst, {
      params: { token }
    }); }
  };
}

describe('G1 Solid login → SAI → WebAuthn → Group-only DPoP authorization chain', () => {
  test('signed Solid ID + SAI + WebAuthn → isolated Group token → reserved identity', async () => {
    const client = await makeClient();
    const h = testBroker(client);
    const credential = await h.performStepup();
    expect(credential).toMatchObject({ tokenType: 'DPoP', expiresIn: 300 });
    const reservation = await h.performReservation(credential);
    expect(reservation.stage).toBe('reserved');
    expect(h.calls.some(x => x.action === 'collective-stepup-credentials.mint')).toBe(true);
    expect(h.calls.some(x => x.action === 'collective-reservations.reserve')).toBe(true);
    // Group-only HS256 JWT is cryptographically invalid for the ordinary
    // Solid-OIDC ES256 verifier, preventing access-token confusion.
    expect(await h.jwtVerify(credential.token)).toBeUndefined();
  });

  test('a single WebAuthn ticket cannot mint two credentials', async () => {
    const h = testBroker(await makeClient());
    await h.performStepup();
    await expect(h.performStepup()).rejects.toMatchObject({
      type: 'COLLECTIVE_STEPUP_REPLAY'
    });
    expect(h.issuedTokens).toHaveLength(1);
  });

  test('revoking SAI consent before step-up denies issuing any Group token', async () => {
    const h = testBroker(await makeClient());
    h.revoke();
    await expect(h.performStepup()).rejects.toMatchObject({
      type: 'COLLECTIVE_APP_CONSENT_MISSING'
    });
    expect(h.issuedTokens).toHaveLength(0);
  });

  test('revoking SAI after step-up prevents reservation despite valid signed token', async () => {
    const client = await makeClient();
    const h = testBroker(client);
    const credential = await h.performStepup();
    h.revoke();
    await expect(h.performReservation(credential)).rejects.toThrow(
      'SAI revoked before authoritative commit'
    );
  });

  test('a DPoP proof for an unrelated bearer cannot reserve a Group', async () => {
    const client = await makeClient();
    const h = testBroker(client);
    const credential = await h.performStepup();
    const wrong = await client.proof('some-other-bearer',
      ISSUER + '/api/collectives/reserve');
    await expect(h.performReservation(credential, { proof: wrong }))
      .rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
  });
});

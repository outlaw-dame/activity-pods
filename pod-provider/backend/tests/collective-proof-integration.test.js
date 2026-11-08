'use strict';

/**
 * Cryptographic integration through actual provider JWT verification, actual
 * DPoP JWK signature/thumbprint/ath/replay verification and the G1 ingress
 * handler. No browser, running OIDC issuer, SAI registry or public mutation.
 */
const crypto = require('node:crypto');
const { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } = require('jose');
const jwkService = require('../services/core/jwk');
const dpopService = require('../services/oauth/oauth-dpop-nonce.service');
const apiService = require('../services/collective-reservations-api.service');

const ISSUER = 'https://provider.example';
const APP = 'https://reader.example/client';
const PERSON = ISSUER + '/users/alice#me';
const SIGNER_SECRET = 'g'.repeat(48);
const REQUEST_KEY = 'a'.repeat(32);

async function realIdentityProof() {
  const issuerKeys = await generateKeyPair('ES256');
  const deviceKeys = await generateKeyPair('ES256');
  const issuerPublic = await exportJWK(issuerKeys.publicKey);
  const devicePublic = await exportJWK(deviceKeys.publicKey);
  const jkt = await calculateJwkThumbprint(devicePublic, 'sha256');
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({
    webid: PERSON, azp: APP,
    cnf: { jkt }, auth_time: now - 20, amr: ['pwd']
  })
    .setProtectedHeader({ alg: 'ES256' })
    .setSubject(PERSON)
    .setAudience(APP)
    .setIssuer(ISSUER)
    .setIssuedAt(now - 20)
    .setExpirationTime(now + 600)
    .sign(issuerKeys.privateKey);
  const jti = crypto.randomUUID();
  const proof = await new SignJWT({
    htm: 'POST', htu: ISSUER + '/api/collectives/reserve',
    ath: crypto.createHash('sha256').update(token).digest('base64url'),
    jti, iat: now
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk: devicePublic })
    .sign(deviceKeys.privateKey);
  return { issuerPublic, token, proof, jkt, jti };
}

function harness(fixture, { dpop = fixture.proof, token = fixture.token } = {}) {
  const replay = new Map(), called = [];
  const jwtInstance = { publicJwk: fixture.issuerPublic, settings: { alg: 'ES256' } };
  const proofInstance = {
    settings: { replayPrefix: 'ci:bound-proof', replayTtlSec: 300 },
    redis: {
      async set(key, val, _ex, _ttl, nx) {
        if (nx !== 'NX') throw new Error('Expected atomic replay NX');
        if (replay.has(key)) return null;
        replay.set(key, val); return 'OK';
      }
    }
  };
  const ctx = {
    params: { displayName: 'Cryptographic Integration Group' },
    meta: {
      webId: APP, impersonatedUser: PERSON,
      tokenPayload: { azp: APP, webid: PERSON },
      $collectivesAuthHeader: 'Bearer ' + token,
      $collectivesDpopProof: dpop,
      $collectivesIdempotencyKey: REQUEST_KEY
    },
    async call(action, params) {
      called.push(action);
      if (action === 'jwk.verifyToken') {
        return jwkService.actions.verifyToken.call(jwtInstance, { params });
      }
      if (action === 'oauth-dpop-nonce.verifyProof') {
        return dpopService.actions.verifyProof.handler.call(proofInstance, { params });
      }
      if (action === 'collective-reservations.reserve') {
        return { canonicalGroupId: 'cg_' + 'c'.repeat(32), stage: 'reserved',
          actorUri: ISSUER + '/groups/cg_' + 'c'.repeat(32) };
      }
      throw new Error('Unexpected action: ' + action);
    }
  };
  return { called, ctx, replay,
    reserve: () => apiService.actions.reserve.handler.call({
      settings: { enabled: true, providerOrigin: ISSUER, grantSecret: SIGNER_SECRET }
    }, ctx) };
}

describe('G1 real JWT + DPoP chain (without browser or live SAI)', () => {
  test('accepts only a correctly signed matching token and DPoP key, atomically replay-fenced', async () => {
    const fixture = await realIdentityProof();
    const h = harness(fixture);
    const result = await h.reserve();
    expect(result.stage).toBe('reserved');
    expect(h.called).toEqual([
      'jwk.verifyToken',
      'oauth-dpop-nonce.verifyProof',
      'collective-reservations.reserve'
    ]);
    expect(h.replay.size).toBe(1);
    await expect(h.reserve()).rejects.toMatchObject({ type: 'DPOP_REPLAY_DETECTED' });
    expect(h.called.filter(x => x === 'collective-reservations.reserve')).toHaveLength(1);
  });

  test('rejects a valid sender proof presented with a different bearer token', async () => {
    const fixture = await realIdentityProof();
    const otherToken = await realIdentityProof();
    const h = harness(fixture, { token: otherToken.token });
    await expect(h.reserve()).rejects.toMatchObject({ type: 'COLLECTIVE_AUTHENTICATION_REQUIRED' });
    expect(h.called).not.toContain('collective-reservations.reserve');
  });

  test('rejects a valid OIDC token with a DPoP proof from a different signing key', async () => {
    const fixture = await realIdentityProof();
    const other = await realIdentityProof();
    const h = harness(fixture, { dpop: other.proof });
    await expect(h.reserve()).rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
    expect(h.called).not.toContain('collective-reservations.reserve');
  });
});

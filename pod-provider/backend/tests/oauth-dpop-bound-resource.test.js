'use strict';

const crypto = require('node:crypto');
const { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } = require('jose');
const service = require('../services/oauth/oauth-dpop-nonce.service');

const ORIGIN = 'https://social.example';
const URL = ORIGIN + '/api/collectives/reserve';
const TOKEN = 'client.bound.access.token';
const tokenHash = token => crypto.createHash('sha256').update(token).digest('base64url');

function fixture() {
  const keys = new Map();
  const instance = {
    settings: { replayPrefix: 'test:replay', replayTtlSec: 300 },
    redis: {
      async set(key, value, _ex, _ttl, nx) {
        if (nx !== 'NX') throw Error('expected atomic replay NX');
        if (keys.has(key)) return null;
        keys.set(key, value);
        return 'OK';
      }
    }
  };
  return { instance, keys };
}

async function signedProof(overrides = {}) {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk, 'sha256');
  const iat = Math.floor(Date.now() / 1000);
  const jwt = await new SignJWT({
    htm: 'POST', htu: URL, iat, jti: crypto.randomUUID(),
    ath: tokenHash(TOKEN),
    ...overrides
  }).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk }).sign(privateKey);
  return { jwt, jkt };
}
function params(proof) {
  return {
    proofJwt: proof.jwt,
    htm: 'POST',
    htu: URL,
    audience: 'https://client.example/app',
    expectedJkt: proof.jkt,
    expectedAth: tokenHash(TOKEN)
  };
}

describe('DPoP access-token hash verification', () => {
  test('valid proof checks exact bearer bytes and consumes atomic jti once', async () => {
    const store = fixture();
    const proof = await signedProof();
    const result = await service.actions.verifyProof.handler.call(store.instance, { params: params(proof) });
    expect(result.jkt).toBe(proof.jkt);
    expect(store.keys.size).toBe(1);
    await expect(service.actions.verifyProof.handler.call(store.instance, { params: params(proof) }))
      .rejects.toMatchObject({ type: 'DPOP_REPLAY_DETECTED' });
  });

  test('same signed proof cannot be replayed with a different access token', async () => {
    const store = fixture();
    const proof = await signedProof();
    await expect(service.actions.verifyProof.handler.call(store.instance, {
      params: { ...params(proof), expectedAth: tokenHash('another token') }
    })).rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
    expect(store.keys.size).toBe(0);
    expect((await service.actions.verifyProof.handler.call(store.instance, { params: params(proof) })).jkt)
      .toBe(proof.jkt);
  });

  test('a valid proof signed without an ath cannot authorize a bound resource', async () => {
    const store = fixture();
    const proof = await signedProof({ ath: undefined });
    await expect(service.actions.verifyProof.handler.call(store.instance, { params: params(proof) }))
      .rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
    expect(store.keys.size).toBe(0);
  });

  test('proof signed by a different key cannot satisfy expected JWK thumbprint', async () => {
    const store = fixture();
    const proof = await signedProof();
    await expect(service.actions.verifyProof.handler.call(store.instance, {
      params: { ...params(proof), expectedJkt: 'a'.repeat(43) }
    })).rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
    expect(store.keys.size).toBe(0);
  });

  test('rejects proof bound to a different URL or HTTP operation', async () => {
    const store = fixture();
    const proof = await signedProof({ htu: ORIGIN + '/api/other', htm: 'GET' });
    await expect(service.actions.verifyProof.handler.call(store.instance, { params: params(proof) }))
      .rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
    expect(store.keys.size).toBe(0);
  });
});

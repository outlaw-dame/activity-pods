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
  const replayTtls = [];
  const instance = {
    settings: { replayPrefix: 'test:replay', replayTtlSec: 300, noncePrefix: 'test:nonce' },
    redis: {
      async set(key, value, _ex, _ttl, nx) {
        replayTtls.push(_ttl);
        if (nx !== 'NX') throw Error('expected atomic replay NX');
        if (keys.has(key)) return null;
        keys.set(key, value);
        return 'OK';
      },
      async call(command, key) {
        if (command !== 'GETDEL') throw Error('Expected atomic Redis GETDEL');
        const val = keys.get(key) || null;
        keys.delete(key);
        return val;
      }
    }
  };
  return { instance, keys, replayTtls };
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

  test('only one concurrent request can consume a DPoP nonce', async () => {
    const f = fixture();
    const key = 'test:nonce:client-a:random-nonce';
    f.keys.set(key, JSON.stringify({ issuedAt: Date.now() }));
    const calls = await Promise.allSettled([
      service.methods.consumeNonce.call(f.instance, { audience: 'client-a', nonce: 'random-nonce' }),
      service.methods.consumeNonce.call(f.instance, { audience: 'client-a', nonce: 'random-nonce' })
    ]);
    expect(calls.filter(v => v.status === 'fulfilled')).toHaveLength(1);
    expect(calls.filter(v => v.status === 'rejected')).toHaveLength(1);
    expect(calls.filter(v => v.status === 'rejected')[0].reason.type).toBe('INVALID_DPOP_NONCE');
    expect(f.keys.has(key)).toBe(false);
  });

  test('invalid ath does not consume nonce before valid proof can use it', async () => {
    const f = fixture();
    const nonce = 'unique-bound-nonce';
    const audience = 'https://client.example/app';
    f.keys.set('test:nonce:' + audience + ':' + nonce, '{"valid":true}');
    const proof = await signedProof({ nonce });
    await expect(service.actions.verifyProof.handler.call(
      { ...f.instance, consumeNonce: service.methods.consumeNonce.bind(f.instance) },
      { params: { ...params(proof), nonce, expectedAth: tokenHash('wrong bearer') } }
    )).rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
    expect(f.keys.has('test:nonce:' + audience + ':' + nonce)).toBe(true);
  });

  test('rejects DPoP protected header exposing a private JWK', async () => {
    const store = fixture();
    const { privateKey } = await generateKeyPair('ES256');
    const privateJwk = await exportJWK(privateKey);
    const proofJwt = await new SignJWT({
      htm: 'POST', htu: URL, iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(), ath: tokenHash(TOKEN)
    }).setProtectedHeader({
      typ: 'dpop+jwt', alg: 'ES256', jwk: privateJwk
    }).sign(privateKey);
    await expect(service.actions.verifyProof.handler.call(store.instance, {
      params: { proofJwt, htm: 'POST', htu: URL,
        audience: 'https://client.example/app', expectedAth: tokenHash(TOKEN) }
    })).rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
    expect(store.keys.size).toBe(0);
  });

  test('replay record cannot expire while the proof remains valid at clock-skew limits', async () => {
    const store = fixture();
    store.instance.settings.replayTtlSec = 60; // Historical unsafe operator config.
    const future = Math.floor(Date.now()/1000) + 55;
    const proof = await signedProof({ iat: future });
    await service.actions.verifyProof.handler.call(store.instance, {
      params: params(proof)
    });
    expect(store.replayTtls).toEqual([420]);
    await expect(service.actions.verifyProof.handler.call(store.instance, {
      params: params(proof)
    })).rejects.toMatchObject({ type: 'DPOP_REPLAY_DETECTED' });
  });

  test('future-dated proofs beyond sixty seconds are rejected', async () => {
    const store = fixture();
    const proof = await signedProof({ iat: Math.floor(Date.now()/1000) + 180 });
    await expect(service.actions.verifyProof.handler.call(store.instance, {
      params: params(proof)
    })).rejects.toMatchObject({ type: 'INVALID_DPOP_PROOF' });
    expect(store.keys.size).toBe(0);
  });

  test('rejects oversized DPoP replay IDs before writing to Redis', async () => {
    const store = fixture();
    const proof = await signedProof({ jti: 'x'.repeat(400) });
    await expect(service.actions.verifyProof.handler.call(store.instance, {
      params: params(proof)
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

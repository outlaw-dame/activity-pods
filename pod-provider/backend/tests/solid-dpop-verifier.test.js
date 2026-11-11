const crypto = require('node:crypto');
const { generateKeyPair, exportJWK, calculateJwkThumbprint, SignJWT } = require('jose');
const { verifySolidDpop } = require('../utils/solid-dpop-verifier');
// The token middleware is tested directly, outside a running provider.
jest.mock('../config/config', () => ({
  BASE_URL: 'https://paper.example.org/',
  FRONTEND_URL: 'https://paper.example.org',
  REDIS_OIDC_PROVIDER_URL: 'redis://127.0.0.1:6379'
}));
const solidOidcService = require('../services/solid/solid-oidc');

const issuer = 'https://paper.example.org/';
const appUri = 'https://paper.example.org/client';
const webId = 'https://paper.example.org/alice';
const targetUrl = 'https://paper.example.org/alice/data/document?view=full';
const token = 'an-already-signature-verified-solid-id-token';

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  const jkt = await calculateJwkThumbprint(jwk);
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: issuer, sub: 'alice',
    webid: webId, azp: appUri, aud: [appUri, 'solid'],
    cnf: { jkt }, iat: now - 10, exp: now + 180
  };
  const create = async (overrides = {}, useKey = privateKey, useJwk = jwk) =>
    new SignJWT({
      htm: 'GET', htu: targetUrl.split('?')[0],
      jti: crypto.randomBytes(20).toString('base64url'),
      iat: now,
      ath: crypto.createHash('sha256').update(token, 'ascii').digest('base64url'),
      ...overrides
    }).setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: useJwk })
      .sign(useKey);
  const seen = new Set();
  const reserveReplay = jest.fn(async key => {
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { now, jwk, privateKey, payload, create, reserveReplay };
}

function input(fixture, proof) {
  return {
    proof, idToken: token, verifiedToken: fixture.payload,
    method: 'GET', targetUrl, reserveReplay: fixture.reserveReplay,
    expectedIssuer: issuer
  };
}

test('valid signed DPoP proof binds the ID token, method, URI and public-key thumbprint', async () => {
  const f = await setup();
  const proof = await f.create();
  const verified = await verifySolidDpop(input(f, proof));
  expect(verified).toEqual({
    webId, appUri, keyThumbprint: f.payload.cnf.jkt
  });
  expect(f.reserveReplay).toHaveBeenCalledTimes(1);
  expect(f.reserveReplay.mock.calls[0][0]).toMatch(/^[0-9a-f]{64}$/);
  expect(f.reserveReplay.mock.calls[0][1]).toBe(130);
});

test('shared replay state rejects a second request even if signed proof and token are valid', async () => {
  const f = await setup();
  const proof = await f.create();
  await verifySolidDpop(input(f, proof));
  await expect(verifySolidDpop(input(f, proof)))
    .rejects.toMatchObject({ code: 'SOLID_DPOP_INVALID' });
  expect(f.reserveReplay).toHaveBeenCalledTimes(2);
});

test('a method, URL, token hash, incorrect key or timestamp mismatch cannot authorize the request', async () => {
  const f = await setup();
  const proof = await f.create();
  const cases = [
    { ...input(f, proof), method: 'POST' },
    { ...input(f, proof), targetUrl: 'https://paper.example.org/alice/data/other' },
    { ...input(f, proof), idToken: 'stolen-token' },
    { ...input(f, proof), verifiedToken: { ...f.payload, cnf: { jkt: 'A'.repeat(43) } } },
    { ...input(f, proof), verifiedToken: { ...f.payload, aud: [appUri] } },
    { ...input(f, proof), verifiedToken: { ...f.payload, exp: f.now - 1 } },
    { ...input(f, proof), expectedIssuer: 'https://attacker.example.org/' }
  ];
  for (const malformed of cases) {
    await expect(verifySolidDpop(malformed))
      .rejects.toMatchObject({ code: 'SOLID_DPOP_INVALID' });
  }
  const stale = await f.create({ iat: f.now - 300 });
  await expect(verifySolidDpop(input(f, stale)))
    .rejects.toMatchObject({ code: 'SOLID_DPOP_INVALID' });
  const missingHash = await f.create({ ath: undefined });
  await expect(verifySolidDpop(input(f, missingHash)))
    .rejects.toMatchObject({ code: 'SOLID_DPOP_INVALID' });
  expect(f.reserveReplay).toHaveBeenCalledTimes(0);
});

test('invalid signature and embedded private key cannot reach the replay ledger', async () => {
  const f = await setup();
  const attacker = await generateKeyPair('ES256');
  const forged = await f.create({}, attacker.privateKey, f.jwk);
  await expect(verifySolidDpop(input(f, forged)))
    .rejects.toMatchObject({ code: 'SOLID_DPOP_INVALID' });
  const privateJwk = await exportJWK(f.privateKey);
  const unsafe = await f.create({}, f.privateKey, privateJwk);
  await expect(verifySolidDpop(input(f, unsafe)))
    .rejects.toMatchObject({ code: 'SOLID_DPOP_INVALID' });
  expect(f.reserveReplay).toHaveBeenCalledTimes(0);
});

test('failure to reserve a shared Redis replay key denies authentication', async () => {
  const f = await setup();
  const proof = await f.create();
  await expect(verifySolidDpop({
    ...input(f, proof), reserveReplay: async () => {
      throw new Error('Redis is disconnected');
    }
  })).rejects.toMatchObject({ code: 'SOLID_DPOP_INVALID' });
});

test('native Solid-OIDC middleware verifies once per HTTP request but rejects a second HTTP replay', async () => {
  const f = await setup();
  const proof = await f.create();
  const seen = new Set();
  const redis = { set: jest.fn(async key => {
    if (seen.has(key)) return null;
    seen.add(key);
    return 'OK';
  }) };
  const instance = {
    settings: { baseUrl: issuer },
    dpopRedis: redis
  };
  instance.verifyDpopRequest = solidOidcService.methods.verifyDpopRequest.bind(instance);
  const req = {
    method: 'GET',
    originalUrl: '/alice/data/document?view=full',
    headers: { dpop: proof }
  };
  await instance.verifyDpopRequest(req, token, f.payload);
  await instance.verifyDpopRequest(req, token, f.payload);
  expect(redis.set).toHaveBeenCalledTimes(1);
  expect(redis.set.mock.calls[0][2]).toBe('EX');
  expect(redis.set.mock.calls[0][4]).toBe('NX');
  await expect(instance.verifyDpopRequest({ ...req }, token, f.payload))
    .rejects.toMatchObject({ code: 'SOLID_DPOP_INVALID' });
});

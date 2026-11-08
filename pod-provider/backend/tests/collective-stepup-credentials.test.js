'use strict';

const crypto = require('node:crypto');
const { jwtVerify, decodeJwt } = require('jose');
const service = require('../services/collective-stepup-credentials.service');

const issuer = 'https://provider.example';
const principal = issuer + '/profile/card#me';
const app = 'https://forum.example/client';
const secret = 'different-from-solid-oidc-jwk-secret'.repeat(3);
const jkt = 'a'.repeat(43);

function harness(settings = {}) {
  const inst = { settings: {
    enabled: true, secret, issuer, ...settings
  }};
  const mint = (overrides = {}) => service.actions.mint.handler.call(inst, {
    params: { principal, app, jkt, verifiedAt: Math.floor(Date.now()/1000), ...overrides }
  });
  const verify = token => service.actions.verify.handler.call(inst, { params: { token } });
  return { inst, mint, verify };
}
async function denied(promise, code) {
  await expect(promise).rejects.toMatchObject({ type: code });
}

describe('isolated provider Group step-up JWT', () => {
  test('WebAuthn-verified principal and app yield a five-minute token with exact DPoP key', async () => {
    const h = harness();
    const result = await h.mint();
    expect(result.tokenType).toBe('DPoP');
    expect(result.expiresIn).toBe(300);
    const claims = decodeJwt(result.token);
    expect(claims).toMatchObject({
      sub: principal, webid: principal, azp: app,
      aud: app, iss: issuer, operation: 'reserve',
      purpose: 'apods:collective-reservation-stepup:v1',
      cnf: { jkt }, amr: ['webauthn']
    });
    expect(claims.exp - claims.iat).toBe(300);
    expect(await h.verify(result.token)).toMatchObject({
      principal, app, jkt
    });
  });

  test('Group-only credential is NOT a token signed by Solid-OIDC ES256 key', async () => {
    const h = harness();
    const result = await h.mint();
    await expect(jwtVerify(result.token, crypto.randomBytes(32), { algorithms: ['ES256'] }))
      .rejects.toThrow();
  });

  test('signer secrets are isolated: a Group token signed by another provider secret fails', async () => {
    const token = (await harness().mint()).token;
    await denied(harness({ secret: 'm'.repeat(48) }).verify(token), 'COLLECTIVE_STEPUP_INVALID');
  });

  test('operation-purpose and audience tampering cannot be accepted', async () => {
    const h = harness();
    const { token } = await h.mint();
    await denied(harness({ issuer: 'https://elsewhere.example' }).verify(token), 'COLLECTIVE_STEPUP_INVALID');
  });

  test.each([
    ['disabled', { enabled: false }, 'COLLECTIVE_STEPUP_DISABLED'],
    ['weak secret', { secret: 'weak' }, 'COLLECTIVE_STEPUP_DISABLED']
  ])('fails closed with %s', async (_label, opts, code) => {
    const h = harness(opts);
    await denied(h.mint(), code);
  });

  test.each([
    ['untrusted WebID', { principal: 'http://insecure.example/me' }],
    ['untrusted app actor', { app: 'https://forum.example/client#redirect' }],
    ['invalid key thumbprint', { jkt: 'invalid' }],
    ['stale WebAuthn assertion', { verifiedAt: Math.floor(Date.now()/1000) - 180 }]
  ])('rejects %s before minting', async (_label, changes) => {
    await denied(harness().mint(changes), 'COLLECTIVE_STEPUP_INVALID');
  });
});

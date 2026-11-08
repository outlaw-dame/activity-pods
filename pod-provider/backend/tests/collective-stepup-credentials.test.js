'use strict';

const crypto = require('node:crypto');
const { jwtVerify, decodeJwt } = require('jose');
const service = require('../services/collective-stepup-credentials.service');
const { signMintAttestation } = require('../services/utils/collective-mint-attestation');

const issuer = 'https://provider.example';
const principal = issuer + '/profile/card#me';
const app = 'https://forum.example/client';
const secret = 'different-from-solid-oidc-jwk-secret'.repeat(3);
const jkt = 'a'.repeat(43);
const issuerSecret = 'distinct-stepup-issuer-secret-'.repeat(3);
const ticketHash = 'b'.repeat(64);

function harness(settings = {}) {
  const inst = { settings: {
    enabled: true, secret, issuer, issuerSecret, approvedApps: [app], ...settings
  }};
  const mint = (overrides = {}) => {
    const params = { principal, app, jkt, verifiedAt: Math.floor(Date.now()/1000),
      ticketHash, ...overrides };
    if (params.issuerAttestation === undefined) {
      params.issuerAttestation = signMintAttestation(issuerSecret, params);
    }
    return service.actions.mint.handler.call(inst, {
      params,
      call: async (action, args) => {
        if (action === 'auth.account.findByWebId') return { webId: args.webId };
        if (action === 'app-registrations.isRegistered') return true;
        if (action === 'access-authorizations.getSpecialRights') return ['apods:CreateGroup'];
        throw new Error('Unexpected SAI service call: ' + action);
      }
    });
  };
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

  test('direct internal calls cannot mint without trusted issuer attestation', async () => {
    const h = harness();
    await denied(h.mint({ issuerAttestation: '0'.repeat(64) }), 'COLLECTIVE_STEPUP_INVALID');
    await denied(h.mint({ issuerAttestation: 'é'.repeat(64) }), 'COLLECTIVE_STEPUP_INVALID');
    await denied(h.mint({ issuerAttestation: null }), 'COLLECTIVE_STEPUP_INVALID');
    await denied(h.mint({ issuerAttestation: signMintAttestation(issuerSecret, {
      principal, app, jkt, verifiedAt: Math.floor(Date.now()/1000),
      ticketHash: 'f'.repeat(64)
    }) }), 'COLLECTIVE_STEPUP_INVALID');
  });

  test('cannot mint after SAI right is withdrawn at credential boundary', async () => {
    const h = harness();
    const params = {
      principal, app, jkt, verifiedAt: Math.floor(Date.now()/1000), ticketHash
    };
    await denied(service.actions.mint.handler.call(h.inst, {
      params: { ...params, issuerAttestation: signMintAttestation(issuerSecret, params) },
      call: async action => {
        if (action === 'auth.account.findByWebId') return { webId: principal };
        if (action === 'app-registrations.isRegistered') return true;
        if (action === 'access-authorizations.getSpecialRights') return [];
        throw new Error('Unexpected call');
      }
    }), 'COLLECTIVE_APP_CONSENT_MISSING');
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

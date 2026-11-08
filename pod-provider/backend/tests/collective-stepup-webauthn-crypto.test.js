'use strict';

const crypto = require('node:crypto');
// Isolate the passkey cryptographic contract from unrelated instance env.
// esbuild-jest hoists static requires, so process.env assignments made above
// require() are NOT a reliable way to initialize CONFIG during this test.
jest.mock('../config/config', () => ({
  BASE_URL: 'https://provider.example',
  FRONTEND_URL: 'https://provider.example',
  COOKIE_SECRET: 'test-credential-signing-secret-for-webauthn'
}));
const passkeys = require('../services/passkeys-api.service');

const ORIGIN = 'https://provider.example';
const WEBID = ORIGIN + '/users/alice#me';
const CREDENTIAL_ID = crypto.randomBytes(20).toString('base64url');
const TICKET_SECRET = 'dedicated-passkey-test-secret-'.repeat(3);

function p256Cose(publicJwk) {
  const x = Buffer.from(publicJwk.x, 'base64url');
  const y = Buffer.from(publicJwk.y, 'base64url');
  // Canonical COSE_Key: {1:2, 3:-7, -1:1, -2:x, -3:y}.
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    x, Buffer.from([0x22, 0x58, 0x20]), y
  ]);
}
function harness() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1'
  });
  const jwk = publicKey.export({ format: 'jwk' });
  const credential = {
    credentialId: CREDENTIAL_ID, webId: WEBID, publicKey: p256Cose(jwk).toString('base64url'),
    counter: 0, transports: [], userHandle: 'dGVzdC11c2Vy'
  };
  const instance = {
    settings: { ticketTtlSec: 300 },
    getExpectedOrigin: () => ORIGIN,
    getRpId: () => 'provider.example',
    ticketSecret: () => TICKET_SECRET,
    signTicket: passkeys.methods.signTicket,
    readTicket: passkeys.methods.readTicket,
    normalizeCredentialId: passkeys.methods.normalizeCredentialId,
    requireWebauthnResponse: passkeys.methods.requireWebauthnResponse,
    async getCredentialByCredentialId(_ctx, id) {
      return id === CREDENTIAL_ID ? credential : null;
    },
    async touchCredential(_ctx, id, updates) {
      expect(id).toBe(CREDENTIAL_ID);
      credential.counter = updates.counter;
      return credential;
    },
    verifyAuthenticationAssertion: passkeys.methods.verifyAuthenticationAssertion
  };

  const challenge = crypto.randomBytes(32).toString('base64url');
  const ticket = instance.signTicket({ kind: 'authentication', challenge });
  const clientData = Buffer.from(JSON.stringify({
    type: 'webauthn.get', challenge, origin: ORIGIN,
    crossOrigin: false
  }));
  const authData = Buffer.alloc(37);
  crypto.createHash('sha256').update('provider.example').digest().copy(authData, 0);
  authData[32] = 0x05; // UP + UV.
  authData.writeUInt32BE(1, 33);
  const signed = Buffer.concat([
    authData, crypto.createHash('sha256').update(clientData).digest()
  ]);
  const signature = crypto.sign('sha256', signed, privateKey);
  const response = {
    id: CREDENTIAL_ID, rawId: CREDENTIAL_ID, type: 'public-key',
    response: {
      clientDataJSON: clientData.toString('base64url'),
      authenticatorData: authData.toString('base64url'),
      signature: signature.toString('base64url')
    },
    clientExtensionResults: {}
  };
  return { instance, credential, ticket, response };
}

describe('actual passkey assertion verification reused by Group step-up', () => {
  test('verifies real P-256 signed WebAuthn response, UV and rpID, then updates credential counter', async () => {
    const { instance, credential, ticket, response } = harness();
    const result = await passkeys.actions.verifyAssertion.call(instance, {
      params: { ticket, response }
    });
    expect(result.webId).toBe(WEBID);
    expect(credential.counter).toBe(1);
    expect(result).not.toHaveProperty('token');
  });

  test('tampered WebAuthn signature is rejected', async () => {
    const { instance, ticket, response } = harness();
    response.response.signature = crypto.randomBytes(70).toString('base64url');
    await expect(passkeys.actions.verifyAssertion.call(instance, {
      params: { ticket, response }
    })).rejects.toMatchObject({ type: 'PASSKEY_AUTHENTICATION_FAILED' });
  });

  test('the same assertion fails counter replay after successful verification', async () => {
    const { instance, ticket, response } = harness();
    await passkeys.actions.verifyAssertion.call(instance, { params: { ticket, response } });
    await expect(passkeys.actions.verifyAssertion.call(instance, {
      params: { ticket, response }
    })).rejects.toMatchObject({ type: 'PASSKEY_AUTHENTICATION_FAILED' });
  });

  test('tampered signed ticket is rejected before credential lookup', async () => {
    const { instance, ticket, response } = harness();
    await expect(passkeys.actions.verifyAssertion.call(instance, {
      params: { ticket: ticket.slice(0, -2) + 'AA', response }
    })).rejects.toMatchObject({ type: 'PASSKEY_TICKET_INVALID' });
  });
});

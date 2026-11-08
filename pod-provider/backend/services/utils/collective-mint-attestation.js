'use strict';

const crypto = require('node:crypto');
const PURPOSE = 'provider.collective.stepup.mint-attestation.v1';

function keyBytes(secret) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret, 'utf8') < 32) return null;
  return Buffer.from(secret, 'utf8');
}
function signedFields({ principal, app, jkt, verifiedAt, ticketHash }) {
  return [PURPOSE, principal, app, jkt, verifiedAt, ticketHash];
}
function signMintAttestation(secret, claims) {
  const key = keyBytes(secret);
  if (!key) return null;
  const fields = signedFields(claims);
  return crypto.createHmac('sha256', key).update(JSON.stringify(fields)).digest('hex');
}
function verifyMintAttestation(secret, claims, signature) {
  const expected = signMintAttestation(secret, claims);
  if (typeof signature !== 'string' || !/^[a-f0-9]{64}$/u.test(signature) || !expected) return false;
  return crypto.timingSafeEqual(Buffer.from(signature, 'ascii'), Buffer.from(expected, 'ascii'));
}
module.exports = { signMintAttestation, verifyMintAttestation };

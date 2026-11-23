'use strict';

// NONACTIVATED: independent, challenge-bound latest credential checkpoint
// verifier. A trusted signature over a fresh nonce defeats replay of an old
// *response*; only an independently administered, nonrewindable signer can
// guarantee that the signer's underlying latest state has not been restored.
// No app/server/admin key may sign the external latest head.
const crypto = require('node:crypto');
const { Buffer } = require('node:buffer');
const CERTIFIED = new WeakSet();
const EPOCH = /^[1-9][0-9]{0,18}$/u;
const HEX = /^[a-f0-9]{64}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const AUTHORITY = /^[a-z0-9._:-]{3,128}$/u;
const MAX_EPOCH = 9223372036854775807n;
const DOMAIN = Buffer.from('paper:credential:attest:v1\0');
const SUBJECT_DOMAIN = 'paper:credential:owner:v1\0';
const FIELDS = 'authority,digest,epoch,issuedAt,kind,nonce,state,subject';

function deny(code) {
  const error = new Error('Independent credential head unavailable');
  error.code = code;
  throw error;
}
function validWebId(value) {
  if (typeof value !== 'string' || value.length < 8 || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !!url.hostname && !url.username &&
      !url.password && !url.search && !url.hash && url.href === value;
  } catch { return false; }
}
function validEpoch(value) {
  return typeof value === 'string' && EPOCH.test(value) && BigInt(value) <= MAX_EPOCH;
}
function subjectHash(webId) {
  if (!validWebId(webId)) deny('CREDENTIAL_HEAD_SCOPE_INVALID');
  return crypto.createHash('sha256').update(SUBJECT_DOMAIN).update(webId).digest('hex');
}
function testGate(fixtureOnly) {
  if (fixtureOnly !== true || process.env.NODE_ENV !== 'test' ||
      process.env.PAPER_CREDENTIAL_HEAD_DISPOSABLE !== 'confirmed')
    deny('CREDENTIAL_HEAD_NOT_RELEASED');
}
function createDisposableCredentialHeadAuthority({
  readHead, trustedPublicKey, authority, fixtureOnly = false,
  now = () => Math.floor(Date.now() / 1000),
  timeoutMs = 2500, maxSkewSeconds = 20
} = {}) {
  testGate(fixtureOnly);
  if (typeof readHead !== 'function' || typeof now !== 'function' ||
      !AUTHORITY.test(authority || '') ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 5000 ||
      !Number.isSafeInteger(maxSkewSeconds) || maxSkewSeconds < 1 ||
      maxSkewSeconds > 60) deny('CREDENTIAL_HEAD_CONFIGURATION_INVALID');
  // Do not turn accidentally provisioned private-key PEM into a trusted
  // public key: createPublicKey(privatePem) would silently derive its public
  // half, masking a catastrophic custody boundary breach.
  if (typeof trustedPublicKey === 'string') {
    if (Buffer.byteLength(trustedPublicKey) > 512 ||
        !/^-----BEGIN PUBLIC KEY-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+-----END PUBLIC KEY-----\\r?\\n?$/u.test(trustedPublicKey))
      deny('CREDENTIAL_HEAD_KEY_INVALID');
  } else if (!(trustedPublicKey instanceof crypto.KeyObject)) {
    deny('CREDENTIAL_HEAD_KEY_INVALID');
  }
  let key;
  try {
    key = trustedPublicKey instanceof crypto.KeyObject ?
      trustedPublicKey : crypto.createPublicKey(trustedPublicKey);
  } catch { deny('CREDENTIAL_HEAD_KEY_INVALID'); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519')
    deny('CREDENTIAL_HEAD_KEY_INVALID');

  async function readFresh(webId) {
    testGate(fixtureOnly);
    const subject = subjectHash(webId);
    const nonce = crypto.randomBytes(32).toString('base64url');
    const controller = new AbortController();
    let timer;
    let reply;
    try {
      reply = await Promise.race([
        Promise.resolve().then(() => readHead(
          Object.freeze({ kind: 'paper.credential.challenge.v1', subject, nonce,
            signal: controller.signal })
        )),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error('head timeout')), timeoutMs);
        })
      ]);
    } catch { deny('CREDENTIAL_HEAD_UNAVAILABLE'); }
    finally {
      clearTimeout(timer);
      controller.abort();
    }
    if (!Buffer.isBuffer(reply?.body) || !Buffer.isBuffer(reply?.signature) ||
        reply.body.length < 170 || reply.body.length > 1024 ||
        reply.signature.length !== 64)
      deny('CREDENTIAL_HEAD_FORMAT_INVALID');
    const signed = Buffer.concat([DOMAIN, reply.body]);
    if (!crypto.verify(null, signed, key, reply.signature))
      deny('CREDENTIAL_HEAD_SIGNATURE_INVALID');
    let data;
    try { data = JSON.parse(reply.body.toString('utf8')); }
    catch { deny('CREDENTIAL_HEAD_FORMAT_INVALID'); }
    if (!data || Array.isArray(data) || typeof data !== 'object' ||
        Object.keys(data).sort().join(',') !== FIELDS ||
        data.kind !== 'paper.credential.head.v1' ||
        data.authority !== authority || data.subject !== subject ||
        !NONCE.test(data.nonce || '') || data.nonce !== nonce ||
        !validEpoch(data.epoch) || !HEX.test(data.digest || '') ||
        !['active', 'pending', 'disabled'].includes(data.state) ||
        !Number.isSafeInteger(data.issuedAt) || data.issuedAt <= 0)
      deny('CREDENTIAL_HEAD_SCOPE_INVALID');
    const canonical = Buffer.from(JSON.stringify({
      kind: data.kind, authority: data.authority, subject: data.subject,
      epoch: data.epoch, state: data.state, digest: data.digest,
      nonce: data.nonce, issuedAt: data.issuedAt
    }));
    if (canonical.length !== reply.body.length ||
        !crypto.timingSafeEqual(canonical, reply.body))
      deny('CREDENTIAL_HEAD_CANONICAL_INVALID');
    let seconds;
    try { seconds = now(); } catch { deny('CREDENTIAL_HEAD_CLOCK_INVALID'); }
    if (!Number.isSafeInteger(seconds) || seconds <= 0 ||
        Math.abs(data.issuedAt - seconds) > maxSkewSeconds)
      deny('CREDENTIAL_HEAD_CLOCK_INVALID');
    return Object.freeze({
      authority, subject, epoch: data.epoch, state: data.state,
      digest: data.digest
    });
  }
  const result = Object.freeze({ readFresh, releaseAccepted: false });
  CERTIFIED.add(result);
  return result;
}
function isDisposableCredentialHeadAuthority(value) {
  return !!value && typeof value === 'object' && CERTIFIED.has(value);
}
module.exports = {
  createDisposableCredentialHeadAuthority,
  isDisposableCredentialHeadAuthority,
  subjectHash
};

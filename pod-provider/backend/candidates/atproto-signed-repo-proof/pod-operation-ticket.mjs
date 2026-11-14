/**
 * Local provider authority for an exact ATProto per-Pod RDF operation.
 * The issuer MUST remain in trusted provider code; never register it on an
 * API route or expose it as a generic Moleculer mint action.
 *
 * Authentication is independent of spoofable Moleculer ctx.meta. This only
 * authenticates the provider operation, it does NOT replace current OIDC,
 * SAI grant verification or the Jena consent revocation fence.
 */
import crypto from 'node:crypto';
// v2 binds the PostgreSQL recovery lease fence independently of the SAI
// consent revision. Never accept v1 tickets on the v2 projection path.
// v3 binds signed repository generation and independently verified parent root
// into the HMAC. Earlier project tickets cannot authorize record mutations.
const PURPOSE = 'paper.atproto.pod-projection.v3';
const DID = /^did:plc:[a-z2-7]{24}$/u;
const FENCE = /^[1-9][0-9]{0,18}$/u;
const CID = /^bafyre[a-z2-7]{53}$/u;
const TID = /^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
function deny() {
  const e = new Error('Missing or invalid provider RDF operation authority');
  e.code = 'POD_PROJECTION_PROVIDER_UNAUTHORIZED';
  throw e;
}
function safeUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) deny();
  let url;
  try { url = new URL(value); } catch { deny(); }
  if (url.protocol !== 'https:' || url.href !== value ||
      url.username || url.password || url.search || url.hash) deny();
  return value;
}
function hmac(secret, body) {
  return crypto.createHmac('sha256', secret).update(PURPOSE + '\0' + body).digest();
}
export function createPodOperationTicketAuthority({ secret, now = Date.now } = {}) {
  const key = Buffer.isBuffer(secret) ? secret : Buffer.from(secret || '', 'utf8');
  if (key.byteLength < 32) deny();
  function normalizeScope({ accountId, did, appUri, grantUri, epoch, operation, projectionFence = null, rootCid = null, rev = null, generation = null, previousRootCid = null, previousRev = null }) {
    safeUrl(accountId);
    safeUrl(appUri);
    safeUrl(grantUri);
    if (!['bootstrap', 'project', 'revoke'].includes(operation) ||
        !DID.test(did || '') || typeof epoch !== 'string' ||
        !FENCE.test(epoch) || BigInt(epoch) > 9223372036854775807n) deny();
    if (operation === 'project') {
      if (!CID.test(rootCid || '') || !TID.test(rev || '') ||
          typeof projectionFence !== 'string' || !FENCE.test(projectionFence) ||
          BigInt(projectionFence) > 9223372036854775807n ||
          !Number.isSafeInteger(generation) || generation < 1 ||
          (generation === 1 &&
            (previousRootCid !== null || previousRev !== null)) ||
          (generation > 1 &&
            (!CID.test(previousRootCid || '') ||
             !TID.test(previousRev || '') || previousRev >= rev))) deny();
    } else if (rootCid !== null || rev !== null || projectionFence !== null ||
               generation !== null || previousRootCid !== null ||
               previousRev !== null) deny();
    return { accountId, did, appUri, grantUri, epoch, operation,
      projectionFence, rootCid, rev, generation, previousRootCid, previousRev };
  }
  function issue(scope) {
    const fields = normalizeScope(scope);
    const issuedAt = now();
    if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) deny();
    const payload = { purpose: PURPOSE, ...fields, issuedAt,
      expiresAt: issuedAt + 30000, nonce: crypto.randomBytes(16).toString('hex') };
    const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    return 'pt1.' + body + '.' + hmac(key, body).toString('base64url');
  }
  function verify(ticket, scope) {
    const expected = normalizeScope(scope);
    if (typeof ticket !== 'string' || ticket.length > 8192) deny();
    const match = /^pt1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{43})$/u.exec(ticket);
    if (!match) deny();
    let signature;
    let payload;
    try {
      signature = Buffer.from(match[2], 'base64url');
      payload = JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8'));
    } catch { deny(); }
    // Reject noncanonical base64url spellings (including alternate unused
    // padding bits); a single credential must not have multiple encodings.
    if (signature.toString('base64url') !== match[2] ||
        Buffer.from(match[1], 'base64url').toString('base64url') !== match[1]) deny();
    const calculated = hmac(key, match[1]);
    if (signature.length !== calculated.length ||
        !crypto.timingSafeEqual(signature, calculated)) deny();
    const time = now();
    if (!payload || payload.purpose !== PURPOSE ||
        !Number.isSafeInteger(payload.issuedAt) ||
        !Number.isSafeInteger(payload.expiresAt) ||
        payload.expiresAt - payload.issuedAt !== 30000 ||
        payload.issuedAt > time + 5000 || payload.expiresAt <= time ||
        !/^[0-9a-f]{32}$/u.test(payload.nonce || '')) deny();
    for (const [keyName, value] of Object.entries(expected)) {
      if (payload[keyName] !== value) deny();
    }
    return Object.freeze({ ...expected, expiresAt: payload.expiresAt });
  }
  return Object.freeze({ issue, verify });
}

'use strict';

/**
 * Candidate ordinary-provider client for a separate dataset administrator.
 *
 * This is wired to the *real* Moleculer dataset-provisioning action only in
 * explicit disposable tests. It accepts a pre-signed claim from a trusted
 * reservation issuer; the ordinary provider never signs claims, handles
 * Fuseki admin credentials or accepts caller-selected network endpoints.
 *
 * No production setting can activate this candidate. The native managed
 * storage production release fuse remains closed separately.
 */
const ENDPOINT = 'http://127.0.0.1:3042/v1/provision';
const DATASET = /^claimtest-[a-z0-9]{8,24}$/u;
const FORBIDDEN_ENV = Object.freeze([
  'SEMAPPS_JENA_PASSWORD',
  'ATPROTO_REPO_PROOF_DSN',
  'PGPASSWORD',
  'PGUSER',
  'DATASET_ADMIN_AGENT_DSN',
  'DATASET_ADMIN_FUSEKI_PASSWORD',
  'DATASET_ADMIN_SIGNER_PRIVATE_KEY'
]);
const CLAIM_KEYS = Object.freeze([
  'version','issuer','audience','dataset','ownerWebid',
  'reservationId','nonce','issuedAtMs','expiresAtMs'
]);

function refusal(code, status = 503) {
  const error = new Error('Restricted dataset administration is unavailable');
  error.code = code;
  error.status = status;
  throw error;
}
function isExactObject(value, keys) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === keys.length &&
    keys.every(key => Object.hasOwn(value, key));
}
function assertDisposableProvider(env = process.env) {
  if (env.NODE_ENV !== 'test' ||
      env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE !== 'confirmed' ||
      env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
      env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE !== 'confirmed' ||
      env.FUSEKI_ISOLATION_URL !== 'http://127.0.0.1:3041') {
    refusal('DATASET_ADMIN_DELEGATION_NOT_RELEASED');
  }
  // A working credential-isolation proof cannot reside in a process that
  // already has the authority to bypass the delegated administration.
  if (FORBIDDEN_ENV.some(key => typeof env[key] === 'string' && env[key].length)) {
    refusal('DATASET_ADMIN_DELEGATION_PRIVILEGE_LEAK');
  }
}
function validateTicket(dataset, ticket, now = Date.now()) {
  if (typeof dataset !== 'string' || !DATASET.test(dataset) ||
      !isExactObject(ticket, ['claim','signature']) ||
      !isExactObject(ticket.claim, CLAIM_KEYS)) {
    refusal('DATASET_ADMIN_DELEGATION_CLAIM_INVALID', 403);
  }
  const claim = ticket.claim;
  if (claim.version !== 1 ||
      claim.issuer !== 'https://paper.example.org/provider' ||
      claim.audience !== 'urn:activitypods:dataset-admin:v1' ||
      claim.dataset !== dataset ||
      claim.ownerWebid !== 'https://paper.example.org/users/' + dataset ||
      typeof claim.reservationId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(claim.reservationId) ||
      typeof claim.nonce !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(claim.nonce) ||
      !Number.isSafeInteger(claim.issuedAtMs) ||
      !Number.isSafeInteger(claim.expiresAtMs) ||
      claim.expiresAtMs - claim.issuedAtMs < 1000 ||
      claim.expiresAtMs - claim.issuedAtMs > 120000 ||
      claim.issuedAtMs - now > 30000 ||
      now - claim.issuedAtMs > 120000 ||
      now >= claim.expiresAtMs ||
      typeof ticket.signature !== 'string' ||
      !/^[A-Za-z0-9_-]{86}$/u.test(ticket.signature)) {
    refusal('DATASET_ADMIN_DELEGATION_CLAIM_INVALID', 403);
  }
  // This is a fast local format/scope check, NOT signature verification.
  // Only the sidecar holding the issuer PUBLIC key may authenticate it.
  return ticket;
}
async function readBoundedJson(response) {
  const reader = response.body?.getReader?.();
  if (!reader) refusal('DATASET_ADMIN_DELEGATION_RESPONSE_INVALID');
  let size = 0;
  const parts = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > 512) refusal('DATASET_ADMIN_DELEGATION_RESPONSE_TOO_LARGE');
      parts.push(Buffer.from(next.value));
    }
  } finally {
    if (reader) await reader.cancel().catch(() => {});
    reader?.releaseLock();
  }
  try { return JSON.parse(Buffer.concat(parts, size).toString('utf8')); }
  catch { refusal('DATASET_ADMIN_DELEGATION_RESPONSE_INVALID'); }
}
/**
 * Called by actual dataset-provisioning service in disposable mode.
 * The caller's Moleculer ctx.meta must contain a previously issued claim.
 * ctx.meta is not considered an authority: the admin sidecar verifies the
 * Ed25519 signature, expected owner and unique PostgreSQL reservation.
 */
async function createDelegatedDisposableDataset({
  dataset, ticket, env = process.env, fetchImpl = globalThis.fetch, now = Date.now()
} = {}) {
  assertDisposableProvider(env);
  validateTicket(dataset, ticket, now);
  if (typeof fetchImpl !== 'function') {
    refusal('DATASET_ADMIN_DELEGATION_NETWORK_UNAVAILABLE');
  }
  const payload = JSON.stringify({ticket});
  if (Buffer.byteLength(payload, 'utf8') > 4096) {
    refusal('DATASET_ADMIN_DELEGATION_CLAIM_INVALID', 403);
  }
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 6000);
  let response;
  try {
    response = await fetchImpl(ENDPOINT, {
      method: 'POST', redirect: 'manual', signal: ctl.signal,
      headers: {'content-type': 'application/json'},
      body: payload
    });
    if (response.status !== 200) {
      if (response.body?.cancel) await response.body.cancel().catch(() => {});
      refusal(response.status === 409 ? 'DATASET_ADMIN_DELEGATION_CONFLICT' :
        response.status === 403 ? 'DATASET_ADMIN_DELEGATION_REJECTED' :
          'DATASET_ADMIN_DELEGATION_UNAVAILABLE',
      response.status === 409 ? 409 : 503);
    }
    const result = await readBoundedJson(response);
    if (!isExactObject(result, ['created','idempotent']) ||
        result.created !== true || typeof result.idempotent !== 'boolean') {
      refusal('DATASET_ADMIN_DELEGATION_RESPONSE_INVALID');
    }
    return Object.freeze({
      dataset, created: true, idempotent: result.idempotent,
      strategy: 'isolated_claim_admin_disposable'
    });
  } catch (error) {
    if (typeof error?.code === 'string' &&
        error.code.startsWith('DATASET_ADMIN_DELEGATION_')) throw error;
    refusal('DATASET_ADMIN_DELEGATION_UNAVAILABLE');
  } finally {
    clearTimeout(timer);
  }
}
module.exports = {
  assertDisposableProvider, validateTicket, createDelegatedDisposableDataset
};

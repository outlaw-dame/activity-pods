'use strict';

/**
 * NONACTIVATED Paper credential epoch guard for newly enrolled unified
 * accounts. SemApps auth.jwt signs RS256 tokens without exp/revocation.
 *
 * This guard DOES NOT hold canonical credential state. The injected authority
 * must be a separately durable, rollback-resistant account epoch reader and
 * serialized change coordinator. No Redis-only or local hash fallback.
 *
 * Do not enable until auth.account mutation paths + native Solid/SAI/PDS
 * admission have shared transactional revocation acceptance.
 */
const crypto = require('node:crypto');
const { Errors: { MoleculerError } } = require('moleculer');

const EPOCH = /^[1-9][0-9]{0,18}$/u;
const MAX_EPOCH = 9223372036854775807n;
const TOKEN_KEYS = ['paper_credential_epoch', 'iat', 'exp'];
const TOKEN_TTL_SECONDS = 900;

function refuse(code = 'CREDENTIAL_EPOCH_UNAVAILABLE') {
  throw new MoleculerError('Canonical credential authority unavailable',
    503, code, { retryable: false });
}
function validWebId(value) {
  if (typeof value !== 'string' || value.length < 8 || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !!url.hostname &&
      !url.username && !url.password && !url.search && !url.hash &&
      url.href === value;
  } catch { return false; }
}
function validEpoch(value) {
  return typeof value === 'string' && EPOCH.test(value) &&
    BigInt(value) <= MAX_EPOCH;
}
function validRecord(record, webId) {
  return record && record.webId === webId &&
    record.mode === 'unified' &&
    validEpoch(record.epoch) && record.state === 'active';
}
function enabled(options) {
  return options?.fixtureOnly === true &&
    process.env.NODE_ENV === 'test' &&
    process.env.PAPER_CREDENTIAL_EPOCH_DISPOSABLE === 'confirmed';
}
function hasEnrollmentMarker(account, webId) {
  return account && account.webId === webId &&
    typeof account.signupReservationId === 'string' &&
    account.signupReservationId.length >= 16;
}
function equalEpoch(first, second) {
  return validEpoch(first) && validEpoch(second) &&
    first.length === second.length &&
    crypto.timingSafeEqual(Buffer.from(first), Buffer.from(second));
}

function createDisposableCredentialEpochMiddleware({
  fixtureOnly = false, authority, ttlSeconds = TOKEN_TTL_SECONDS,
  now = () => Math.floor(Date.now() / 1000)
} = {}) {
  // A production broker must never register a test reader or accidentally
  // accept a fallback status from a stale cache.
  if (!enabled({ fixtureOnly })) refuse('CREDENTIAL_EPOCH_NOT_RELEASED');
  if (typeof authority?.readOwnerState !== 'function' ||
      typeof now !== 'function' ||
      !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 ||
      ttlSeconds > 3600) refuse('CREDENTIAL_EPOCH_CONFIGURATION_INVALID');

  const getAccount = async (ctx, webId) => {
    if (!validWebId(webId)) refuse('CREDENTIAL_EPOCH_SCOPE_INVALID');
    try {
      const account = await ctx.broker.call('auth.account.findByWebId',
        { webId }, { meta: {}, retries: 0, timeout: 3000 });
      if (!account || account.webId !== webId) refuse('CREDENTIAL_EPOCH_ACCOUNT_UNAVAILABLE');
      return account;
    } catch {
      refuse('CREDENTIAL_EPOCH_ACCOUNT_UNAVAILABLE');
    }
  };
  const read = async (webId, account) => {
    let record;
    try { record = await authority.readOwnerState(webId); }
    catch { refuse(); }
    if (!record || record.webId !== webId) refuse();
    // A restored/missing enrollment marker must NEVER downgrade an owner
    // from unified to legacy. Classification must be independently durable,
    // not inferred solely from a rewound account record.
    if (record.mode === 'legacy') {
      if (hasEnrollmentMarker(account, webId)) refuse('CREDENTIAL_EPOCH_DOWNGRADE_DENIED');
      return null;
    }
    if (!hasEnrollmentMarker(account, webId))
      refuse('CREDENTIAL_EPOCH_DOWNGRADE_DENIED');
    if (!validRecord(record, webId)) refuse();
    return record.epoch;
  };
  const clock = () => {
    const value = now();
    if (!Number.isSafeInteger(value) || value <= 0 ||
        !Number.isSafeInteger(value + ttlSeconds))
      refuse('CREDENTIAL_EPOCH_CLOCK_INVALID');
    return value;
  };
  const safeToken = token => {
    if (!token || typeof token !== 'object' || Array.isArray(token) ||
        !validWebId(token.webId) || !validEpoch(token.paper_credential_epoch) ||
        !Number.isSafeInteger(token.iat) || !Number.isSafeInteger(token.exp) ||
        token.iat <= 0 || token.exp - token.iat !== ttlSeconds ||
        token.exp <= clock() || token.iat > clock() + 30)
      return false;
    return true;
  };

  return {
    name: 'PaperDisposableCredentialEpoch',
    localAction(next, action) {
      if (action.name === 'auth.jwt.generateServerSignedToken') {
        return async ctx => {
          const original = ctx.params?.payload;
          const webId = original?.webId;
          const account = await getAccount(ctx, webId);
          const first = await read(webId, account);
          if (first === null) return next(ctx);
          if (!original || Object.getPrototypeOf(original) !== Object.prototype ||
              TOKEN_KEYS.some(k => Object.prototype.hasOwnProperty.call(original, k)))
            refuse('CREDENTIAL_EPOCH_TOKEN_SHAPE_INVALID');
          const issuedAt = clock();
          // SemApps' upstream JWT signer accepts iat/exp JSON claims.
          // Never accept epoch/iat/exp from the HTTP client.
          const minted = {
            ...original, paper_credential_epoch: first,
            iat: issuedAt, exp: issuedAt + ttlSeconds
          };
          const previous = ctx.params;
          let result;
          try {
            ctx.params = { ...previous, payload: minted };
            result = await next(ctx);
          } finally {
            ctx.params = previous;
          }
          // A credential change racing signing means the resulting token
          // must not be given to the caller.
          const afterAccount = await getAccount(ctx, webId);
          const second = await read(webId, afterAccount);
          if (!equalEpoch(first, second)) refuse('CREDENTIAL_EPOCH_CHANGED');
          return result;
        };
      }
      if (action.name === 'auth.jwt.verifyServerSignedToken') {
        return async ctx => {
          // SemApps is the only component validating RS256 signature.
          // Do not parse or trust unverified token payload.
          const payload = await next(ctx);
          if (!payload) return payload;
          const webId = payload.webId;
          let account;
          try { account = await getAccount(ctx, webId); }
          catch { return false; }
          try {
            const current = await read(webId, account);
            if (current === null) return payload;
            return safeToken(payload) &&
              equalEpoch(payload.paper_credential_epoch, current) ?
              payload : false;
          } catch { return false; }
        };
      }
      return next;
    }
  };
}

/**
 * Strictly scoped proof of one credential mutation crossing the canonical
 * epoch authority BEFORE touching SemApps account state. beginChange must
 * atomically mark the owner 'pending'; reads must deny pending. Once apply
 * has begun, an error/timeout is an ambiguous mutation: do NOT 'undo'
 * pending, guess whether the password changed, or retry a second mutation.
 * Reconciliation must inspect both stores independently.
 */
async function runDisposableCredentialChange({
  authority, webId, operationId, apply, fixtureOnly = false
} = {}) {
  if (!enabled({ fixtureOnly })) refuse('CREDENTIAL_EPOCH_NOT_RELEASED');
  if (!validWebId(webId) ||
      typeof operationId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(operationId) ||
      typeof apply !== 'function' ||
      typeof authority?.beginChange !== 'function' ||
      typeof authority?.commitChange !== 'function')
    refuse('CREDENTIAL_EPOCH_CONFIGURATION_INVALID');
  let admission;
  try {
    admission = await authority.beginChange({ webId, operationId });
  } catch { refuse('CREDENTIAL_EPOCH_MUTATION_UNCERTAIN'); }
  if (admission?.accepted !== true ||
      !validEpoch(admission.previousEpoch) ||
      !validEpoch(admission.nextEpoch) ||
      BigInt(admission.nextEpoch) !== BigInt(admission.previousEpoch) + 1n)
    refuse('CREDENTIAL_EPOCH_MUTATION_UNCERTAIN');

  let changed;
  try { changed = await apply(); }
  catch { refuse('CREDENTIAL_EPOCH_MUTATION_UNCERTAIN'); }
  let sealed;
  try {
    sealed = await authority.commitChange({
      webId, operationId, nextEpoch: admission.nextEpoch
    });
  } catch { refuse('CREDENTIAL_EPOCH_MUTATION_UNCERTAIN'); }
  if (sealed?.committed !== true ||
      sealed.epoch !== admission.nextEpoch)
    refuse('CREDENTIAL_EPOCH_MUTATION_UNCERTAIN');
  return changed;
}
module.exports = {
  createDisposableCredentialEpochMiddleware,
  runDisposableCredentialChange
};

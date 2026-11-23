'use strict';

const { Errors: { MoleculerError } } = require('moleculer');

// The enrolled-but-not-released owner cannot use the upstream SemApps
// plaintext password/reset/tombstone actions. These mutate the underlying
// account outside Paper's independently attested pending-epoch coordinator.
// Existing legacy accounts are unaffected by this holding fence.
// These are inherited from moleculer-db. They are *not* the reviewed
// SemApps create/change/settings/delete actions: arbitrary generic inserts
// and updates have no owner-scoped credential/consent authorization.
const RAW_DB_WRITES = new Set([
  'auth.account.insert', 'auth.account.update', 'auth.account.remove'
]);

const ENROLLED_MUTATIONS = new Set([
  'auth.account.setPassword',
  'auth.account.setNewPassword',
  'auth.account.generateResetPasswordToken',
  'auth.account.updateAccountSettings',
  'auth.account.deleteByWebId',
  'auth.account.setTombstone'
]);

function refuseMutation() {
  throw new MoleculerError('Unified account credential mutation is not released',
    503, 'ACCOUNT_ENROLLMENT_MUTATION_NOT_RELEASED', { retryable: false });
}
async function assertNoEnrolledMutation(ctx, actionName) {
  // Upstream updateAccountSettings takes the WebID from ctx.meta, not
  // ctx.params; other SemApps mutations consume ctx.params.webId.
  const webId = actionName === 'auth.account.updateAccountSettings'
    ? ctx.meta?.webId : ctx.params?.webId;
  if (typeof webId !== 'string' || webId.length < 8 || webId.length > 2048)
    refuseMutation();
  let account;
  try {
    account = await ctx.broker.call('auth.account.findByWebId',
      { webId }, { meta: {}, timeout: 3000, retries: 0 });
  } catch { refuseMutation(); }
  if (!account || account.webId !== webId) refuseMutation();
  if (Object.prototype.hasOwnProperty.call(account, 'signupReservationId'))
    refuseMutation();
}


function deny() {
  throw new MoleculerError('Account enrollment is incomplete',
    403, 'ACCOUNT_ENROLLMENT_INCOMPLETE', { retryable: false });
}

async function assertOwnerAccess(broker, account) {
  if (!account || !Object.prototype.hasOwnProperty.call(account, 'signupReservationId')) return;
  const { signupReservationId, username, webId } = account;
  if (process.env.NODE_ENV !== 'test' || process.env.PAPER_LOCAL_NATIVE_AUTH !== 'confirmed' ||
      process.env.PAPER_BROWSER_ENROLLMENT_DISPOSABLE !== 'confirmed' ||
      typeof username !== 'string' || !/^claimtest-[a-z0-9]{8,24}$/u.test(username) ||
      webId !== 'https://paper.example.org/' + username || typeof signupReservationId !== 'string') deny();
  let ready;
  try {
    ready = await broker.call('auth.account.providerOwnerReady', { signupReservationId, username, webId },
      { meta: {}, timeout: 3000, retries: 0 });
  } catch { deny(); }
  if (ready !== true) deny();
}

module.exports = function AccountEnrollmentMiddleware() {
  // Capture the production boundary once at construction. Never let
  // runtime environment mutation, broker-call metadata or action params
  // reopen an inherited generic database write route.
  const closedRawAccountWrites = process.env.NODE_ENV === 'production';
  return {
    name: 'AccountEnrollment',
    localAction(next, action) {
      if (closedRawAccountWrites && RAW_DB_WRITES.has(action.name)) {
        return async function denyGenericAccountWrite() {
          throw new MoleculerError('Unscoped raw account mutation is unavailable',
            403, 'ACCOUNT_RAW_DATABASE_MUTATION_DENIED',
            { retryable: false });
        };
      }
      if (ENROLLED_MUTATIONS.has(action.name)) {
        return async function fencedMutation(ctx) {
          await assertNoEnrolledMutation(ctx, action.name);
          return next(ctx);
        };
      }
      if (action.name === 'auth.account.verify') {
        return async function verify(ctx) {
          const account = await next(ctx);
          await assertOwnerAccess(ctx.broker, account);
          return account;
        };
      }
      if (action.name === 'auth.jwt.generateServerSignedToken') {
        return async function mint(ctx) {
          const webId = ctx.params?.payload?.webId;
          if (typeof webId !== 'string' || !webId) deny();
          // Fresh call: HTTP routing metadata cannot select another dataset.
          // No cache, retry, or fallback on a failed account lookup.
          let account;
          try {
            account = await ctx.broker.call('auth.account.findByWebId',
              { webId }, { meta: {}, timeout: 5000, retries: 0 });
          } catch {
            deny();
          }
          if (!account || account.webId !== webId) deny();
          await assertOwnerAccess(ctx.broker, account);
          return next(ctx);
        };
      }
      if (action.name === 'auth.jwt.verifyServerSignedToken') {
        return async function verifyToken(ctx) {
          const payload = await next(ctx);
          if (!payload) return payload;
          const webId = payload.webId;
          if (typeof webId !== 'string' || !webId) return false;
          try {
            const account = await ctx.broker.call('auth.account.findByWebId',
              { webId }, { meta: {}, timeout: 5000, retries: 0 });
            if (!account || account.webId !== webId) return false;
            await assertOwnerAccess(ctx.broker, account);
            return payload;
          } catch {
            return false;
          }
        };
      }
      return next;
    }
  };
};

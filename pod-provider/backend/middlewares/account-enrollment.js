'use strict';

const { Errors: { MoleculerError } } = require('moleculer');

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
  return {
    name: 'AccountEnrollment',
    localAction(next, action) {
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

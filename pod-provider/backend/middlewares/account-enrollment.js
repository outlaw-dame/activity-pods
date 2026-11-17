'use strict';

const { Errors: { MoleculerError } } = require('moleculer');

function deny() {
  throw new MoleculerError('Account enrollment is incomplete',
    403, 'ACCOUNT_ENROLLMENT_INCOMPLETE', { retryable: false });
}

function assertNotEnrolling(account) {
  // Presence, not truthiness: malformed, empty and null markers also deny.
  // This field is stored in the private auth-account dataset, not the WebID.
  if (account && Object.prototype.hasOwnProperty.call(account, 'signupReservationId')) deny();
}

module.exports = function AccountEnrollmentMiddleware() {
  return {
    name: 'AccountEnrollment',
    localAction(next, action) {
      if (action.name === 'auth.account.verify') {
        return async function verify(ctx) {
          const account = await next(ctx);
          assertNotEnrolling(account);
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
          assertNotEnrolling(account);
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
            assertNotEnrolling(account);
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

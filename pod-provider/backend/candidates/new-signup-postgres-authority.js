'use strict';
const { createAccountPostgresLifecycleCandidate } =
  require('./account-postgres-lifecycle');
const { verifyNewSignupSolidAuthority } =
  require('./solid-new-signup-proof');

/**
 * Nonactivated bridge from the operational PostgreSQL ledger to the
 * authoritative SemApps account + Jena/WebID services.
 *
 * ONLY new signups: do not discover, import, migrate, or repair existing
 * accounts. The call argument must be a trusted INTERNAL Moleculer ctx.call
 * scoped to the current Pod provider, not an arbitrary client callback.
 *
 * No full account scan, private RDF copying, additional state map, or
 * distributed lock: username equality uses SemApps' existing lookup.
 */
function createNewSignupPostgresAuthority({
  pool, call, resolveTrustedKeyDid, verifyGenesis, verifyPds
} = {}) {
  if (typeof call !== 'function') {
    throw new TypeError('NEW_SIGNUP_INTERNAL_AUTHORITY_CALL_REQUIRED');
  }
  return createAccountPostgresLifecycleCandidate({
    pool,
    resolveTrustedKeyDid,
    verifyGenesis,
    verifyPds,
    assertFreshAccount: async ({ usernameKey }) => {
      if (typeof usernameKey !== 'string' || !usernameKey ||
          usernameKey.length > 128) return false;
      const existing = await call('auth.account.findByUsername', {
        username: usernameKey
      });
      // Undefined/null means absence. Any non-null result must NOT be
      // adopted into the new account ledger.
      return existing == null;
    },
    verifySolid: args => verifyNewSignupSolidAuthority({ call, ...args })
  });
}

module.exports = { createNewSignupPostgresAuthority };

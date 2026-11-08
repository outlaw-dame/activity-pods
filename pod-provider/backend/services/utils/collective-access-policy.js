'use strict';

/**
 * Live, fail-closed SAI consent check for a provider-authoritative Group action.
 * This is a second enforcement gate, NOT a grant issuer or client authenticator.
 * A caller must ALSO supply a verified, operation-bound grant from a trusted
 * issuer, and no app name or ctx.meta value is trusted here.
 */
const { MoleculerError } = require('moleculer').Errors;

const RIGHTS = Object.freeze({
  reserve: 'apods:CreateGroup',
  read: 'apods:ReadGroups'
});

function deny(code) {
  throw new MoleculerError(code, 403, code);
}

function acceptedRights(value) {
  if (!Array.isArray(value)) return [];
  return value.filter(v => typeof v === 'string');
}

/**
 * Approved apps are explicit provider policy (not approval merely because an
 * app exists). The operator may configure multiple independent applications.
 */
function parseApprovedApps(value) {
  if (!value) return [];
  const entries = String(value).split(',').map(v => v.trim()).filter(Boolean);
  if (entries.some(v => {
    try {
      const url = new URL(v);
      return url.protocol !== 'https:' || url.href !== v || url.username ||
        url.password || url.search || url.hash;
    } catch {
      return true;
    }
  })) {
    throw new Error('PROVIDER_COLLECTIVES_APPROVED_APPS contains an invalid application URI');
  }
  return [...new Set(entries)];
}

async function assertLiveCollectiveConsent(ctx, { principal, app, operation, approvedApps }) {
  if (!Object.hasOwn(RIGHTS, operation)) deny('COLLECTIVE_INVALID_CONSENT_OPERATION');
  if (!Array.isArray(approvedApps) || !approvedApps.includes(app)) {
    deny('COLLECTIVE_APP_NOT_APPROVED');
  }

  // Do not downgrade missing services, unavailable authoritative storage, or
  // authorization failures into "allowed" or cached grants.
  const account = await ctx.call('auth.account.findByWebId', { webId: principal });
  if (!account || account.webId !== principal) deny('COLLECTIVE_USER_NOT_FOUND');
  const registered = await ctx.call('app-registrations.isRegistered', {
    appUri: app, podOwner: principal
  });
  if (registered !== true) deny('COLLECTIVE_APP_NOT_REGISTERED');

  const rights = acceptedRights(await ctx.call('access-authorizations.getSpecialRights', {
    appUri: app, podOwner: principal
  }));
  if (!rights.includes(RIGHTS[operation])) {
    deny('COLLECTIVE_APP_CONSENT_MISSING');
  }
  return true;
}

module.exports = { RIGHTS, parseApprovedApps, assertLiveCollectiveConsent };

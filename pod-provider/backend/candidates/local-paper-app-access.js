'use strict';

const { createLocalSignupApp } = require('./local-signup-app');
const { NS } = require('../services/utils/collective-special-rights');
const app = createLocalSignupApp();
const ownerPattern = /^https:\/\/paper\.example\.org\/(claimtest-[a-z0-9]{8,24})$/u;

function queryForOwner(owner) {
  // Both the registration and the grant must remain attached to the owner's
  // native SAI records in the same Jena snapshot. Optional rights do not
  // participate in admission. Their feature handlers check them separately.
  const required = app.requiredRights.map(right => '<' + NS + right.slice('apods:'.length) + '>').join(', ');
  return `PREFIX i: <http://www.w3.org/ns/solid/interop#>
    PREFIX apods: <http://activitypods.org/ns/core#>
    ASK {
      <${owner}> i:hasRegistrySet/i:hasAgentRegistry ?registry .
      ?registry i:hasApplicationRegistration ?registration .
      ?registration a i:ApplicationRegistration ; i:registeredBy <${owner}> ;
        i:registeredAgent <${app.appUri}> ; i:hasAccessGrant ?grant .
      ?grant a i:AccessGrant ; i:grantedBy <${owner}> ; i:grantee <${app.appUri}> ;
        i:hasAccessNeedGroup <${app.groupUri}> ; apods:hasSpecialRights ${required} .
      FILTER NOT EXISTS { ?registration i:registeredBy ?other FILTER (?other != <${owner}>) }
      FILTER NOT EXISTS { ?registration i:registeredAgent ?other FILTER (?other != <${app.appUri}>) }
      FILTER NOT EXISTS { ?grant i:grantedBy ?other FILTER (?other != <${owner}>) }
      FILTER NOT EXISTS { ?grant i:grantee ?other FILTER (?other != <${app.appUri}>) }
    }`;
}

async function paperAppAccess(broker, owner, clientId, issuer) {
  if (clientId !== app.appUri) return true;
  // Other providers can host the same test client. Only the configured local
  // Paper runtime owns this policy and must reject an unexpected issuer.
  if (issuer !== 'https://paper.example.org/') return !process.env.PAPER_LOCAL_BROWSER_CONFIG;
  const match = typeof owner === 'string' && owner.match(ownerPattern);
  if (!match || process.env.NODE_ENV !== 'test' || !process.env.PAPER_LOCAL_BROWSER_CONFIG ||
      process.env.PAPER_BROWSER_ENROLLMENT_DISPOSABLE !== 'confirmed') return false;
  try {
    return true === await broker.call('triplestore.query', {
      query: queryForOwner(owner), dataset: match[1], webId: owner
    }, { meta: {}, timeout: 3000, retries: 0 });
  } catch { return false; }
}

// oidc-provider may reuse an existing browser session without another login
// interaction. Enforce current SAI consent at both account-claims issuance and
// that session's existing-grant admission; neither path caches a permission.
function installPaperOidcAdmission(config, { broker, issuer, AccessDenied }) {
  if (!config || typeof config.findAccount !== 'function' ||
      typeof config.loadExistingGrant !== 'function' || typeof AccessDenied !== 'function') {
    throw new TypeError('Invalid OIDC admission integration');
  }
  const requireAccess = async (owner, clientId) => {
    if (!await paperAppAccess(broker, owner, clientId, issuer)) {
      throw new AccessDenied('The owner has not granted the required application access');
    }
  };
  const findAccount = config.findAccount;
  const loadExistingGrant = config.loadExistingGrant;
  config.findAccount = async (ctx, owner, token) => {
    await requireAccess(owner, ctx.oidc.client?.clientId ?? token?.clientId);
    return findAccount(ctx, owner, token);
  };
  config.loadExistingGrant = async ctx => {
    await requireAccess(ctx.oidc.session?.accountId, ctx.oidc.client?.clientId);
    return loadExistingGrant(ctx);
  };
}

module.exports = { paperAppAccess, installPaperOidcAdmission };

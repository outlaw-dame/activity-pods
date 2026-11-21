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
  if (clientId !== app.appUri || issuer !== 'https://paper.example.org/') return true;
  const match = typeof owner === 'string' && owner.match(ownerPattern);
  if (!match || process.env.NODE_ENV !== 'test' || !process.env.PAPER_LOCAL_BROWSER_CONFIG ||
      process.env.PAPER_BROWSER_ENROLLMENT_DISPOSABLE !== 'confirmed') return false;
  try {
    return true === await broker.call('triplestore.query', {
      query: queryForOwner(owner), dataset: match[1], webId: owner
    }, { meta: {}, timeout: 3000, retries: 0 });
  } catch { return false; }
}

module.exports = { paperAppAccess };

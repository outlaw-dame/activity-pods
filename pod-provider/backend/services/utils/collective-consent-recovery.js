'use strict';

// Offline, operator-only reset of abandoned SAI mutation markers. This module
// MUST NOT be exposed as an HTTP or Moleculer action. Administrators must first
// stop *all* Pod provider writers and keep the G1 release fuse closed.
const crypto = require('node:crypto');
const { consentSubject } = require('../collective-consent-fence.service');

const NS = 'http://activitypods.org/ns/core#';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function revision(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) {
    throw new TypeError('Expected a positive, safe consent revision');
  }
  return value;
}
function validateRequest({ principal, app, expectedRevision, nonce }) {
  const subject = consentSubject(principal, app);
  const current = revision(expectedRevision);
  if (typeof nonce !== 'string' || !UUID.test(nonce)) {
    throw new TypeError('A unique random v4 recovery nonce is required');
  }
  return { subject, current, nonce };
}
function queryState(principal, app) {
  const subject = consentSubject(principal, app);
  return 'PREFIX apods: <' + NS + '>\n' +
    'SELECT ?revision ?status ?pending ?recovery WHERE { ' + subject +
    ' apods:collectiveConsentRevision ?revision ; apods:collectiveConsentStatus ?status . ' +
    'OPTIONAL { ' + subject + ' apods:collectivePendingMutation ?pending . } ' +
    'OPTIONAL { ' + subject + ' apods:collectiveRecoveryNonce ?recovery . } }';
}
function resetQuery(input) {
  const { subject: s, current, nonce } = validateRequest(input);
  // beginQuery writes xsd:integer revision literals, not RDF strings.
  // SPARQL numeric syntax is required for a real CAS match on Fuseki.
  const from = String(current);
  const to = String(current + 1);
  const marker = JSON.stringify(nonce);
  return 'PREFIX apods: <' + NS + '>\n' +
    'DELETE { ' + s + ' apods:collectivePendingMutation ?pending ; ' +
    'apods:collectiveConsentRevision ' + from + ' . }\n' +
    'INSERT { ' + s + ' apods:collectiveConsentRevision ' + to + ' ; ' +
    'apods:collectiveRecoveryNonce ' + marker + ' . }\n' +
    'WHERE { ' + s + ' apods:collectiveConsentStatus "blocked" ; ' +
    'apods:collectiveConsentRevision ' + from + ' ; ' +
    'apods:collectivePendingMutation ?pending . ' +
    'FILTER NOT EXISTS { ' + s + ' apods:collectiveRecoveryNonce ' + marker + ' . } }';
}
function freshNonce() {
  return crypto.randomUUID();
}

module.exports = { queryState, resetQuery, validateRequest, freshNonce };

/**
 * NON-ACTIVATED: per-Pod atomic SAI-consent fence for protected repository RDF.
 *
 * All mutations and reads target the SAME per-user Jena dataset/graph as the
 * canonical identity-binding resource. The external SAI lifecycle must call
 * beginRevocation BEFORE deleting/updating a grant. Without full hook coverage
 * this remains a disposable integration proof, not a permission authority.
 */
'use strict';
const crypto = require('node:crypto');

const NS = 'http://activitypods.org/ns/core#';
const MAX_EPOCH = 9223372036854775807n;
const UINT = /^[1-9][0-9]{0,18}$/u;

function fail(message) {
  const e = new Error(message);
  e.code = 'POD_CONSENT_INVALID';
  throw e;
}
function safeIri(raw, { httpsOnly = false } = {}) {
  if (typeof raw !== 'string' || !raw || raw.length > 2048 ||
      /[\u0000-\u0020\u007f<>"{}\\]/u.test(raw)) fail('Invalid protected RDF IRI');
  let url;
  try { url = new URL(raw); } catch { fail('Invalid protected RDF IRI'); }
  if ((httpsOnly && url.protocol !== 'https:') ||
      (!httpsOnly && !['https:', 'urn:'].includes(url.protocol)) ||
      (url.protocol === 'https:' && (url.username || url.password || url.href !== raw))) {
    fail('Untrusted or noncanonical protected RDF IRI');
  }
  return '<' + raw + '>';
}
function safeEpoch(raw) {
  if (typeof raw !== 'string' || !UINT.test(raw) || BigInt(raw) > MAX_EPOCH) {
    fail('Invalid SAI consent revision');
  }
  return raw;
}
function consentSubject(accountId, appUri) {
  safeIri(accountId, { httpsOnly: true });
  safeIri(appUri, { httpsOnly: true });
  const digest = crypto.createHash('sha256')
    .update(JSON.stringify([accountId, appUri, 'atproto.repository.projection.v1']))
    .digest('hex');
  return 'urn:apods:atproto:consent:' + digest;
}
function graphWrap(graphUri, statement) {
  return graphUri ? 'GRAPH ' + safeIri(graphUri) + ' { ' + statement + ' }' : statement;
}
function prefix() {
  return 'PREFIX apods: <' + NS + '> PREFIX xsd: <http://www.w3.org/2001/XMLSchema#> ';
}
function consentGuard({ subjectUri, grantUri, revision, graphUri = null }) {
  const subject = safeIri(subjectUri);
  const grant = safeIri(grantUri, { httpsOnly: true });
  const epoch = safeEpoch(revision);
  const identity = subject + ' apods:repoConsentStatus "active" ; ' +
    'apods:repoConsentRevision "' + epoch + '"^^xsd:integer ; ' +
    'apods:repoConsentGrant ' + grant + ' . ';
  // A matching grant is insufficient when a conflicting status, grant or
  // revision also exists. Treat ambiguous RDF as denied.
  const unambiguous = [
    ['repoConsentStatus', '"active"'],
    ['repoConsentRevision', '"' + epoch + '"^^xsd:integer'],
    ['repoConsentGrant', grant]
  ].map(([field, expected], i) =>
    'FILTER NOT EXISTS { ' + subject + ' apods:' + field + ' ?other' + i +
    ' . FILTER(STR(?other' + i + ') != STR(' + expected + ')) } '
  ).join('');
  return 'FILTER EXISTS { ' + graphWrap(graphUri, identity + unambiguous) + ' } ';
}
function readConsentQuery({ subjectUri, graphUri = null }) {
  const statement = safeIri(subjectUri) +
    ' apods:repoConsentStatus ?status ; apods:repoConsentRevision ?revision ; ' +
    'apods:repoConsentGrant ?grant . ';
  return prefix() + 'SELECT ?status ?revision ?grant WHERE { ' +
    graphWrap(graphUri, statement) + ' } LIMIT 3';
}
function bootstrapConsentQuery({ subjectUri, grantUri, graphUri = null }) {
  const s = safeIri(subjectUri);
  const g = safeIri(grantUri, { httpsOnly: true });
  const body = s + ' apods:repoConsentStatus "active" ; ' +
    'apods:repoConsentRevision "1"^^xsd:integer ; apods:repoConsentGrant ' + g + ' . ';
  const guard = 'FILTER NOT EXISTS { ' + s + ' ?anyPredicate ?anyObject . }';
  return prefix() + 'INSERT { ' + graphWrap(graphUri, body) +
    ' } WHERE { ' + graphWrap(graphUri, guard) + ' }';
}
function beginRevocationQuery({ subjectUri, grantUri, revision, graphUri = null }) {
  const s = safeIri(subjectUri), g = safeIri(grantUri, { httpsOnly: true });
  const n = safeEpoch(revision);
  if (BigInt(n) === MAX_EPOCH) fail('Consent epoch exhausted');
  const from = s + ' apods:repoConsentStatus "active" ; ' +
    'apods:repoConsentRevision "' + n + '"^^xsd:integer ; apods:repoConsentGrant ' + g + ' . ';
  const to = s + ' apods:repoConsentStatus "blocked" ; ' +
    'apods:repoConsentRevision "' + String(BigInt(n) + 1n) + '"^^xsd:integer ; ' +
    'apods:repoConsentGrant ' + g + ' . ';
  // One conditional Jena transaction blocks any projection begun after the
  // revocation's commit. No attempt is made to "undo" a completed projection;
  // readiness still requires current active consent.
  return prefix() + 'DELETE { ' + graphWrap(graphUri, from) + ' } ' +
    'INSERT { ' + graphWrap(graphUri, to) + ' } WHERE { ' +
    graphWrap(graphUri, from + consentGuard({ subjectUri, grantUri, revision, graphUri })) + ' }';
}
function parseConsentRows(rows, { grantUri }) {
  if (!Array.isArray(rows) || rows.length !== 1) {
    const e = new Error('Missing or ambiguous protected SAI consent');
    e.code = 'POD_CONSENT_NOT_ACTIVE';
    throw e;
  }
  const row = rows[0];
  const get = k => typeof row[k]?.value === 'string' ? row[k].value : row[k];
  const status = get('status'), revision = get('revision'), grant = get('grant');
  if (!['active', 'blocked'].includes(status) || grant !== grantUri) {
    const e = new Error('Protected SAI grant differs from consent pointer');
    e.code = 'POD_CONSENT_NOT_ACTIVE';
    throw e;
  }
  safeEpoch(String(revision));
  return Object.freeze({ status, revision: String(revision), grantUri: grant });
}

module.exports = { safeIri, safeEpoch, consentSubject, consentGuard, readConsentQuery, bootstrapConsentQuery, beginRevocationQuery, parseConsentRows };

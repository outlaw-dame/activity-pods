'use strict';

/**
 * Provider-owned G2 membership RDF templates. The G1 settings TDB2 dataset
 * remains authoritative; this code does not create Group Pods or AP actors.
 * No global account scan, OFFSET, remote HTTP, Redis or sidecar calls.
 *
 * The caller must authenticate the owner and enforce the signed internal
 * operation capability. These templates ALSO bind the persisted G1 owner and
 * reservation in the SAME atomic settings-dataset transaction.
 */
const crypto = require('node:crypto');
const NS = 'http://activitypods.org/ns/core#';
const PREFIX = 'urn:apods:collective:';
const MEMBER_PREFIX = 'urn:apods:collective-member:';
const ID = /^cg_[0-9a-f]{32}$/u;
const ROLES = new Set(['member', 'moderator', 'admin']);
const STATUSES = new Set(['active', 'banned', 'left']);
const MAX_LIMIT = 1000;

function fail(message) { throw new TypeError('Invalid Group membership operation: ' + message); }
function validateId(id) {
  if (typeof id !== 'string' || !ID.test(id)) fail('invalid canonical Group ID');
  return id;
}
function validateActor(value) {
  if (typeof value !== 'string' || value.length > 2048 ||
      /[\u0000-\u0020\u007f\\]/u.test(value)) fail('invalid actor URI');
  let u;
  try { u = new URL(value); } catch { fail('invalid actor URI'); }
  if (u.protocol !== 'https:' || u.href !== value || u.username ||
      u.password || u.search) fail('invalid actor URI');
  return value;
}
function literal(value) { return JSON.stringify(value); }
function groupSubject(id) { return '<' + PREFIX + validateId(id) + '>'; }
// SemApps AuthAccount and Group revision live in the SAME Fuseki settings
// dataset, so a membership update must join current account authority in the
// same atomic conditional write rather than trust an earlier service lookup.
function activeOwnerCondition(owner) {
  const webId = literal(validateActor(owner));
  const accountNs = 'http://semapps.org/ns/core#';
  const account = '?groupMembershipOwnerAccount';
  return account + ' a <' + accountNs + 'AuthAccount> ; ' +
    '<' + accountNs + 'webId> ' + webId + ' . ' +
    'FILTER NOT EXISTS { ' + account + ' <' + accountNs + 'deletedAt> ?ownerDeletedAt . } ' +
    'FILTER NOT EXISTS { ' + account + ' <' + accountNs + 'suspendedAt> ?ownerSuspendedAt . } ' +
    'FILTER NOT EXISTS { ' + account + ' <' + accountNs + 'disabled> ?ownerDisabled . ' +
      'FILTER(LCASE(STR(?ownerDisabled)) = "true") } ' +
    'FILTER NOT EXISTS { ' + account + ' <' + accountNs + 'deleted> ?ownerDeletedFlag . ' +
      'FILTER(LCASE(STR(?ownerDeletedFlag)) = "true") } ' +
    'FILTER NOT EXISTS { ' + account + ' <' + accountNs + 'status> ?ownerStatus . ' +
      'FILTER(LCASE(STR(?ownerStatus)) IN ("suspended", "deleted", "disabled")) } ' +
    'FILTER NOT EXISTS { ?otherOwnerAccount a <' + accountNs + 'AuthAccount> ; ' +
      '<' + accountNs + 'webId> ' + webId +
      ' . FILTER(?otherOwnerAccount != ' + account + ') } ';
}
function memberSubject(id, actorUri) {
  const seed = JSON.stringify([validateId(id), validateActor(actorUri)]);
  return '<' + MEMBER_PREFIX + crypto.createHash('sha256').update(seed).digest('hex') + '>';
}
function initializeQuery({ groupId, owner }) {
  const g = groupSubject(groupId);
  const ownerUri = validateActor(owner);
  const m = memberSubject(groupId, ownerUri);
  return 'PREFIX apods: <' + NS + '>\nPREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n' +
    'INSERT { ' + g + ' apods:collectiveMembershipEpoch "1"^^xsd:integer . ' +
      m + ' a apods:CollectiveMembershipV1 ; ' +
      'apods:collectiveMemberGroup ' + literal(groupId) + ' ; ' +
      'apods:collectiveMemberActor ' + literal(ownerUri) + ' ; ' +
      'apods:collectiveMemberRole "owner" ; ' +
      'apods:collectiveMemberStatus "active" . } WHERE { ' +
      g + ' a apods:CollectiveReservationV1 ; ' +
      'apods:collectiveOwner ' + literal(ownerUri) + ' . ' +
      activeOwnerCondition(ownerUri) +
      'FILTER NOT EXISTS { ' + g + ' apods:collectiveMembershipEpoch ?existing . } ' +
      'FILTER NOT EXISTS { ' + m + ' ?existingMemberProperty ?existingMemberValue . } }';
}
function mutateQuery({ groupId, owner, member, role, status, expectedEpoch }) {
  const g = groupSubject(groupId);
  const memberUri = validateActor(member);
  const ownerUri = validateActor(owner);
  if (memberUri === ownerUri) fail('cannot modify Group owner membership');
  if (!ROLES.has(role) || !STATUSES.has(status)) fail('invalid role/status');
  if (!Number.isSafeInteger(expectedEpoch) || expectedEpoch < 1) fail('invalid expected epoch');
  const m = memberSubject(groupId, memberUri);
  return 'PREFIX apods: <' + NS + '>\nPREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n' +
    'DELETE { ' + g + ' apods:collectiveMembershipEpoch ?oldEpoch . ' +
      m + ' apods:collectiveMemberRole ?oldRole ; ' +
      'apods:collectiveMemberStatus ?oldStatus . }\n' +
    'INSERT { ' + g + ' apods:collectiveMembershipEpoch ?nextEpoch . ' +
      m + ' a apods:CollectiveMembershipV1 ; ' +
      'apods:collectiveMemberGroup ' + literal(groupId) + ' ; ' +
      'apods:collectiveMemberActor ' + literal(memberUri) + ' ; ' +
      'apods:collectiveMemberRole ' + literal(role) + ' ; ' +
      'apods:collectiveMemberStatus ' + literal(status) + ' . }\n' +
    'WHERE { ' + g + ' a apods:CollectiveReservationV1 ; ' +
      'apods:collectiveOwner ' + literal(ownerUri) + ' ; ' +
      'apods:collectiveMembershipEpoch ?oldEpoch . ' +
      activeOwnerCondition(ownerUri) +
      'FILTER(xsd:integer(?oldEpoch) = ' + expectedEpoch + ') ' +
      'BIND(xsd:integer(?oldEpoch) + 1 AS ?nextEpoch) ' +
      'OPTIONAL { ' + m + ' apods:collectiveMemberRole ?oldRole . } ' +
      'OPTIONAL { ' + m + ' apods:collectiveMemberStatus ?oldStatus . } ' +
      'FILTER NOT EXISTS { ' + m + ' apods:collectiveMemberActor ?otherActor . ' +
      'FILTER(?otherActor != ' + literal(memberUri) + ') } ' +
      'FILTER NOT EXISTS { ' + m + ' apods:collectiveMemberGroup ?otherGroup . ' +
      'FILTER(?otherGroup != ' + literal(groupId) + ') } }';
}
function readEpochQuery({ groupId, owner }) {
  const g = groupSubject(groupId);
  return 'PREFIX apods: <' + NS + '>\n' +
    'SELECT ?epoch WHERE { ' + g + ' a apods:CollectiveReservationV1 ; ' +
    'apods:collectiveOwner ' + literal(validateActor(owner)) + ' ; ' +
    'apods:collectiveMembershipEpoch ?epoch . ' +
    activeOwnerCondition(owner) + '} LIMIT 2';
}
function listQuery({ groupId, owner, cursor = null, limit = 100 }) {
  const g = groupSubject(groupId);
  validateActor(owner);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
    fail('invalid keyset page limit');
  }
  if (cursor !== null) validateActor(cursor);
  return 'PREFIX apods: <' + NS + '>\n' +
    'SELECT ?actor ?role ?epoch WHERE { ' + g + ' a apods:CollectiveReservationV1 ; ' +
      'apods:collectiveOwner ' + literal(owner) + ' ; ' +
      'apods:collectiveMembershipEpoch ?epoch . ' +
      activeOwnerCondition(owner) +
      '?membership a apods:CollectiveMembershipV1 ; ' +
      'apods:collectiveMemberGroup ' + literal(groupId) + ' ; ' +
      'apods:collectiveMemberActor ?actor ; apods:collectiveMemberRole ?role ; ' +
      'apods:collectiveMemberStatus "active" . ' +
      (cursor === null ? '' : 'FILTER(STR(?actor) > ' + literal(cursor) + ') ') +
    '} ORDER BY STR(?actor) LIMIT ' + (limit + 1);
}
module.exports = Object.freeze({
  MAX_LIMIT, ROLES, STATUSES,
  validateId, validateActor, groupSubject, memberSubject,
  initializeQuery, mutateQuery, readEpochQuery, listQuery
});

'use strict';

/**
 * Release-disabled, provider-authorized and bounded revision delta snapshot.
 *
 * Reads canonical membership and durable changed-member pointers in the
 * SAME TDB2 settings query snapshot, using only the indexed Group subject.
 * This is not an HTTP API, Group authority, or executable delivery plan.
 */
const rdf = require('./collective-membership-rdf');
const MAX_DELTA = rdf.MAX_INDEX_DELTA;
const NS = 'http://activitypods.org/ns/core#';
function fail(code) { throw new TypeError(code); }
function value(row, name) {
  const v = row?.[name];
  return typeof v === 'string' ? v : v?.value;
}
function exactEpoch(valueString) {
  if (typeof valueString !== 'string' || !/^[0-9]+$/u.test(valueString)) {
    fail('INDEX_DELTA_INVALID_REVISION');
  }
  const n = Number(valueString);
  if (!Number.isSafeInteger(n) || n < 0) fail('INDEX_DELTA_INVALID_REVISION');
  return n;
}
function readDeltaSnapshotQuery({ groupId, owner, app }) {
  const g = rdf.groupSubject(groupId);
  const base = rdf.readEpochQuery({ groupId, owner, app });
  const replaced = base.replace('SELECT ?epoch WHERE {',
    'SELECT ?epoch ?baseEpoch ?deltaCount ?member ?actor ?role ?status WHERE {');
  if (replaced === base || !replaced.endsWith('} LIMIT 2')) {
    fail('INDEX_DELTA_UNEXPECTED_AUTHORITY_QUERY');
  }
  return replaced.replace('} LIMIT 2',
    g + ' apods:collectiveIndexedMembershipEpoch ?baseEpoch ; ' +
    'apods:collectiveIndexDeltaCount ?deltaCount . ' +
    'FILTER(xsd:integer(?baseEpoch) <= xsd:integer(?epoch)) ' +
    'OPTIONAL { ' + g + ' apods:collectiveIndexChangedMember ?member . ' +
      '?member a apods:CollectiveMembershipV1 ; ' +
      'apods:collectiveMemberGroup ' + JSON.stringify(groupId) + ' ; ' +
      'apods:collectiveMemberActor ?actor ; ' +
      'apods:collectiveMemberRole ?role ; ' +
      'apods:collectiveMemberStatus ?status ; ' +
      'apods:collectiveChangedSinceIndex true . ' +
    '} } LIMIT ' + (MAX_DELTA + 2))
    .replace('PREFIX apods: <' + NS + '>',
      'PREFIX apods: <' + NS + '> PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>');
}
function decodeDeltaSnapshot(rows, { groupId, owner, maxDelta = MAX_DELTA }) {
  rdf.validateId(groupId);
  const ownerUri = rdf.validateActor(owner);
  if (!Number.isSafeInteger(maxDelta) || maxDelta < 0 || maxDelta > MAX_DELTA ||
      !Array.isArray(rows) || rows.length < 1 || rows.length > maxDelta + 1) {
    fail('INDEX_DELTA_UNVERIFIED');
  }
  const first = rows[0];
  const epoch = exactEpoch(value(first, 'epoch'));
  const baseEpoch = exactEpoch(value(first, 'baseEpoch'));
  const count = exactEpoch(value(first, 'deltaCount'));
  if (epoch < 1 || baseEpoch < 1 || baseEpoch > epoch || count > maxDelta ||
      rows.some(row => value(row, 'epoch') !== String(epoch) ||
        value(row, 'baseEpoch') !== String(baseEpoch) ||
        value(row, 'deltaCount') !== String(count))) {
    fail('INDEX_DELTA_UNVERIFIED');
  }
  const changes = [];
  const seenActors = new Set();
  const seenSubjects = new Set();
  for (const row of rows) {
    const subject = value(row, 'member');
    if (subject === undefined) {
      if (rows.length !== 1 || count !== 0) fail('INDEX_DELTA_INCOMPLETE');
      continue;
    }
    const uri = rdf.validateActor(value(row, 'actor'));
    const role = value(row, 'role');
    const status = value(row, 'status');
    if (typeof subject !== 'string' ||
        !subject.startsWith('urn:apods:collective-member:') ||
        subject.length !== 96 ||
        uri === ownerUri || (role !== 'owner' && !rdf.ROLES.has(role)) ||
        !rdf.STATUSES.has(status) ||
        seenActors.has(uri) || seenSubjects.has(subject) ||
        subject !== rdf.memberSubject(groupId, uri).slice(1, -1)) {
      fail('INDEX_DELTA_CORRUPT');
    }
    seenActors.add(uri);
    seenSubjects.add(subject);
    changes.push(status === 'active'
      ? { actorUri: uri, kind: 'upsert', role }
      : { actorUri: uri, kind: 'remove' });
  }
  if (changes.length !== count) fail('INDEX_DELTA_INCOMPLETE');
  changes.sort((a, b) => a.actorUri < b.actorUri ? -1 : 1);
  return Object.freeze({
    groupId, baseRevision: baseEpoch, membershipRevision: epoch,
    deltaCount: count,
    changes: Object.freeze(changes.map(change => Object.freeze(change)))
  });
}
module.exports = Object.freeze({
  MAX_DELTA, readDeltaSnapshotQuery, decodeDeltaSnapshot
});

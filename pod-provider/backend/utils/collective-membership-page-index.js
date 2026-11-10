'use strict';

/**
 * G2 read-only, revision-fenced materialized membership pages.
 *
 * The authoritative membership/consent/account state is still the existing
 * ActivityPods TDB2 settings dataset. This is a candidate read projection,
 * NOT a second membership authority, public route, delivery queue, or writer.
 *
 * Publishing must only be done by a trusted, authenticated provider worker
 * after complete authoritative snapshot verification. Incomplete staging
 * records cannot be read: readers require an epoch-bound publish marker.
 */
const crypto = require('node:crypto');
const rdf = require('./collective-membership-rdf');

const PAGE_LIMIT = 100;
const MAX_PAGE_BYTES = 32768;
const NS = 'http://activitypods.org/ns/core#';
function reject(code) { throw new TypeError(code); }
function hash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}
function validateRevision(revision) {
  if (!Number.isSafeInteger(revision) || revision < 1) reject('INVALID_MEMBERSHIP_REVISION');
  return revision;
}
function pageSubject(groupId, revision, cursor) {
  rdf.validateId(groupId);
  validateRevision(revision);
  if (cursor !== null) rdf.validateActor(cursor);
  const key = hash(JSON.stringify([groupId, revision, cursor]));
  return '<urn:apods:collective-membership-index-page:' + key + '>';
}
function normalizeMembers(input) {
  if (!Array.isArray(input) || input.length === 0 || input.length > PAGE_LIMIT) {
    reject('INVALID_MEMBERSHIP_INDEX_PAGE_SIZE');
  }
  let previous = '';
  return input.map(item => {
    const actorUri = rdf.validateActor(item?.actorUri);
    if (actorUri <= previous) reject('INVALID_MEMBERSHIP_INDEX_ORDER');
    previous = actorUri;
    if (item.role !== 'owner' && !rdf.ROLES.has(item.role)) {
      reject('INVALID_MEMBERSHIP_INDEX_ROLE');
    }
    return { actorUri, role: item.role };
  });
}
function encodePage({ groupId, revision, cursor = null, members, hasMore }) {
  rdf.validateId(groupId);
  validateRevision(revision);
  if (cursor !== null) rdf.validateActor(cursor);
  const items = normalizeMembers(members);
  if (cursor !== null && items[0].actorUri <= cursor) reject('INVALID_MEMBERSHIP_INDEX_CURSOR');
  if (typeof hasMore !== 'boolean') reject('INVALID_MEMBERSHIP_INDEX_TERMINAL');
  const nextCursor = hasMore ? items[items.length - 1].actorUri : null;
  const payload = { version: 1, groupId, revision, cursor, members: items,
    hasMore, nextCursor };
  const json = JSON.stringify(payload);
  if (Buffer.byteLength(json, 'utf8') > MAX_PAGE_BYTES) reject('MEMBERSHIP_INDEX_PAGE_TOO_LARGE');
  return Object.freeze({ ...payload, json, digest: hash(json),
    subject: pageSubject(groupId, revision, cursor) });
}
function stagePageQuery(page) {
  if (!page || page.digest !== hash(page.json) ||
      page.subject !== pageSubject(page.groupId, page.revision, page.cursor)) {
    reject('INVALID_MEMBERSHIP_INDEX_STAGE');
  }
  // Only append immutable, unique revision/cursor page content. A conflicting
  // existing page is detected by a separate publisher verification step.
  return 'PREFIX apods: <' + NS + '> INSERT DATA { ' +
    page.subject + ' apods:collectiveIndexPageJson ' + JSON.stringify(page.json) +
    ' ; apods:collectiveIndexPageDigest ' + JSON.stringify(page.digest) + ' . }';
}
function readPageQuery({ groupId, owner, app, revision, cursor = null }) {
  const page = pageSubject(groupId, revision, cursor);
  const g = rdf.groupSubject(groupId);
  const base = rdf.readEpochQuery({ groupId, owner, app });
  const select = base.replace('SELECT ?epoch WHERE {',
    'SELECT ?epoch ?pageJson ?pageDigest WHERE {');
  if (select === base || !select.endsWith('} LIMIT 2')) reject('UNEXPECTED_AUTHORITY_TEMPLATE');
  return select.replace(/} LIMIT 2$/u,
    g + ' apods:collectiveIndexedMembershipEpoch ?epoch . ' +
    page + ' apods:collectiveIndexPageJson ?pageJson ; ' +
    'apods:collectiveIndexPageDigest ?pageDigest . } LIMIT 2');
}
function publishQuery({ groupId, owner, app, revision }) {
  validateRevision(revision);
  const g = rdf.groupSubject(groupId);
  const base = rdf.readEpochQuery({ groupId, owner, app });
  const whereStart = base.indexOf('WHERE {');
  if (whereStart < 0 || !base.endsWith('} LIMIT 2')) reject('UNEXPECTED_AUTHORITY_TEMPLATE');
  const authorizedWhere = base.slice(whereStart + 7, -9);
  // The epoch equality and account/SAI ledger authorization participate
  // in the same Fuseki TDB2 transaction as publishing the version pointer.
  return 'PREFIX apods: <' + NS + '> PREFIX xsd: <http://www.w3.org/2001/XMLSchema#> ' +
    'DELETE { ' + g + ' apods:collectiveIndexedMembershipEpoch ?oldIndexEpoch . } ' +
    'INSERT { ' + g + ' apods:collectiveIndexedMembershipEpoch ?epoch . } ' +
    'WHERE { ' + authorizedWhere +
    ' FILTER(xsd:integer(?epoch) = ' + revision + ') ' +
    'OPTIONAL { ' + g +
    ' apods:collectiveIndexedMembershipEpoch ?oldIndexEpoch . } }';
}
function value(row, key) {
  const v = row?.[key];
  return typeof v === 'string' ? v : v?.value;
}
function decodeRead(rows, { groupId, revision, cursor = null }) {
  if (!Array.isArray(rows) || rows.length !== 1 ||
      Number(value(rows[0], 'epoch')) !== revision) {
    reject('MEMBERSHIP_INDEX_UNAVAILABLE');
  }
  const json = value(rows[0], 'pageJson');
  const digest = value(rows[0], 'pageDigest');
  if (typeof json !== 'string' || Buffer.byteLength(json, 'utf8') > MAX_PAGE_BYTES ||
      typeof digest !== 'string' || digest !== hash(json)) {
    reject('MEMBERSHIP_INDEX_CORRUPT');
  }
  let page;
  try { page = JSON.parse(json); } catch { reject('MEMBERSHIP_INDEX_CORRUPT'); }
  try {
    const checked = encodePage(page);
    if (page.version !== 1 || page.groupId !== groupId ||
        page.revision !== revision || page.cursor !== cursor ||
        page.nextCursor !== checked.nextCursor ||
        page.hasMore !== checked.hasMore || checked.json !== json) {
      reject('MEMBERSHIP_INDEX_CORRUPT');
    }
    return Object.freeze({
      groupId, membershipRevision: revision, members: checked.members,
      nextCursor: checked.nextCursor, hasMore: checked.hasMore
    });
  } catch {
    reject('MEMBERSHIP_INDEX_CORRUPT');
  }
}
module.exports = Object.freeze({
  PAGE_LIMIT, MAX_PAGE_BYTES, pageSubject, encodePage, stagePageQuery,
  readPageQuery, publishQuery, decodeRead
});

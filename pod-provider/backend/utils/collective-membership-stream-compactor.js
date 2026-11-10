'use strict';

/**
 * G2 crash-safe-by-construction staging algorithm, NOT a live compactor.
 *
 * Streams an already verified immutable base from a trusted provider callback
 * and overlays a bounded canonical revision-delta. Buffers at most one 101
 * member lookahead plus twenty <=32KiB stage pages. It cannot publish, delete
 * old data, hold a lease, sign, enqueue federation, or grant membership.
 *
 * A separate authorized service must atomically verify+publish the complete
 * manifest at the same membership epoch, and implement bounded orphan GC,
 * restart checkpoints and hot-Group backpressure before production release.
 */
const crypto = require('node:crypto');
const rdf = require('./collective-membership-rdf');
const index = require('./collective-membership-page-index');
const { validateDelta } = require('./collective-membership-delta-merge');

/**
 * Existing base-index pages remain readable to a trusted compactor after
 * the canonical membership epoch advances, but ONLY while both the
 * expected current epoch and indexed base epoch match in one SAI/account
 * authorization-fenced TDB2 snapshot. This is never a public roster route.
 */
function readCompactionBaseQuery({ groupId, owner, app, baseRevision,
  membershipRevision, cursor = null }) {
  rdf.validateId(groupId);
  rdf.validateActor(owner);
  rdf.validateActor(app);
  if (!Number.isSafeInteger(baseRevision) || baseRevision < 1 ||
      !Number.isSafeInteger(membershipRevision) || membershipRevision < baseRevision) {
    fail('GROUP_COMPACTION_INVALID_REVISION');
  }
  const page = index.pageSubject(groupId, baseRevision, cursor);
  const g = rdf.groupSubject(groupId);
  const query = rdf.readEpochQuery({ groupId, owner, app });
  const modified = query.replace('SELECT ?epoch WHERE {',
    'SELECT ?epoch ?baseEpoch ?pageJson ?pageDigest WHERE {');
  if (query === modified || !modified.endsWith('} LIMIT 2')) {
    fail('GROUP_COMPACTION_AUTHORITY_TEMPLATE_DRIFT');
  }
  return modified.replace('} LIMIT 2',
    g + ' apods:collectiveIndexedMembershipEpoch ?baseEpoch . ' +
    'FILTER(xsd:integer(?epoch) = ' + membershipRevision + ') ' +
    'FILTER(xsd:integer(?baseEpoch) = ' + baseRevision + ') ' +
    page + ' apods:collectiveIndexPageJson ?pageJson ; ' +
    'apods:collectiveIndexPageDigest ?pageDigest . } LIMIT 2')
    .replace('PREFIX apods: <http://activitypods.org/ns/core#>',
      'PREFIX apods: <http://activitypods.org/ns/core#> ' +
      'PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>');
}
function decodeCompactionBase(rows, { groupId, baseRevision,
  membershipRevision, cursor = null }) {
  if (!Array.isArray(rows) || rows.length !== 1) {
    fail('GROUP_COMPACTION_BASE_UNAVAILABLE');
  }
  const get = (name) => typeof rows[0]?.[name] === 'string'
    ? rows[0][name] : rows[0]?.[name]?.value;
  if (!/^[0-9]+$/u.test(String(get('epoch'))) ||
      !/^[0-9]+$/u.test(String(get('baseEpoch'))) ||
      Number(get('epoch')) !== membershipRevision ||
      Number(get('baseEpoch')) !== baseRevision) {
    fail('GROUP_COMPACTION_BASE_UNAVAILABLE');
  }
  return index.decodeRead([{
    epoch: { value: String(baseRevision) },
    pageJson: { value: get('pageJson') },
    pageDigest: { value: get('pageDigest') }
  }], { groupId, revision: baseRevision, cursor });
}
const PAGE_WINDOW = index.PAGE_LIMIT + 1;
const STAGE_BATCH = 20;
const DEFAULT_MAX_BASE_PAGES = 2000;
const MAX_BASE_PAGES = 10000;

function fail(code) { throw new TypeError(code); }
function safeRevision(value) {
  return Number.isSafeInteger(value) && value >= 1;
}
function compare(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

/** Calls readBasePage once per actual persisted page, never per actor. */
async function* readVerifiedBase({ groupId, baseRevision, expectedBaseCount,
  readBasePage, maxBasePages }) {
  let cursor = null;
  let total = 0;
  let count = 0;
  let ownerCount = 0;
  while (true) {
    if (++count > maxBasePages) fail('GROUP_COMPACTION_BASE_PAGE_LIMIT');
    const data = await readBasePage({ groupId, revision: baseRevision, cursor });
    if (!data || data.groupId !== groupId ||
        data.membershipRevision !== baseRevision ||
        !Array.isArray(data.members) || data.members.length < 1 ||
        data.members.length > index.PAGE_LIMIT ||
        typeof data.hasMore !== 'boolean') fail('GROUP_COMPACTION_BASE_CORRUPT');
    let previous = cursor;
    for (const item of data.members) {
      const actorUri = rdf.validateActor(item?.actorUri);
      if ((previous !== null && actorUri <= previous) ||
          (item.role !== 'owner' && !rdf.ROLES.has(item.role))) {
        fail('GROUP_COMPACTION_BASE_CORRUPT');
      }
      previous = actorUri;
      if (item.role === 'owner' && ++ownerCount > 1) fail('GROUP_COMPACTION_OWNER_CORRUPT');
      if (++total > expectedBaseCount) fail('GROUP_COMPACTION_BASE_COUNT_MISMATCH');
      yield { actorUri, role: item.role };
    }
    const expectedCursor = data.hasMore ? previous : null;
    if (data.nextCursor !== expectedCursor) fail('GROUP_COMPACTION_BASE_CURSOR');
    if (!data.hasMore) break;
    cursor = expectedCursor;
  }
  if (total !== expectedBaseCount) fail('GROUP_COMPACTION_BASE_COUNT_MISMATCH');
  if (ownerCount !== 1) fail('GROUP_COMPACTION_OWNER_CORRUPT');
}

/** Ordered merge (O(total members + <=512 changes), bounded memory). */
async function* overlay(base, changes) {
  let changePosition = 0;
  let previousOutput = null;
  function* emitBefore(uri) {
    while (changePosition < changes.length &&
        changes[changePosition].actorUri < uri) {
      const change = changes[changePosition++];
      if (change.kind === 'upsert') yield {
        actorUri: change.actorUri, role: change.role
      };
    }
  }
  function* ensureUnique(items) {
    for (const item of items) {
      if (previousOutput !== null && item.actorUri <= previousOutput) {
        fail('GROUP_COMPACTION_MERGE_ORDER');
      }
      previousOutput = item.actorUri;
      yield item;
    }
  }
  for await (const entry of base) {
    for (const item of ensureUnique(emitBefore(entry.actorUri))) yield item;
    const changed = changes[changePosition];
    if (changed && changed.actorUri === entry.actorUri) {
      changePosition++;
      if (changed.kind === 'upsert') {
        for (const item of ensureUnique([{
          actorUri: changed.actorUri, role: changed.role
        }])) yield item;
      }
    } else {
      for (const item of ensureUnique([entry])) yield item;
    }
  }
  for (const item of ensureUnique(
    changes.slice(changePosition).filter(x => x.kind === 'upsert')
      .map(x => ({ actorUri: x.actorUri, role: x.role }))
  )) yield item;
}

/**
 * Stage complete immutable replacement pages using <=20 page calls.
 * A successful return is a manifest, NOT a claim of publication.
 */
async function stageCompactedMembership({
  groupId, owner, deltaSnapshot, expectedBaseCount,
  readBasePage, stagePages, maxBasePages = DEFAULT_MAX_BASE_PAGES,
}) {
  rdf.validateId(groupId);
  const ownerUri = rdf.validateActor(owner);
  const revision = deltaSnapshot?.membershipRevision;
  const baseRevision = deltaSnapshot?.baseRevision;
  if (!safeRevision(revision) || !safeRevision(baseRevision) ||
      revision < baseRevision || deltaSnapshot.groupId !== groupId ||
      !Number.isSafeInteger(expectedBaseCount) || expectedBaseCount < 1 ||
      !Number.isSafeInteger(maxBasePages) || maxBasePages < 1 ||
      maxBasePages > MAX_BASE_PAGES ||
      typeof readBasePage !== 'function' || typeof stagePages !== 'function' ||
      !Array.isArray(deltaSnapshot.changes) ||
      deltaSnapshot.changes.length > rdf.MAX_INDEX_DELTA ||
      deltaSnapshot.deltaCount !== deltaSnapshot.changes.length) {
    fail('GROUP_COMPACTION_INVALID_INPUT');
  }
  const changes = validateDelta(deltaSnapshot.changes);
  if (changes.some(c => c.actorUri === ownerUri)) fail('GROUP_COMPACTION_OWNER_IMMUTABLE');

  const base = readVerifiedBase({
    groupId, baseRevision, expectedBaseCount, readBasePage, maxBasePages,
  });
  const merged = overlay(base, changes);
  const buffer = [];
  let pages = [];
  let cursor = null;
  let outputCount = 0;
  let pageCount = 0;
  let ownerCount = 0;
  let digest = crypto.createHash('sha256').update(JSON.stringify([
    groupId, baseRevision, revision, expectedBaseCount, 'g2-compaction-v1'
  ])).digest('hex');

  async function persist(page) {
    outputCount += page.members.length;
    if (++pageCount > MAX_BASE_PAGES) fail('GROUP_COMPACTION_OUTPUT_PAGE_LIMIT');
    digest = crypto.createHash('sha256')
      .update(JSON.stringify([digest, page.subject, page.digest,
        page.members.length, page.nextCursor])).digest('hex');
    pages.push(page);
    if (pages.length === STAGE_BATCH) {
      await stagePages(Object.freeze(pages));
      pages = [];
    }
  }
  function take(sourceHasMore) {
    const { page, consumedCount } = index.packPage({
      groupId, revision, cursor, members: buffer,
      sourceHasMore,
    });
    buffer.splice(0, consumedCount);
    cursor = page.nextCursor;
    return page;
  }
  for await (const row of merged) {
    if (row.role === 'owner') {
      if (row.actorUri !== ownerUri || ++ownerCount > 1) fail('GROUP_COMPACTION_OWNER_CORRUPT');
    }
    buffer.push(row);
    if (buffer.length >= PAGE_WINDOW) await persist(take(true));
  }
  while (buffer.length > 0) {
    // Last page must carry hasMore=false; in-page byte pressure may split
    // more pages, each remaining page links to the next exact cursor.
    await persist(take(false));
  }
  if (pageCount === 0) fail('GROUP_COMPACTION_EMPTY');
  if (ownerCount !== 1) fail('GROUP_COMPACTION_OWNER_CORRUPT');
  if (pages.length) await stagePages(Object.freeze(pages));

  return Object.freeze({
    schema: 'paper.groups.compaction-manifest.v1',
    groupId, baseRevision, membershipRevision: revision,
    baseMemberCount: expectedBaseCount, memberCount: outputCount,
    pageCount, digest
  });
}
module.exports = Object.freeze({
  readCompactionBaseQuery, decodeCompactionBase,
  stageCompactedMembership, STAGE_BATCH, DEFAULT_MAX_BASE_PAGES,
  MAX_BASE_PAGES
});

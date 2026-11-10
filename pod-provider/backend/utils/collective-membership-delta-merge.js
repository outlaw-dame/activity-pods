'use strict';

/**
 * Bounded LSM-style delta merge for immutable indexed membership base pages.
 * This is an IO-free candidate for amortizing O(N) baseline construction,
 * not a second authority or a public route.
 *
 * A provider worker must atomically couple each delta to the canonical
 * membership epoch, authorize page access and fence compaction publication.
 */
const rdf = require('./collective-membership-rdf');
const PAGE_SIZE = 100;
const MAX_DELTA = 512;
const MAX_BASE_PAGES = 8;
function fail(code) { throw new TypeError(code); }
function validateDelta(changes) {
  if (!Array.isArray(changes) || changes.length > MAX_DELTA) {
    fail('INVALID_MEMBERSHIP_DELTA_SIZE');
  }
  let previous = '';
  return changes.map(change => {
    const actorUri = rdf.validateActor(change?.actorUri);
    if (actorUri <= previous) fail('INVALID_MEMBERSHIP_DELTA_ORDER');
    previous = actorUri;
    if (change.kind === 'remove') {
      if (change.role !== undefined) fail('INVALID_MEMBERSHIP_DELTA_REMOVE');
      return { actorUri, kind: 'remove' };
    }
    if (change.kind !== 'upsert' || (change.role !== 'owner' &&
        !rdf.ROLES.has(change.role))) fail('INVALID_MEMBERSHIP_DELTA_ROLE');
    return { actorUri, kind: 'upsert', role: change.role };
  });
}
function mergeWindow({ pages, delta, after = null, limit = PAGE_SIZE,
  baseRevision, currentRevision }) {
  if (!Number.isSafeInteger(baseRevision) || baseRevision < 1 ||
      !Number.isSafeInteger(currentRevision) || currentRevision < baseRevision ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > PAGE_SIZE ||
      !Array.isArray(pages) || pages.length < 1 || pages.length > MAX_BASE_PAGES) {
    fail('INVALID_MEMBERSHIP_MERGE_INPUT');
  }
  if (after !== null) rdf.validateActor(after);
  const changes = validateDelta(delta);
  const base = [];
  let prior = '';
  for (let i = 0; i < pages.length; i++) {
    const page = pages[i];
    if (page.revision !== baseRevision || !Array.isArray(page.members) ||
        page.members.length < 1 || page.members.length > PAGE_SIZE ||
        typeof page.hasMore !== 'boolean' ||
        (i > 0 && pages[i - 1].nextCursor !== page.cursor) ||
        (i > 0 && pages[i - 1].hasMore !== true)) {
      fail('INVALID_MEMBERSHIP_BASE_PAGE');
    }
    for (const entry of page.members) {
      const actorUri = rdf.validateActor(entry?.actorUri);
      if (actorUri <= prior || (entry.role !== 'owner' && !rdf.ROLES.has(entry.role))) {
        fail('INVALID_MEMBERSHIP_BASE_ORDER');
      }
      prior = actorUri;
      base.push({ actorUri, role: entry.role });
    }
    if (page.nextCursor !== (page.hasMore
      ? page.members[page.members.length - 1].actorUri : null)) {
      fail('INVALID_MEMBERSHIP_BASE_CURSOR');
    }
  }
  let i = 0, j = 0;
  const result = [];
  // Bound useful work to <= 8*100 base items + 512 changed actors. No DB,
  // resolver, broker or per-recipient network work occurs here.
  while (i < base.length || j < changes.length) {
    const existing = base[i];
    const changed = changes[j];
    let selected = null;
    if (changed && (!existing || changed.actorUri < existing.actorUri)) {
      if (changed.kind === 'upsert') selected = {
        actorUri: changed.actorUri, role: changed.role
      };
      j++;
    } else if (existing && (!changed || existing.actorUri < changed.actorUri)) {
      selected = existing;
      i++;
    } else {
      if (changed.kind === 'upsert') selected = {
        actorUri: changed.actorUri, role: changed.role
      };
      i++; j++;
    }
    if (selected && (after === null || selected.actorUri > after)) {
      result.push(selected);
      if (result.length > limit) break;
    }
  }
  const finalPage = pages[pages.length - 1];
  if (result.length <= limit && finalPage.hasMore) {
    fail('MEMBERSHIP_MERGE_NEEDS_MORE_BASE_PAGES');
  }
  const members = result.slice(0, limit);
  return Object.freeze({
    baseRevision, membershipRevision: currentRevision, members,
    hasMore: result.length > limit,
    nextCursor: result.length > limit ? members[members.length - 1].actorUri : null,
    basePageCount: pages.length, deltaCount: changes.length
  });
}
module.exports = Object.freeze({
  PAGE_SIZE, MAX_DELTA, MAX_BASE_PAGES, validateDelta, mergeWindow
});

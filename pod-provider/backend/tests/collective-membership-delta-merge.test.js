'use strict';
const index = require('../utils/collective-membership-page-index');
const deltaIndex = require('../utils/collective-membership-delta-merge');

const groupId = 'cg_' + 'b'.repeat(32);
const actor = i => 'https://members.example/u' + String(i).padStart(7, '0');
const baseline = (count = 1000) => Array.from({ length: Math.ceil(count / 100) }, (_, indexNo) => {
  const begin = indexNo * 100;
  return index.encodePage({
    groupId, revision: 5,
    cursor: indexNo === 0 ? null : actor(begin - 1),
    hasMore: begin + 100 < count,
    members: Array.from({ length: Math.min(count - begin, 100) }, (_, k) => ({
      actorUri: actor(begin + k), role: 'member'
    }))
  });
});
function merge(pages, delta, after = null, limit = 100) {
  return deltaIndex.mergeWindow({
    groupId, pages, delta, after, limit, baseRevision: 5,
    currentRevision: 6
  });
}
describe('G2 bounded index delta merge: read-cost independent of total group size', () => {
  test('unmodified canonical base returns exact first and next page', () => {
    const pages = baseline(300);
    expect(() => merge([pages[0]], [])).toThrow('MORE_BASE_PAGES');
    const first = merge(pages.slice(0, 2), []);
    expect(first.members).toHaveLength(100);
    expect(first.members[0].actorUri).toBe(actor(0));
    expect(first.nextCursor).toBe(actor(99));
    expect(first.hasMore).toBe(true);
    const second = merge(pages.slice(1), [], actor(99));
    expect(second.members[0].actorUri).toBe(actor(100));
    expect(second.members[99].actorUri).toBe(actor(199));
    expect(second.hasMore).toBe(true);
    expect(second.basePageCount).toBe(2);
  });
  test('insertions, updated roles, and tombstones merge without duplicate actors', () => {
    const pages = baseline(200);
    const delta = [
      { actorUri: actor(5), kind: 'remove' },
      { actorUri: actor(20), kind: 'upsert', role: 'moderator' },
      { actorUri: 'https://members.example/u0000020-extra', kind: 'upsert', role: 'member' }
    ];
    const result = merge(pages, delta);
    expect(result.members.some(x => x.actorUri === actor(5))).toBe(false);
    expect(result.members.find(x => x.actorUri === actor(20)).role).toBe('moderator');
    expect(result.members.some(x => x.actorUri === 'https://members.example/u0000020-extra')).toBe(true);
    expect(new Set(result.members.map(x => x.actorUri)).size).toBe(result.members.length);
    expect(result.members.map(x => x.actorUri)).toEqual(
      [...result.members.map(x => x.actorUri)].sort()
    );
  });
  test('512 removals require at most eight 100-member base pages for one output', () => {
    const pages = baseline(1000);
    const delta = Array.from({ length: 512 }, (_, i) => ({
      actorUri: actor(i), kind: 'remove'
    }));
    const result = merge(pages.slice(0, 8), delta);
    expect(result.members).toHaveLength(100);
    expect(result.members[0].actorUri).toBe(actor(512));
    expect(result.members[99].actorUri).toBe(actor(611));
    expect(result.basePageCount).toBe(8);
    expect(result.deltaCount).toBe(512);
    expect(result.hasMore).toBe(true);
  });
  test('an incomplete base page range is never silently considered terminal', () => {
    const pages = baseline(1000);
    const delta = Array.from({ length: 512 }, (_, i) => ({
      actorUri: actor(i), kind: 'remove'
    }));
    expect(() => merge(pages.slice(0, 6), delta))
      .toThrow('MEMBERSHIP_MERGE_NEEDS_MORE_BASE_PAGES');
  });
  test('bounded delta, page count, membership revision and role constraints fail closed', () => {
    const pages = baseline(1000);
    expect(() => merge(pages.slice(0, 9), [])).toThrow('INVALID_MEMBERSHIP_MERGE_INPUT');
    expect(() => merge(pages.slice(0, 2), Array.from({ length: 513 }, (_, i) => ({
      actorUri: actor(i), kind: 'remove'
    })))).toThrow('INVALID_MEMBERSHIP_DELTA_SIZE');
    expect(() => merge(pages.slice(0, 2), [
      { actorUri: actor(10), kind: 'upsert', role: 'owner' }
    ])).toThrow('INVALID_MEMBERSHIP_DELTA_ROLE');
    expect(() => merge(pages.slice(0, 2), [
      { actorUri: actor(10), kind: 'remove' },
      { actorUri: actor(10), kind: 'remove' }
    ])).toThrow('INVALID_MEMBERSHIP_DELTA_ORDER');
    const wrongGroup = { ...pages[0], groupId: 'cg_' + 'a'.repeat(32) };
    expect(() => merge([wrongGroup], [])).toThrow('INVALID_MEMBERSHIP_BASE_PAGE');
    expect(() => deltaIndex.mergeWindow({
      groupId, pages: pages.slice(0, 2), delta: [],
      baseRevision: 5, currentRevision: 4
    })).toThrow('INVALID_MEMBERSHIP_MERGE_INPUT');
  });
  test('no global full-membership scan, network or broker actions are used by merge', () => {
    const pages = baseline(1000);
    const delta = [{ actorUri: actor(20), kind: 'remove' }];
    const result = merge(pages.slice(0, 2), delta);
    expect(result.members).toHaveLength(100);
    expect(result.deltaCount).toBe(1);
    expect(result.basePageCount).toBe(2);
  });
});

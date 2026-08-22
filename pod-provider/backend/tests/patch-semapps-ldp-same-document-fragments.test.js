'use strict';

const fs = require('fs');
const path = require('path');

const {
  PATCH_MARKER,
  ORIGINAL_FILTER,
  PATCHED_FILTER,
  patchSource
} = require('../scripts/patch-semapps-ldp-same-document-fragments');

describe('SemApps same-document fragment traversal patch', () => {
  test('is available before production image dependency installation', () => {
    const dockerfile = fs.readFileSync(path.resolve(__dirname, '../../docker/backend.dockerfile'), 'utf8');
    const copyIndex = dockerfile.indexOf(
      'ADD backend/scripts/patch-semapps-ldp-same-document-fragments.js /app/backend/scripts/patch-semapps-ldp-same-document-fragments.js'
    );
    const installIndex = dockerfile.indexOf('RUN yarn install && yarn cache clean');

    expect(copyIndex).toBeGreaterThan(-1);
    expect(installIndex).toBeGreaterThan(copyIndex);
  });

  test('adds only same-document named fragments to blank-node traversal', () => {
    const result = patchSource(`before\n${ORIGINAL_FILTER}\nafter`);
    expect(result.changed).toBe(true);
    expect(result.source).toContain(PATCHED_FILTER);
    expect(result.source).toContain('STRSTARTS(STR(?o${i}), CONCAT(STR(?s1), "#"))');
    expect(result.source).not.toContain(ORIGINAL_FILTER);
  });

  test('is idempotent and validates its marker contract', () => {
    const first = patchSource(`before\n${ORIGINAL_FILTER}\nafter`);
    expect(patchSource(first.source)).toEqual({ source: first.source, changed: false });
    expect(() => patchSource(`// ${PATCH_MARKER}`)).toThrow('marker exists without the expected filter');
  });

  test('fails closed when the pinned SemApps source drifts', () => {
    expect(() => patchSource('no matching filter')).toThrow('Expected one pinned SemApps blank-node filter');
    expect(() => patchSource(`${ORIGINAL_FILTER}\n${ORIGINAL_FILTER}`)).toThrow(
      'Expected one pinned SemApps blank-node filter, found 2'
    );
  });
});

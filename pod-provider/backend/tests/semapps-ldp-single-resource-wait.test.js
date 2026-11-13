'use strict';

const { BEFORE, AFTER, MARKER, patchSingleResource, applyPatch } =
  require('../scripts/patch-semapps-ldp-single-resource-wait');

describe('SemApps Solid preferences readiness has a finite bound', () => {
  const fixture = `module.exports = {
    actions: { waitForResourceCreation: {
      async handler() {
        let resource, attempts = 0;
        do { attempts += 1; } while (!resource || attempts > 30);
        if (!resource) throw new Error('Resource still had not been created after 30s');
      }
    }}
  };`;

  test('replaces only inverted readiness loop while preserving missing-resource failure', () => {
    const result = patchSingleResource(fixture);
    expect(result.changed).toBe(true);
    expect(result.source).toContain(AFTER);
    expect(result.source).toContain(MARKER);
    expect(result.source).not.toContain(BEFORE);
    expect(result.source).toContain("if (!resource) throw new Error");
    const second = patchSingleResource(result.source);
    expect(second.changed).toBe(false);
    expect(second.source).toBe(result.source);
  });

  test('refuses unreviewed upstream changes', () => {
    expect(() => patchSingleResource('module.exports={}')).toThrow('refusing patch');
    expect(() => patchSingleResource(fixture.replace(BEFORE, AFTER))).toThrow('refusing patch');
    expect(() => patchSingleResource(patchSingleResource(fixture).source.replace(AFTER, BEFORE))).toThrow('drifted');
  });

  test('postinstall applied patch to installed version-locked SemApps LDP', () => {
    const result = applyPatch();
    expect(result.changed).toBe(false);
    expect(result.source).toContain(AFTER);
    expect(result.source).not.toContain(BEFORE);
  });
});

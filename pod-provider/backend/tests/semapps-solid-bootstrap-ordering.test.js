'use strict';

const fs = require('fs');
const path = require('path');
const {
  MARKER, WAIT_NEW, WAIT_OLD, patchTypeIndexes, applyPatch
} = require('../scripts/patch-semapps-solid-bootstrap-ordering');

describe('distributed Solid type-index bootstrap ordering', () => {
  const fixture = [
    'module.exports = {',
    '  events: {',
    "    'auth.registered': {",
    '      async handler(ctx) {',
    '        const { webId } = ctx.params;',
    '        await this.actions.createPublicIndex({ webId }, { parentCtx: ctx });',
    '        await this.actions.createPrivateIndex({ webId }, { parentCtx: ctx });',
    '      }',
    '    }',
    '  },',
    '  actions: {',
    '    createPublicIndex() {}, createPrivateIndex() {},',
    '    waitForIndexCreation: {',
    '      async handler() {',
    '        let attempts = 0, indexUri;',
    '        do { attempts++; } while (!indexUri || attempts > 30);',
    '      }',
    '    }',
    '  }',
    '};'
  ].join('\n');

  test('requires persisted preferences before private index, retains event handler and public index order', () => {
    const patched = patchTypeIndexes(fixture);
    expect(patched.changed).toBe(true);
    expect(patched.source).toContain(MARKER);
    expect(patched.source).toContain("await ctx.call('solid-preferences-file.waitForResourceCreation', { webId });");
    const source = patched.source;
    expect(source.indexOf('createPublicIndex({ webId }')).toBeLessThan(source.indexOf('solid-preferences-file.waitForResourceCreation'));
    expect(source.indexOf('solid-preferences-file.waitForResourceCreation')).toBeLessThan(source.indexOf('createPrivateIndex({ webId }'));
    expect(source).toContain(WAIT_NEW);
    expect(source).not.toContain(WAIT_OLD);
  });

  test('same patch does not emit a duplicate event or add a second writer', () => {
    const first = patchTypeIndexes(fixture);
    const second = patchTypeIndexes(first.source);
    expect(second.changed).toBe(false);
    expect(second.source).toEqual(first.source);
    expect(second.source.match(/auth\.registered/g)).toHaveLength(1);
    expect(second.source).not.toContain('ctx.emit(');
    expect(second.source).not.toContain('ldp.resource.create');
  });

  test('rejects upstream drift and incomplete prior patch', () => {
    expect(() => patchTypeIndexes('module.exports={}')).toThrow('refusing patch');
    expect(() => patchTypeIndexes(fixture.replace(WAIT_OLD, WAIT_NEW))).toThrow('refusing patch');
    const damaged = patchTypeIndexes(fixture).source.replace(WAIT_NEW, WAIT_OLD);
    expect(() => patchTypeIndexes(damaged)).toThrow('drifted');
  });

  test('installed SemApps 1.1.4 artifact is patched by postinstall and validated', () => {
    const result = applyPatch();
    expect(result.source).toContain(MARKER);
    expect(result.source).toContain(WAIT_NEW);
    expect(result.source).not.toContain(WAIT_OLD);
    expect(result.changed).toBe(false);
  });
});

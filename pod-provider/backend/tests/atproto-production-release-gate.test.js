'use strict';

const { assertNativeProtectedStorageReleased } =
  require('../services/utils/atproto-production-release-gate');

test('native protected RDF authorizations cannot activate in production before storage separation', () => {
  expect(() => assertNativeProtectedStorageReleased({
    NODE_ENV: 'production',
    APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true'
  })).toThrow(/canonical RDF storage remains reachable/);
});

test('normal provider startup and disposable integration proofs remain available', () => {
  for (const env of [
    { NODE_ENV: 'production', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'false' },
    { NODE_ENV: 'production' },
    { NODE_ENV: 'test', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true' },
    { NODE_ENV: 'development', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true' }
  ]) {
    expect(() => assertNativeProtectedStorageReleased(env)).not.toThrow();
  }
});

test('generic triplestore loads a release check rather than relying on deployment promises', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const source = fs.readFileSync(path.join(__dirname, '../services/core/triplestore.js'), 'utf8');
  expect(source).toContain('assertNativeProtectedStorageReleased();');
});

'use strict';

const { assertNativeProtectedStorageReleased } =
  require('../services/utils/atproto-production-release-gate');

test('unreleased native storage enforcement is denied regardless of NODE_ENV', () => {
  for (const env of [
    { NODE_ENV: 'production', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true' },
    { NODE_ENV: 'development', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true' },
    { APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true' },
    { NODE_ENV: 'test', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true' },
    { NODE_ENV: 'production', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true',
      APODS_ATPROTO_TEST_STORAGE_DISPOSABLE: 'confirmed' },
    { NODE_ENV: 'development', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true',
      APODS_ATPROTO_TEST_STORAGE_DISPOSABLE: 'confirmed' }
  ]) {
    expect(() => assertNativeProtectedStorageReleased(env))
      .toThrow(/canonical RDF storage remains reachable/);
  }
});

test('normal provider startup and explicitly disposable test providers remain available', () => {
  for (const env of [
    { NODE_ENV: 'production', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'false' },
    { NODE_ENV: 'production' },
    { NODE_ENV: 'development' },
    { NODE_ENV: 'test', APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED: 'true',
      APODS_ATPROTO_TEST_STORAGE_DISPOSABLE: 'confirmed' }
  ]) {
    expect(() => assertNativeProtectedStorageReleased(env)).not.toThrow();
  }
});

test('generic triplestore checks the release boundary before initialization', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const source = fs.readFileSync(path.join(__dirname, '../services/core/triplestore.js'), 'utf8');
  expect(source).toContain('assertNativeProtectedStorageReleased();');
  const launcher = fs.readFileSync(path.join(__dirname, '../scripts/run-moleculer-fabric.js'), 'utf8');
  expect(launcher).toContain('assertNativeProtectedStorageReleased();');
});

test('new canonical PostgreSQL authority cannot bypass the release fuse or native owner gate', () => {
  const { assertNativeProtectedStorageReleased } =
    require('../services/utils/atproto-production-release-gate');
  expect(() => assertNativeProtectedStorageReleased({
    NODE_ENV:'production',
    APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED:'true',
    APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED:'true'
  })).toThrow(/not released/);
  expect(() => assertNativeProtectedStorageReleased({
    NODE_ENV:'test',APODS_ATPROTO_TEST_STORAGE_DISPOSABLE:'confirmed',
    APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED:'true',
    APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED:'false'
  })).toThrow(/requires the native SAI owner fence/);
  expect(() => assertNativeProtectedStorageReleased({
    NODE_ENV:'test',APODS_ATPROTO_TEST_STORAGE_DISPOSABLE:'confirmed',
    APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED:'true',
    APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED:'true'
  })).not.toThrow();
});

test('distributed SAI owner authorization requires native gate and disposable test provider', () => {
  const { assertNativeProtectedStorageReleased } =
    require('../services/utils/atproto-production-release-gate');
  expect(() => assertNativeProtectedStorageReleased({
    NODE_ENV:'production',
    APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED:'true',
    APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED:'true'
  })).toThrow(/not released/);
  expect(() => assertNativeProtectedStorageReleased({
    NODE_ENV:'test',APODS_ATPROTO_TEST_STORAGE_DISPOSABLE:'confirmed',
    APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED:'false',
    APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED:'true'
  })).toThrow(/requires native SAI authorization/);
  expect(() => assertNativeProtectedStorageReleased({
    NODE_ENV:'test',APODS_ATPROTO_TEST_STORAGE_DISPOSABLE:'confirmed',
    APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED:'true',
    APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED:'true'
  })).not.toThrow();
});

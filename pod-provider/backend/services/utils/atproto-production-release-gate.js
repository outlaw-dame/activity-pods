'use strict';

/**
 * A shared SemApps triplestore can still write into the same per-Pod dataset
 * as an ATProto identity binding. JavaScript LDP hooks cannot prevent direct
 * privileged SPARQL updates to that dataset. Do not activate repository
 * grant fencing in a production provider until canonical permission state
 * lives behind a separately privileged storage connection.
 *
 * This is a source-controlled release boundary. Any attempt to enable the
 * native fence fails before service startup, regardless of NODE_ENV, except
 * for a deliberately marked disposable test provider. Remove this gate only
 * after proving that an ordinary privileged SPARQL writer cannot alter the
 * isolated canonical authority.
 */
const NATIVE_PROTECTED_STORAGE_RELEASED = false;

function assertNativeProtectedStorageReleased(env = process.env) {
  const disposableTest = env.NODE_ENV === 'test' &&
    env.APODS_ATPROTO_TEST_STORAGE_DISPOSABLE === 'confirmed';
  if (env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED === 'true' &&
      env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED !== 'true') {
    throw new Error('The canonical PG authority requires the native SAI owner fence');
  }
  if ((env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED === 'true' ||
       env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED === 'true') &&
      !NATIVE_PROTECTED_STORAGE_RELEASED && !disposableTest) {
    throw new Error(
      'The ATProto SAI integration is not released: canonical RDF storage remains reachable by general privileged SPARQL writers'
    );
  }
}

module.exports = { assertNativeProtectedStorageReleased };

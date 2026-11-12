'use strict';

/**
 * A shared SemApps triplestore can still write into the same per-Pod dataset
 * as an ATProto identity binding. JavaScript LDP hooks cannot prevent direct
 * privileged SPARQL updates to that dataset. Do not activate repository
 * grant fencing in a production provider until canonical permission state
 * lives behind a separately privileged storage connection.
 *
 * This is a source-controlled release boundary, not an environment variable
 * that an operator can bypass accidentally. Remove it only in the change
 * that installs and verifies the isolated canonical storage service.
 */
const NATIVE_PROTECTED_STORAGE_RELEASED = false;

function assertNativeProtectedStorageReleased(env = process.env) {
  if (env.NODE_ENV === 'production' &&
      env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED === 'true' &&
      !NATIVE_PROTECTED_STORAGE_RELEASED) {
    throw new Error(
      'The ATProto SAI integration is not released: canonical RDF storage remains reachable by general privileged SPARQL writers'
    );
  }
}

module.exports = { assertNativeProtectedStorageReleased };

'use strict';

/**
 * Fail-closed compatibility barrier for LEGACY LDP mutation entry points.
 *
 * A resource carrying any repoProjectionFence is managed by the fenced
 * PostgreSQL/Jena projection protocol and must NOT be replaced/deleted by
 * the preexisting non-CAS identitybindings.upsert/remove handlers.
 *
 * This check cannot make a read-then-write LDP operation atomic. A genuine
 * production activation must disable ALL unfenced writers at the triplestore
 * mutation boundary and use provider-owned conditional SPARQL against the
 * authoritative per-Pod dataset/graph. Do not mistake this for that gate.
 */
const FENCE_IRI = 'http://activitypods.org/ns/core#repoProjectionFence';
const FENCE_KEYS = Object.freeze(['repoProjectionFence', 'apods:repoProjectionFence', FENCE_IRI]);

function readFenceMarkers(resource) {
  if (!resource || typeof resource !== 'object' || Array.isArray(resource)) return [];
  const markers = [];
  for (const key of FENCE_KEYS) {
    if (Object.prototype.hasOwnProperty.call(resource, key)) {
      const value = resource[key];
      // Even malformed/empty/duplicate fence properties must deny legacy
      // writes; a parsing error must never downgrade a protected resource.
      markers.push({ key, value });
    }
  }
  return markers;
}

function assertUnfencedIdentityBindingMutation(resource, operation) {
  if (!['upsert', 'remove'].includes(operation)) {
    const error = new Error('Unsupported identity-binding mutation operation');
    error.code = 'IDENTITY_BINDING_MUTATION_INVALID';
    throw error;
  }
  if (readFenceMarkers(resource).length > 0) {
    const error = new Error(
      'Fenced identity binding requires provider-controlled atomic projection or deletion'
    );
    error.code = 'IDENTITY_BINDING_FENCED_LEGACY_MUTATION_FORBIDDEN';
    error.status = 409;
    throw error;
  }
}

module.exports = {
  FENCE_IRI,
  readFenceMarkers,
  assertUnfencedIdentityBindingMutation
};

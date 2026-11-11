'use strict';

const { MoleculerError } = require('moleculer').Errors;

/**
 * This is a deliberate compatibility gate, not the final repository writer.
 * Once native consent enforcement is enabled, generic SemApps LDP actions
 * may no longer replace or delete managed identity bindings. The signed
 * repository writer uses an exact conditional Jena update instead.
 *
 * Generic triplestore.update/insert and privileged Fuseki credentials remain
 * separate bypass paths. Production cutover requires a storage-level policy
 * that covers those paths too.
 */
function protectedPath(uri, baseUrl) {
  if (typeof uri !== 'string' || typeof baseUrl !== 'string' ||
      uri.length > 4096 || baseUrl.length > 2048) return false;
  let target, base;
  try {
    target = new URL(uri);
    base = new URL(baseUrl);
  } catch {
    return false;
  }
  const loopback = base.protocol === 'http:' &&
    ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
  if ((base.protocol !== 'https:' && !loopback) ||
      target.protocol !== base.protocol ||
      target.origin !== base.origin ||
      target.username || target.password) return false;

  const root = base.pathname.endsWith('/') ? base.pathname : base.pathname + '/';
  if (!target.pathname.startsWith(root)) return false;
  // URL parsing normalizes ./ and ../. Decode each segment so percent
  // encoding cannot disguise the protected container name.
  let segments;
  try {
    segments = target.pathname.slice(root.length)
      .split('/').map(segment => decodeURIComponent(segment));
  } catch {
    // Malformed escapes on a local resource are rejected conservatively.
    return /identity[-%]/iu.test(target.pathname);
  }
  // A local Pod has /<username>/data/identity-bindings/<resource>.
  // Matching the path segment rather than a substring avoids blocking
  // similarly named, unrelated user data.
  return segments.includes('identity-bindings');
}

function isPodStorageAncestor(uri, baseUrl) {
  if (typeof uri !== 'string' || typeof baseUrl !== 'string') return false;
  try {
    const target = new URL(uri);
    const base = new URL(baseUrl);
    const root = base.pathname.endsWith('/') ? base.pathname : base.pathname + '/';
    const loopback = base.protocol === 'http:' &&
      ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
    if (target.origin !== base.origin || target.protocol !== base.protocol ||
        (base.protocol !== 'https:' && !loopback) ||
        !target.pathname.startsWith(root)) return false;
    const pieces = target.pathname.slice(root.length).split('/')
      .filter(Boolean).map(segment => decodeURIComponent(segment));
    // Clearing or deleting a Pod root or its storage root can remove the
    // protected container indirectly, before per-resource hooks run.
    return pieces.length === 1 ||
      (pieces.length === 2 && pieces[1] === 'data');
  } catch {
    return false;
  }
}

function assertNotManagedLdpMutation(ctx, baseUrl, {
  checkResource = true, checkContainer = true, protectAncestors = false
} = {}) {
  if (process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED !== 'true') return;
  let base;
  try { base = new URL(baseUrl); } catch { /* invalid provider URL */ }
  if (!base || (base.protocol !== 'https:' &&
      !(base.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)))) {
    throw new MoleculerError(
      'ATProto LDP fencing requires a canonical HTTPS or loopback provider URL',
      503, 'ATPROTO_LDP_FENCE_CONFIG_INVALID'
    );
  }
  const params = ctx?.params || {};
  const candidates = [];
  if (checkResource) {
    candidates.push(params.resourceUri, params.resource?.['@id'], params.resource?.id,
      params.forcedResourceUri);
  }
  if (checkContainer) candidates.push(params.containerUri);
  if (candidates.some(uri => protectedPath(uri, baseUrl)) ||
      (protectAncestors && isPodStorageAncestor(params.containerUri, baseUrl))) {
    throw new MoleculerError(
      'Managed repository identity bindings cannot be changed through the general LDP API',
      409,
      'ATPROTO_MANAGED_BINDING_WRITE_FENCED'
    );
  }
}

module.exports = { protectedPath, isPodStorageAncestor, assertNotManagedLdpMutation };

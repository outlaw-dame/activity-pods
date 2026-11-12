'use strict';

const { MoleculerError } = require('moleculer').Errors;

// Only one parsed provider origin is retained per process. Normal LDP writes
// return before reaching this cache when repository fencing is disabled.
let cachedBaseUrl;
let cachedBase;

function providerBase(baseUrl) {
  if (baseUrl === cachedBaseUrl) return cachedBase;
  let parsed;
  try {
    if (typeof baseUrl === 'string' && baseUrl.length <= 2048) {
      const u = new URL(baseUrl);
      const loopback = u.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
      if ((u.protocol === 'https:' || loopback) &&
          !u.username && !u.password && !u.search && !u.hash) {
        parsed = Object.freeze({
          origin: u.origin,
          protocol: u.protocol,
          path: u.pathname.endsWith('/') ? u.pathname : u.pathname + '/'
        });
      }
    }
  } catch {
    // Invalid provider configuration is reported by the enabled write gate.
  }
  cachedBaseUrl = baseUrl;
  cachedBase = parsed || null;
  return cachedBase;
}

function localPath(uri, base) {
  if (typeof uri !== 'string') return null;
  // Never interpret overlong, malformed paths as safe under enforcement.
  if (uri.length > 4096) return { invalid: true };
  let target;
  try { target = new URL(uri); } catch { return null; }
  if (target.origin !== base.origin || target.protocol !== base.protocol) return null;
  if (target.username || target.password ||
      !target.pathname.startsWith(base.path)) return null;
  let tail = target.pathname.slice(base.path.length);
  // SemApps, HTTP routing, and reverse proxies need not decode the same
  // number of times. Recognize encoded container names and separators before
  // any of those layers can reinterpret them.
  for (let i = 0; i < 4; i++) {
    let decoded;
    try { decoded = decodeURIComponent(tail); }
    catch { return { invalid: true }; }
    if (decoded === tail) return { segments: tail.split('/').filter(Boolean) };
    tail = decoded;
  }
  // Further encodings are ambiguous. Reject instead of guessing.
  return { invalid: /%[0-9a-f]{2}/iu.test(tail), segments: tail.split('/').filter(Boolean) };
}

function protectedPath(uri, baseUrl) {
  const base = providerBase(baseUrl);
  if (!base) return false;
  const path = localPath(uri, base);
  if (!path) return false;
  return Boolean(path.invalid || path.segments?.includes('identity-bindings'));
}

function isPodStorageAncestor(uri, baseUrl) {
  const base = providerBase(baseUrl);
  if (!base) return false;
  const path = localPath(uri, base);
  if (!path) return false;
  if (path.invalid) return true;
  const segments = path.segments;
  // The provider root, Pod root and Pod data root can contain the protected
  // container. Guard bulk deletion before it enumerates any resources.
  return segments.length === 0 || segments.length === 1 ||
    (segments.length === 2 && segments[1] === 'data');
}

/**
 * Initial creation of the empty managed container is part of the native Pod
 * signup registry. Denying it blocks every later registered container and
 * leaves an incompletely provisioned account. Only the exact empty container
 * can be created or attached: its child resources still require the fenced
 * writer, and its contents cannot be modified by generic LDP operations.
 */
function exactIdentityContainer(uri, baseUrl) {
  const base = providerBase(baseUrl);
  if (!base) return null;
  const value = localPath(uri, base);
  if (!value || value.invalid || value.segments?.length !== 3) return null;
  const [username, storage, container] = value.segments;
  if (storage !== 'data' || container !== 'identity-bindings' ||
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u.test(username)) return null;
  return {
    owner: base.origin + base.path + username,
    storage: base.origin + base.path + username + '/data'
  };
}

function safeBootstrapOptions(options) {
  const perms = options?.newResourcesPermissions;
  const accepted = options?.acceptedTypes;
  return Boolean(options && typeof options === 'object' &&
    options.name === 'identitybindings' &&
    options.path === '/identity-bindings' &&
    options.excludeFromMirror === true &&
    options.activateTombstones === false &&
    options.readOnly === false &&
    Array.isArray(accepted) && accepted.length === 1 &&
    accepted[0] === 'http://activitypods.org/ns/core#AtprotoIdentityBinding' &&
    perms?.anon?.read === false &&
    perms?.user?.read === false &&
    perms?.user?.write === false);
}

function isAllowedEmptyContainerBootstrap(ctx, baseUrl, kind) {
  const params = ctx?.params || {};
  if (kind === 'create') {
    const exact = exactIdentityContainer(params.containerUri, baseUrl);
    return Boolean(exact && params.webId === exact.owner &&
      safeBootstrapOptions(params.options));
  }
  if (kind === 'attach') {
    const exact = exactIdentityContainer(params.resourceUri, baseUrl);
    if (!exact || params.webId !== 'system') return false;
    const target = localPath(params.containerUri, providerBase(baseUrl));
    const base = providerBase(baseUrl);
    if (!target || target.invalid ||
        target.segments?.length !== 2) return false;
    const [username, storage] = target.segments;
    return username && storage === 'data' &&
      exact.storage === base.origin + base.path + username + '/data';
  }
  return false;
}

function assertNotManagedLdpMutation(ctx, baseUrl, {
  checkResource = true, checkContainer = true, protectAncestors = false,
  allowEmptyBootstrap = null
} = {}) {
  if (process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED !== 'true') return;
  if (!providerBase(baseUrl)) {
    throw new MoleculerError(
      'ATProto LDP fencing requires a canonical HTTPS or loopback provider URL',
      503, 'ATPROTO_LDP_FENCE_CONFIG_INVALID'
    );
  }
  const params = ctx?.params || {};
  if (allowEmptyBootstrap &&
      isAllowedEmptyContainerBootstrap(ctx, baseUrl, allowEmptyBootstrap)) return;
  // O(1) URI checks: no account listing, graph traversal, network call,
  // database query, or persistent per-user state in the hot path.
  if (
    (checkResource && (
      protectedPath(params.resourceUri, baseUrl) ||
      protectedPath(params.resource?.['@id'], baseUrl) ||
      protectedPath(params.resource?.id, baseUrl) ||
      protectedPath(params.forcedResourceUri, baseUrl)
    )) ||
    (checkContainer && protectedPath(params.containerUri, baseUrl)) ||
    (protectAncestors && isPodStorageAncestor(params.containerUri, baseUrl))
  ) {
    throw new MoleculerError(
      'Managed repository identity bindings cannot be changed through the general LDP API',
      409, 'ATPROTO_MANAGED_BINDING_WRITE_FENCED'
    );
  }
}

module.exports = {
  protectedPath, isPodStorageAncestor, exactIdentityContainer,
  isAllowedEmptyContainerBootstrap, assertNotManagedLdpMutation
};

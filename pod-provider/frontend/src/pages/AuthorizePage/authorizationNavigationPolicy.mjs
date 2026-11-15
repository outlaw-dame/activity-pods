/**
 * Provider-owned SAI browser navigation boundary.
 *
 * WebID RDF is user-editable data, not a trusted bearer-token destination.
 * The provider backend origin is supplied by the immutable frontend config;
 * never put a locally issued login token on a request to a WebID-advertised
 * arbitrary issuer. Never follow redirects on authenticated app-status.
 */
const MAX_URL_LENGTH = 4096;

function parseHttpUrl(value, { allowFragment = false, allowQuery = false } = {}) {
  if (typeof value !== 'string' || !value ||
      value.length > MAX_URL_LENGTH || value.trim() !== value) {
    throw new Error('SAI_URL_UNTRUSTED');
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error('SAI_URL_UNTRUSTED');
  }
  const loopback = url.hostname === 'localhost' ||
    url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) ||
      !url.hostname || url.username || url.password ||
      (!allowFragment && url.hash) || (!allowQuery && url.search) ||
      url.toString() !== value && !(url.pathname === '/' &&
        url.toString() === value + '/')) {
    throw new Error('SAI_URL_UNTRUSTED');
  }
  return url;
}

export function trustedAppStatusUrl({
  backendUrl, webId, oidcIssuer, appUri
}) {
  const backend = parseHttpUrl(backendUrl);
  const webid = parseHttpUrl(webId, { allowFragment: true });
  const app = parseHttpUrl(appUri, { allowFragment: true, allowQuery: true });

  // Restrict this native *local-provider* consent page to the provider
  // that owns the active login credential. Cross-provider WebID/OIDC
  // authorization must use a separately authenticated, explicit flow.
  if (webid.origin !== backend.origin || !app) {
    throw new Error('SAI_ACCOUNT_PROVIDER_MISMATCH');
  }

  if (oidcIssuer !== undefined && oidcIssuer !== null) {
    const issuer = parseHttpUrl(oidcIssuer);
    if (issuer.origin !== backend.origin) {
      throw new Error('SAI_OIDC_ISSUER_MISMATCH');
    }
  }

  // The app-status service is registered at the provider's root, not at
  // a path inferred from WebID / oidcIssuer data.
  const endpoint = new URL('/.well-known/app-status', backend.origin);
  endpoint.searchParams.set('appUri', appUri);
  return endpoint.toString();
}

/**
 * Application callback must be an absolute canonical browser-safe URL
 * controlled by the SAI application descriptor's *own origin*. The caller
 * is not allowed to pass an arbitrary open-redirect destination.
 *
 * Cross-origin callbacks need a separate reviewed allowlist/consent policy.
 */
export function trustedAppAuthorizationCallback(appUri, callbackUrl) {
  const app = parseHttpUrl(appUri, { allowFragment: true, allowQuery: true });
  const callback = parseHttpUrl(callbackUrl, { allowQuery: true, allowFragment: true });
  if (callback.origin !== app.origin) {
    throw new Error('SAI_CALLBACK_ORIGIN_MISMATCH');
  }
  return callback.toString();
}

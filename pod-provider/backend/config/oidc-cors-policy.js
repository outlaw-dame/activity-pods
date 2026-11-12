'use strict';

// oidc-provider 8 calls clientBasedCORS with the resolved client metadata.
// A browser origin is authorized only for that client's registered HTTPS
// redirect origins; a client may never broaden another client's access.
function allowedOrigin(origin, client, { allowLocalhost = false } = {}) {
  if (typeof origin !== 'string' || origin.length > 2048 ||
      typeof client !== 'object' || !client) return false;

  let requested;
  try {
    requested = new URL(origin);
  } catch {
    return false;
  }
  const local = allowLocalhost && requested.protocol === 'http:' &&
    (requested.hostname === 'localhost' || requested.hostname === '127.0.0.1');
  if ((!local && requested.protocol !== 'https:') ||
      requested.origin !== origin || requested.username ||
      requested.password || requested.pathname !== '/' ||
      requested.search || requested.hash) return false;

  const redirectUris = client.redirectUris;
  if (!Array.isArray(redirectUris) || !redirectUris.length ||
      redirectUris.length > 32) return false;

  return redirectUris.some(raw => {
    if (typeof raw !== 'string' || raw.length > 2048) return false;
    let redirect;
    try { redirect = new URL(raw); } catch { return false; }
    return redirect.origin === origin &&
      redirect.protocol === requested.protocol &&
      !redirect.username && !redirect.password &&
      !redirect.hash &&
      redirect.href === raw;
  });
}

module.exports = { allowedOrigin };

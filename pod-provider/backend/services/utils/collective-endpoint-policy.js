'use strict';

/** Explicit browser origins for high-trust Group APIs. Does not grant access. */
function canonicalOrigin(value) {
  if (typeof value !== 'string' || value.length > 512 ||
      /[\u0000-\u0020\u007f\\]/u.test(value)) return null;
  try {
    const u = new URL(value);
    if (u.protocol !== 'https:' || u.username || u.password || u.pathname !== '/' ||
        u.search || u.hash || u.origin !== value.replace(/\/$/u, '')) return null;
    return u.origin;
  } catch {
    return null;
  }
}
function approvedBrowserOrigins(providerOrigin, csv = '') {
  const ownOrigin = canonicalOrigin(providerOrigin);
  if (!ownOrigin) throw new Error('Invalid canonical HTTPS provider origin for Groups');
  const items = String(csv || '').split(',').map(x => x.trim()).filter(Boolean);
  if (items.length > 32) throw new Error('Too many Group browser CORS origins');
  const parsed = items.map(canonicalOrigin);
  if (parsed.some(x => !x)) throw new Error('Invalid Group browser CORS origin');
  return [...new Set([ownOrigin, ...parsed])];
}
module.exports = { canonicalOrigin, approvedBrowserOrigins };

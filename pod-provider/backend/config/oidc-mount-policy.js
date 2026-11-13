'use strict';

// oidc-provider's callback is a root-mounted Node HTTP handler. Moleculer
// exposes it below a prefix; strip only that exact prefix, preserving the
// query string. Other URL paths and similarly prefixed names are untouched.
function mountedOidcCallback(callback, prefix) {
  if (typeof callback !== 'function' || typeof prefix !== 'string' ||
      !prefix.startsWith('/') || prefix.endsWith('/') ||
      prefix.includes('?') || prefix.includes('#') || prefix.includes('//') ||
      prefix.includes('..') || prefix.length > 1024) {
    throw new TypeError('Invalid OIDC provider mount');
  }
  return (req, res, next) => {
    const raw = req?.url;
    if (typeof raw !== 'string' || raw.length > 8192) {
      return typeof next === 'function' ? next(new Error('Invalid OIDC request URL')) : undefined;
    }
    const sep = raw.indexOf('?');
    const pathname = sep === -1 ? raw : raw.slice(0, sep);
    if (pathname === prefix || pathname.startsWith(prefix + '/')) {
      const remainder = pathname.slice(prefix.length) || '/';
      req.url = remainder + (sep === -1 ? '' : raw.slice(sep));
    }
    return callback(req, res, next);
  };
}

module.exports = Object.freeze({ mountedOidcCallback });

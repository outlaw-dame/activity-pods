'use strict';

// moleculer-web v0.10.x matches route prefixes in array order and stops at
// the FIRST match. In particular, the default root ('/') route matches every
// URL, including /.oidc/auth/*, even when it has only a GET '/' alias.
// Keep the root fallback last; ordinary path routes must precede it.
// Preserve registration order within each priority group for predictable
// behavior when unrelated services add aliases at runtime.
const routePriority = route => {
  if (route.path === '/') return 2;
  if (route.opts?.catchAll) return 1;
  return 0;
};

// Aliases have their own exact-match resolver, so a GET '/' redirect must
// not lose its original precedence merely because its parent route is '/'.
const aliasPriority = alias => alias.route.opts?.catchAll ? 1 : 0;

function optimizeApiRouteOrder(gateway) {
  gateway.routes.sort((a, b) => routePriority(a) - routePriority(b));
  gateway.aliases.sort((a, b) => aliasPriority(a) - aliasPriority(b));
}

module.exports = { optimizeApiRouteOrder };

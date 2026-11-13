'use strict';

// Keep catch-all routes last without reordering routes at the same priority.
// A comparator that only examines its first argument violates the sort
// contract and can change alias precedence between startup instances.
const catchAllPriority = route => route.opts.catchAll ? 1 : 0;

function optimizeApiRouteOrder(gateway) {
  gateway.routes.sort((a, b) => catchAllPriority(a) - catchAllPriority(b));
  gateway.aliases.sort((a, b) => catchAllPriority(a.route) - catchAllPriority(b.route));
}

module.exports = { optimizeApiRouteOrder };

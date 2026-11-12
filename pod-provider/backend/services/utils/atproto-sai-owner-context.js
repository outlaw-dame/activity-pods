'use strict';

// The SAI owner action may invoke several nested Moleculer services.
// Individual LDP calls can use the provider's system WebID to write a
// resource, but that is not proof that the user approved the change.
//
// Keep the authorization on the already-authenticated parent action
// context, never in propagated ctx.meta or a caller-supplied parameter.
const ownerActions = new WeakMap();
const MAX_PARENT_DEPTH = 40;

function authorizeOwnerSaiAction(ctx, { owner, app }) {
  if (typeof owner !== 'string' || typeof app !== 'string' ||
      !owner.startsWith('https://') || !app.startsWith('https://') ||
      !ctx || ctx.meta?.webId !== owner || ctx.meta?.impersonatedUser) {
    const err = new Error('Only the authenticated Pod owner may authorize this SAI change');
    err.code = 'ATPROTO_SAI_OWNER_CONTEXT_INVALID';
    throw err;
  }
  if (ownerActions.has(ctx)) {
    throw Error('The SAI owner action is already in progress');
  }
  ownerActions.set(ctx, { owner, app });
  return () => ownerActions.delete(ctx);
}

function hasAuthorizedOwnerParent(ctx, { owner, app }) {
  let current = ctx;
  for (let depth = 0; current && depth < MAX_PARENT_DEPTH; depth++) {
    const scope = ownerActions.get(current);
    if (scope) return scope.owner === owner && scope.app === app;
    current = current.parentCtx;
  }
  return false;
}

module.exports = { authorizeOwnerSaiAction, hasAuthorizedOwnerParent };

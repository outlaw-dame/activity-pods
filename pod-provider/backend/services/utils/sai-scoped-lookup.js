'use strict';

const namespace = 'http://www.w3.org/ns/solid/interop#';

// Grants and authorizations may share need identifiers across applications.
async function findScopedRecord(service, ctx, ownerProperty, needProperty, needUri) {
  const { podOwner, appUri } = ctx.params;
  const scope = { [ownerProperty]: podOwner, grantee: appUri, [needProperty]: needUri };
  if (!Object.values(scope).every(value => typeof value === 'string' && value.length > 0 &&
      value.length <= 2048 && !/[\s<>"{}|^`\\]/u.test(value))) throw new Error('Incomplete SAI grant scope');
  const filters = Object.fromEntries(Object.entries(scope).map(([key, value]) => [namespace + key, value]));
  const container = await service.actions.list({ filters, webId: podOwner }, { parentCtx: ctx });
  const items = container['ldp:contains'];
  if (items === undefined || (Array.isArray(items) && !items.length)) return undefined;
  const rows = Array.isArray(items) ? items : [items];
  if (rows.length !== 1 || !rows[0]?.id ||
      Object.entries(scope).some(([key, value]) => rows[0]['interop:' + key] !== value)) {
    throw new Error('Ambiguous or mismatched SAI grant scope');
  }
  return rows[0];
}

module.exports = { findScopedRecord };

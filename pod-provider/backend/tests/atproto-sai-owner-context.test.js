'use strict';

const {
  authorizeOwnerSaiAction, hasAuthorizedOwnerParent
} = require('../services/utils/atproto-sai-owner-context');

const owner = 'https://paper.example.org/alice';
const app = 'https://writer.example.org/client';

test('nested provider writes inherit only the owner-approved application scope', () => {
  const root = { meta: { webId: owner } };
  const release = authorizeOwnerSaiAction(root, { owner, app });
  const child = { meta: { webId: 'system' }, parentCtx: root };
  const nested = { meta: { webId: 'system' }, parentCtx: child };
  expect(hasAuthorizedOwnerParent(nested, { owner, app })).toBe(true);
  expect(hasAuthorizedOwnerParent(nested, { owner, app: 'https://other.example.org' })).toBe(false);
  expect(hasAuthorizedOwnerParent(nested, { owner: 'https://paper.example.org/bob', app })).toBe(false);
  release();
  expect(hasAuthorizedOwnerParent(nested, { owner, app })).toBe(false);
});

test('unverified parent identity, client impersonation and forged child metadata cannot create a scope', () => {
  const fake = { meta: { webId: 'system' } };
  expect(() => authorizeOwnerSaiAction(fake, { owner, app })).toThrow();
  const impersonated = { meta: { webId: owner, impersonatedUser: owner } };
  expect(() => authorizeOwnerSaiAction(impersonated, { owner, app })).toThrow();
  expect(hasAuthorizedOwnerParent({ meta: { webId: owner }, parentCtx: fake }, { owner, app })).toBe(false);
});

test('owner scope is bounded by the parent chain and does not leak to another request', () => {
  const root = { meta: { webId: owner } };
  const release = authorizeOwnerSaiAction(root, { owner, app });
  expect(() => authorizeOwnerSaiAction(root, { owner, app })).toThrow();
  const unrelated = { meta: { webId: 'system' }, parentCtx: { meta: { webId: owner } } };
  expect(hasAuthorizedOwnerParent(unrelated, { owner, app })).toBe(false);
  let child = root;
  for (let i = 0; i < 40; i++) child = { meta: { webId: 'system' }, parentCtx: child };
  expect(hasAuthorizedOwnerParent(child, { owner, app })).toBe(false);
  release();
});

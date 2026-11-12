'use strict';

const {
  authorizeOwnerSaiAction, hasAuthorizedOwnerParent
} = require('../services/utils/atproto-sai-owner-context');

const owner = 'https://paper.example.org/alice';
const app = 'https://writer.example.org/client';

function root(id = 'request-1') {
  return { requestID: id, meta: { webId: owner } };
}
function child(parent, { requestID = parent.requestID, meta = parent.meta } = {}) {
  // Moleculer 0.14 inherits the request ID and shallow-copies metadata;
  // a child does not expose parentCtx.
  return { requestID, meta: { ...meta, webId: 'system' } };
}

test('nested grant writes carry one short-lived owner-approved scope', () => {
  const initial = root();
  const release = authorizeOwnerSaiAction(initial, { owner, app });
  const nested = child(child(initial));
  expect(hasAuthorizedOwnerParent(nested, { owner, app })).toBe(true);
  expect(hasAuthorizedOwnerParent(nested, {
    owner, app: 'https://other.example.org'
  })).toBe(false);
  expect(hasAuthorizedOwnerParent(nested, {
    owner: 'https://paper.example.org/bob', app
  })).toBe(false);
  release();
  expect(hasAuthorizedOwnerParent(nested, { owner, app })).toBe(false);
});

test('scope must match the originating request and cannot be invented by a child', () => {
  const initial = root();
  const release = authorizeOwnerSaiAction(initial, { owner, app });
  const anotherRequest = child(initial, { requestID: 'request-attacker' });
  expect(hasAuthorizedOwnerParent(anotherRequest, { owner, app })).toBe(false);
  const guessed = child(initial, {
    meta: { webId: owner, apodsNativeSaiOwnerProof: 'x'.repeat(43) }
  });
  expect(hasAuthorizedOwnerParent(guessed, { owner, app })).toBe(false);
  release();
});

test('an unverified Pod owner, impersonated app and duplicate scope cannot gain approval', () => {
  expect(() => authorizeOwnerSaiAction({
    requestID: 'req', meta: { webId: 'system' }
  }, { owner, app })).toThrow();
  expect(() => authorizeOwnerSaiAction({
    requestID: 'req', meta: { webId: owner, impersonatedUser: owner }
  }, { owner, app })).toThrow();
  const initial = root('request-2');
  const release = authorizeOwnerSaiAction(initial, { owner, app });
  expect(() => authorizeOwnerSaiAction(initial, { owner, app })).toThrow();
  release();
  expect(initial.meta.apodsNativeSaiOwnerProof).toBeUndefined();
});

test('owner authorization is never inherited across independent top-level requests', () => {
  const first = root('request-3');
  const release = authorizeOwnerSaiAction(first, { owner, app });
  expect(hasAuthorizedOwnerParent(child(root('request-4')), { owner, app })).toBe(false);
  release();
  expect(hasAuthorizedOwnerParent(child(first), { owner, app })).toBe(false);
});

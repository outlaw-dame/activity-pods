'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const {
  FENCE_IRI, readFenceMarkers, assertUnfencedIdentityBindingMutation
} = require('../utils/identitybinding-fence-policy');

const fenceValues = [
  '1', '9223372036854775807', '0', '', null, false, [],
  { '@value': '7', '@type': 'http://www.w3.org/2001/XMLSchema#integer' },
  [{ '@value': '6' }, { '@value': '7' }]
];

test('unfenced LDP resources and absent bindings retain legacy compatibility', () => {
  for (const operation of ['upsert', 'remove']) {
    assert.doesNotThrow(() => assertUnfencedIdentityBindingMutation(null, operation));
    assert.doesNotThrow(() =>
      assertUnfencedIdentityBindingMutation({
        '@id': 'https://paper.example.org/identity-bindings/atproto-123',
        'apods:repoRootCid': 'bafyre...'
      }, operation)
    );
  }
});

test('all fence encodings, including malformed/duplicate, forbid legacy upsert and delete', () => {
  for (const key of [FENCE_IRI, 'apods:repoProjectionFence', 'repoProjectionFence']) {
    for (const value of fenceValues) {
      const resource = { [key]: value };
      assert.equal(readFenceMarkers(resource).length, 1);
      for (const operation of ['upsert', 'remove']) {
        assert.throws(
          () => assertUnfencedIdentityBindingMutation(resource, operation),
          error => error.code === 'IDENTITY_BINDING_FENCED_LEGACY_MUTATION_FORBIDDEN' &&
            error.status === 409
        );
      }
    }
  }
});

test('multiple contradictory fence encodings still fail closed', () => {
  const resource = {
    repoProjectionFence: '9',
    [FENCE_IRI]: '6'
  };
  assert.equal(readFenceMarkers(resource).length, 2);
  assert.throws(
    () => assertUnfencedIdentityBindingMutation(resource, 'upsert'),
    error => error.code === 'IDENTITY_BINDING_FENCED_LEGACY_MUTATION_FORBIDDEN'
  );
});

test('unknown operation never gets a permissive default', () => {
  assert.throws(
    () => assertUnfencedIdentityBindingMutation(null, 'overwrite'),
    error => error.code === 'IDENTITY_BINDING_MUTATION_INVALID'
  );
});

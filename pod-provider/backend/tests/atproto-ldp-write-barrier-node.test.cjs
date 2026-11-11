'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

class MoleculerError extends Error {
  constructor(message, code, type) {
    super(message);
    this.code = code;
    this.type = type;
  }
}
function load(filename, imported) {
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
    module, exports: module.exports, process, URL,
    require(name) {
      if (!Object.hasOwn(imported, name)) throw Error('Unexpected import: ' + name);
      return imported[name];
    }
  }, { filename, timeout: 2500 });
  return module.exports;
}
const backend = path.resolve(__dirname, '..');
const guard = load(path.join(backend, 'services/utils/atproto-ldp-write-barrier.js'), {
  moleculer: { Errors: { MoleculerError } }
});
const root = 'https://paper.example.org/';
const prefix = root + 'alice/data/';
const binding = prefix + 'identity-bindings/atproto-abc';
const elsewhere = prefix + 'articles/a';
const ldp = load(path.join(backend, 'services/core/ldp.js'), {
  '@semapps/ldp': { LdpService: {}, DocumentTaggerMixin: {} },
  '../../config/config': { BASE_URL: root },
  '../utils/atproto-ldp-write-barrier': guard
});

const previous = process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
process.on('exit', () => {
  if (previous === undefined) delete process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
  else process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED = previous;
});
const on = () => { process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED = 'true'; };
const off = () => { delete process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED; };

test('no additional work or rejection when repository protection is disabled', () => {
  off();
  for (const operation of ['put', 'patch', 'delete', 'create', 'upload']) {
    assert.doesNotThrow(() => ldp.hooksResource.before[operation]({
      params: { resourceUri: binding }
    }));
  }
  assert.doesNotThrow(() => ldp.hooksContainer.before.post({
    params: { containerUri: prefix + 'identity-bindings/' }
  }));
});

test('all direct SemApps resource write entry points reject protected bindings', () => {
  on();
  for (const operation of ['put', 'patch', 'delete', 'create', 'upload']) {
    assert.throws(() => ldp.hooksResource.before[operation]({
      params: { resourceUri: binding }
    }), e => e.code === 409 && e.type === 'ATPROTO_MANAGED_BINDING_WRITE_FENCED');
  }
  assert.throws(() => ldp.hooksResource.before.put({
    params: { resource: { '@id': binding } }
  }), e => e.code === 409);
});

test('container POST, attach/detach, patch, delete and create cannot bypass a protected binding', () => {
  on();
  for (const operation of ['post', 'create', 'createAndAttach', 'delete', 'clear', 'patch', 'attach', 'detach']) {
    assert.throws(() => ldp.hooksContainer.before[operation]({
      params: { containerUri: prefix + 'identity-bindings/' }
    }), e => e.code === 409);
  }
  for (const operation of ['attach', 'detach']) {
    assert.throws(() => ldp.hooksContainer.before[operation]({
      params: { containerUri: prefix, resourceUri: binding }
    }), e => e.code === 409);
  }
  assert.throws(() => ldp.hooksContainer.before.post({
    params: { containerUri: prefix, forcedResourceUri: binding }
  }), e => e.code === 409);
});

test('other Pod resources and remote namespaces keep their normal LDP behavior', () => {
  on();
  for (const uri of [
    elsewhere, prefix + 'identity-bindings-public/article',
    'https://remote.example.org/alice/data/identity-bindings/item',
    root + 'bob/data/posts/abc'
  ]) {
    assert.doesNotThrow(() => ldp.hooksResource.before.put({
      params: { resourceUri: uri }
    }));
  }
  assert.equal(guard.protectedPath(binding, root), true);
  assert.equal(guard.protectedPath(elsewhere, root), false);
});

test('bulk clear/delete cannot start deleting Pod ancestors before reaching a protected resource', () => {
  on();
  for (const operation of ['clear', 'delete']) {
    for (const containerUri of [root + 'alice/', root + 'alice/data/']) {
      assert.throws(() => ldp.hooksContainer.before[operation]({
        params: { containerUri }
      }), e => e.code === 409);
    }
  }
  assert.doesNotThrow(() => ldp.hooksContainer.before.clear({
    params: { containerUri: prefix + 'ordinary-posts/' }
  }));
});

test('percent-encoded segments cannot bypass the protected container match', () => {
  on();
  const encoded = prefix + '%69dentity-bindings/atproto-abc';
  assert.equal(guard.protectedPath(encoded, root), true);
  assert.throws(() => ldp.hooksResource.before.delete({
    params: { resourceUri: encoded }
  }), e => e.code === 409);
});

test('loopback development URLs are fenced and invalid provider origins fail closed', () => {
  on();
  assert.equal(guard.protectedPath(
    'http://127.0.0.1:3000/alice/data/identity-bindings/x',
    'http://127.0.0.1:3000/'
  ), true);
  assert.throws(() => guard.assertNotManagedLdpMutation(
    { params: { resourceUri: binding } },
    'http://untrusted.example.org/'
  ), e => e.code === 503 && e.type === 'ATPROTO_LDP_FENCE_CONFIG_INVALID');
});

test('barriers are installed at the LdpService subservice hooks, not only ControlledContainerMixin', () => {
  assert.equal(typeof ldp.hooksResource.before.delete, 'function');
  assert.equal(typeof ldp.hooksResource.before.patch, 'function');
  assert.equal(typeof ldp.hooksContainer.before.post, 'function');
  assert.equal(typeof ldp.hooksContainer.before.detach, 'function');
  assert.ok(ldp.mixins.length >= 1);
});

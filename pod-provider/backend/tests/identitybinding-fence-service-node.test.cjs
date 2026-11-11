'use strict';
/**
 * Dependency-free service handler wiring test. Loads the real service module
 * with small stand-ins for external SemApps/Moleculer packages, so the test
 * verifies guard placement BEFORE any put/post/delete side effect.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const servicePath = path.join(__dirname, '..', 'services', 'identitybindings.service.js');
const policy = require('../utils/identitybinding-fence-policy');
class MoleculerError extends Error {
  constructor(message, code, type) {
    super(message);
    this.code = code;
    this.type = type;
  }
}

function loadService() {
  const modules = {
    'url-join': (...parts) => parts.join('/').replace(/\/{2,}/g, '/'),
    '@semapps/ldp': { ControlledContainerMixin: {} },
    '@semapps/mime-types': { MIME_TYPES: { JSON: 'application/json' } },
    '@semapps/triplestore': { sanitizeSparqlQuery: text => text },
    moleculer: { Errors: { MoleculerError } }
  };
  const module = { exports: {} };
  const sandbox = {
    module, exports: module.exports, URL, Buffer, console, process,
    require: name => {
      if (name === 'crypto') return require('node:crypto');
      if (name === '../utils/identitybinding-fence-policy') return policy;
      if (Object.hasOwn(modules, name)) return modules[name];
      throw new Error('Unexpected runtime dependency: ' + name);
    }
  };
  vm.runInNewContext(fs.readFileSync(servicePath, 'utf8'), sandbox, {
    filename: servicePath, timeout: 1000
  });
  return module.exports;
}

function simulate(binding) {
  const service = loadService();
  const effects = [];
  const ctx = {
    params: { canonicalAccountId: 'https://paper.example.org/users/alice', webId: 'https://paper.example.org/users/alice' },
    call: async name => {
      effects.push(name);
      if (name === 'ldp.resource.exist') return true;
      throw new Error('Side effect or unexpected lookup should never occur: ' + name);
    }
  };
  const thisService = {
    _resolveBindingLocation: async () => ({
      resourceUri: 'https://paper.example.org/users/alice/identity-bindings/atproto-abc',
      bindingWebId: ctx.params.webId,
      slug: 'atproto-abc'
    }),
    _getBindingResourceOrNull: async () => binding,
    _assertUnfencedMutation: service.methods._assertUnfencedMutation,
    _readField: service.methods._readField,
    actions: {
      put: async () => { effects.push('put'); },
      post: async () => { effects.push('post'); },
      delete: async () => { effects.push('delete'); }
    }
  };
  return { service, ctx, thisService, effects };
}

const FENCED = {
  '@id': 'https://paper.example.org/users/alice/identity-bindings/atproto-abc',
  'http://activitypods.org/ns/core#repoProjectionFence': { '@value': '8' }
};

test('real identitybindings.upsert handler rejects fenced resource before any LDP write', async () => {
  const { service, ctx, thisService, effects } = simulate(FENCED);
  await assert.rejects(
    service.actions.upsert.handler.call(thisService, ctx),
    err => err instanceof MoleculerError &&
      err.code === 409 && err.type === 'IDENTITY_BINDING_FENCED_LEGACY_MUTATION_FORBIDDEN'
  );
  assert.deepEqual(effects, []);
});

test('real identitybindings.remove handler rejects fenced resource before deletion', async () => {
  const { service, ctx, thisService, effects } = simulate(FENCED);
  await assert.rejects(
    service.actions.remove.handler.call(thisService, ctx),
    err => err instanceof MoleculerError &&
      err.code === 409 && err.type === 'IDENTITY_BINDING_FENCED_LEGACY_MUTATION_FORBIDDEN'
  );
  assert.deepEqual(effects, ['ldp.resource.exist']);
});

test('real identitybindings.remove handler rejects a missing resource after exist=true', async () => {
  const { service, ctx, thisService, effects } = simulate(null);
  await assert.rejects(
    service.actions.remove.handler.call(thisService, ctx),
    err => err instanceof MoleculerError &&
      err.code === 409 && err.type === 'IDENTITY_BINDING_MUTATION_RACE'
  );
  assert.deepEqual(effects, ['ldp.resource.exist']);
});

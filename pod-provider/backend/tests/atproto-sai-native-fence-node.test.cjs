'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

class MoleculerError extends Error {
  constructor(message, code, type, data) {
    super(message);
    this.code = code;
    this.type = type;
    this.data = data;
  }
}

const backend = path.join(__dirname, '..');
function load(file, deps) {
  const module = { exports: {} };
  const source = readFileSync(file, 'utf8');
  vm.runInNewContext(source, {
    module, exports: module.exports, process, Buffer, URL, BigInt, Set,
    require(name) {
      if (Object.hasOwn(deps, name)) return deps[name];
      throw new Error('Unexpected dependency ' + name + ' in ' + file);
    }
  }, { filename: file, timeout: 3000 });
  return module.exports;
}
const account = require('../candidates/atproto-signed-repo-proof/pod-account-lookup.cjs');
const consent = require('../candidates/atproto-signed-repo-proof/pod-consent-fence.cjs');
const ownerScope = require('../services/utils/atproto-sai-owner-context');
const native = load(path.join(backend, 'services/utils/atproto-sai-native-fence.js'), {
  moleculer: { Errors: { MoleculerError } },
  './atproto-sai-owner-context': ownerScope,
  '../../candidates/atproto-signed-repo-proof/pod-account-lookup.cjs': account,
  '../../candidates/atproto-signed-repo-proof/pod-consent-fence.cjs': consent
});

const origin = 'https://paper.example.org';
const owner = origin + '/alice';
const app = origin + '/clients/paper';
const grant = owner + '/data/access-grants/ag1';
const resource = {
  'interop:grantedBy': owner,
  'interop:dataOwner': owner,
  'interop:grantee': app
};
const datasetRow = [{
  account: { value: 'urn:AuthAccount:alice' },
  username: { value: 'alice' }
}];

function setup() {
  const calls = [];
  let status = 'active';
  let revision = '1';
  let skipUpdate = false;
  let resourceAttached = true;
  const ctx = {
    params: { resource, resourceUri: grant },
    meta: { webId: owner },
    call: async (name, params, options) => {
      calls.push({ name, params, options });
      if (name === 'triplestore.query' && params.dataset === 'settings') return datasetRow;
      if (name === 'triplestore.query' && params.dataset === 'alice') {
        if (params.query.trimStart().startsWith('ASK WHERE')) return resourceAttached;
        return [{
          status: { value: status },
          revision: { value: revision },
          grant: { value: grant }
        }];
      }
      if (name === 'triplestore.update') {
        assert.equal(params.dataset, 'alice');
        assert.match(params.query, /repoConsentRevision/);
        if (!skipUpdate && status === 'active') {
          status = 'blocked'; revision = '2';
        }
        return undefined;
      }
      if (name.endsWith('.getContainerUri')) {
        return owner + '/data/' + name.split('.')[0] + '/';
      }
      if (name === 'webacl.resource.hasRights') {
        assert.equal(params.webId, owner);
        return { append: true, write: true };
      }
      throw Error('Unexpected native service action: ' + name);
    }
  };
  return {
    calls, ctx,
    setSkipUpdate(value) { skipUpdate = value; },
    setResourceAttached(value) { resourceAttached = value; },
    current() { return { status, revision }; }
  };
}

const oldEnabled = process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
const oldApps = process.env.APODS_ATPROTO_SAI_FENCED_APPS;
function env(enabled, apps = app) {
  if (enabled) {
    process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED = 'true';
    process.env.APODS_ATPROTO_SAI_FENCED_APPS = apps;
  } else {
    delete process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
    delete process.env.APODS_ATPROTO_SAI_FENCED_APPS;
  }
}
process.on('exit', () => {
  if (oldEnabled === undefined) delete process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
  else process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED = oldEnabled;
  if (oldApps === undefined) delete process.env.APODS_ATPROTO_SAI_FENCED_APPS;
  else process.env.APODS_ATPROTO_SAI_FENCED_APPS = oldApps;
});

test('feature-disabled SAI traffic adds no Moleculer or Jena calls', async () => {
  env(false);
  const { ctx, calls } = setup();
  assert.equal((await native.beforeSaiMutation(ctx, 'access-grants', resource, 'post')).checked, false);
  assert.equal(calls.length, 0);
});

test('unrelated application does not touch the repository consent dataset', async () => {
  env(true, origin + '/clients/another');
  const { ctx, calls } = setup();
  assert.equal((await native.beforeSaiMutation(ctx, 'data-authorizations', resource, 'post')).checked, false);
  assert.equal(calls.length, 0);
});

test('native grant mutation first durably blocks the exact per-user consent revision', async () => {
  env(true);
  const { ctx, calls, current } = setup();
  const result = await native.beforeSaiMutation(ctx, 'access-grants', resource, 'post');
  assert.equal(result.blocked, true);
  assert.deepEqual(current(), { status: 'blocked', revision: '2' });
  assert.deepEqual(calls.map(x => x.name), [
    'access-grants.getContainerUri',
    'webacl.resource.hasRights',
    'triplestore.query',
    'triplestore.query',
    'access-grants.getContainerUri',
    'triplestore.query',
    'triplestore.update',
    'triplestore.query'
  ]);
  assert.match(calls[2].params.query, /LIMIT 2/);
  assert.ok(calls.every(x => x.options && Number.isInteger(x.options.timeout) &&
    x.options.timeout > 0 && x.options.timeout <= 5000),
  'Each Moleculer call has a bounded timeout inside the shared operation budget');
  assert.ok(!calls.some(x => x.name.startsWith('auth.account') || x.name.includes('.list')));
  assert.ok(calls.filter(x => x.name === 'triplestore.update')
    .every(x => x.params.dataset === 'alice' && x.params.webId === 'system'));
});

test('ambiguous update success must not permit a native LDP mutation', async () => {
  env(true);
  const { ctx, calls, setSkipUpdate } = setup();
  setSkipUpdate(true);
  await assert.rejects(
    native.beforeSaiMutation(ctx, 'data-grants', resource, 'post'),
    e => e.code === 503 && e.type === 'ATPROTO_SAI_FENCE_NOT_DURABLE'
  );
  assert.equal(calls.filter(x => x.name === 'triplestore.update').length, 1);
});

test('blocked permissions remain blocked when a second native mutation arrives', async () => {
  env(true);
  const { ctx, calls } = setup();
  await native.beforeSaiMutation(ctx, 'access-authorizations', resource, 'post');
  const priorUpdates = calls.filter(x => x.name === 'triplestore.update').length;
  assert.equal((await native.beforeSaiMutation(ctx, 'data-authorizations', resource, 'post')).blocked, true);
  assert.equal(calls.filter(x => x.name === 'triplestore.update').length, priorUpdates);
});

test('missing owner, malformed app config and unauthorized grant-kind fail without write', async () => {
  env(true);
  const { ctx, calls } = setup();
  await assert.rejects(native.beforeSaiMutation(ctx, 'access-grants', {
    'interop:grantee': app
  }, 'post'), e => e.type === 'ATPROTO_SAI_FENCE_IDENTITY_INVALID');
  await assert.rejects(native.beforeSaiMutation(ctx, 'unknown', resource, 'post'),
    e => e.type === 'ATPROTO_SAI_FENCE_KIND_INVALID');
  env(true, 'not a URI');
  await assert.rejects(native.beforeSaiMutation(ctx, 'access-grants', resource, 'post'));
  assert.equal(calls.length, 0);
});

test('actual AccessGrant and DataGrant hooks use persisted pre-delete identity', async () => {
  env(true);
  const stubLdp = { ControlledContainerMixin: {} };
  for (const serviceName of ['access-grants', 'data-grants']) {
    const s = load(path.join(backend, 'services/sai/' + serviceName + '.js'), {
      '../utils/atproto-sai-native-fence': native,
      '@semapps/ldp': stubLdp
    });
    const { ctx, calls } = setup();
    ctx.params.resourceUri = owner + '/data/' + serviceName + '/r1';
    ctx.params.resource = {
      'interop:grantedBy': origin + '/attacker',
      'interop:dataOwner': origin + '/attacker',
      'interop:grantee': origin + '/attacker'
    };
    const instance = { actions: {
      get: async () => ({ ...resource, '@id': grant })
    }};
    const result = await s.hooks.before.delete.call(instance, ctx);
    assert.equal(result, undefined);
    assert.ok(calls.some(x => x.name === 'triplestore.update'));
  }
});

test('native AccessAuthorization post honors the ATProto fence even when Group bridge is off', async () => {
  env(true);
  const s = load(path.join(backend, 'services/sai/access-authorizations.js'), {
    '../utils/atproto-sai-native-fence': native,
    '../utils/collective-special-rights': { isGroupRight: () => false, onlyGroupRights: () => false },
    '@semapps/ldp': { ControlledContainerMixin: {}, arrayOf: x => Array.isArray(x) ? x : x ? [x] : [] },
    '@semapps/mime-types': { MIME_TYPES: { JSON: 'application/json' } }
  });
  const { ctx, calls } = setup();
  delete process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED;
  await s.hooks.before.post(ctx);
  assert.ok(calls.some(x => x.name === 'triplestore.update'));
});


test('an unauthorized caller cannot block consent by triggering a SAI before-hook', async () => {
  env(true);
  const { ctx, calls, current } = setup();
  ctx.meta.webId = origin + '/other-user';
  await assert.rejects(
    native.beforeSaiMutation(ctx, 'access-grants', resource, 'post'),
    e => e.code === 403 && e.type === 'ATPROTO_SAI_OWNER_REQUIRED'
  );
  assert.equal(calls.length, 0);
  assert.equal(current().status, 'active');
});

test('an app token impersonating a Pod owner is not a user approval for repository revocation', async () => {
  env(true);
  const { ctx, calls } = setup();
  ctx.meta.webId = app;
  ctx.meta.impersonatedUser = owner;
  await assert.rejects(
    native.beforeSaiMutation(ctx, 'access-grants', resource, 'delete'),
    e => e.code === 403 && e.type === 'ATPROTO_SAI_OWNER_REQUIRED'
  );
  assert.equal(calls.length, 0);
});

test('a denied WebACL permission never writes a consent revocation', async () => {
  env(true);
  const { ctx, calls } = setup();
  const actualCall = ctx.call;
  ctx.call = async (name, params) => {
    if (name === 'webacl.resource.hasRights') {
      calls.push({ name, params });
      return { write: false, append: false };
    }
    return actualCall(name, params);
  };
  await assert.rejects(
    native.beforeSaiMutation(ctx, 'access-grants', resource, 'post'),
    e => e.code === 403 && e.type === 'ATPROTO_SAI_MUTATION_NOT_ALLOWED'
  );
  assert.equal(calls.filter(x => x.name === 'triplestore.update').length, 0);
  assert.equal(calls.filter(x => x.name === 'triplestore.query').length, 0);
});

test('cross-Pod and incorrectly scoped SAI resource URIs cannot revoke a grant', async () => {
  env(true);
  const { ctx, calls } = setup();
  ctx.params.resourceUri = 'https://attacker.example.org/data/access-grants/other';
  await assert.rejects(
    native.beforeSaiMutation(ctx, 'access-grants', resource, 'delete'),
    e => e.code === 403 && e.type === 'ATPROTO_SAI_TARGET_INVALID'
  );
  assert.equal(calls.some(x => x.name === 'triplestore.update'), false);
});


test('unrelated resource in the same Pod cannot be deleted as a protected SAI authorization', async () => {
  env(true);
  const { ctx, calls, setResourceAttached } = setup();
  ctx.params.resourceUri = owner + '/data/unrelated-resource';
  setResourceAttached(false);
  await assert.rejects(
    native.beforeSaiMutation(ctx, 'access-authorizations', resource, 'delete'),
    e => e.code === 403 && e.type === 'ATPROTO_SAI_TARGET_INVALID'
  );
  assert.equal(calls.filter(x => x.name === 'triplestore.update').length, 0);
  assert.ok(calls.some(x => x.name === 'triplestore.query' &&
    x.params.query.startsWith('ASK WHERE')));
});

test('approved app changes are recognized without restarting or retaining old grants', async () => {
  env(true);
  const original = setup();
  assert.equal((await native.beforeSaiMutation(
    original.ctx, 'data-grants', resource, 'post'
  )).blocked, true);

  env(true, origin + '/clients/other');
  const later = setup();
  assert.equal((await native.beforeSaiMutation(
    later.ctx, 'data-grants', resource, 'post'
  )).checked, false);
  assert.equal(later.calls.length, 0);
});

test('duplicate, unbounded and noncanonical app allowlists fail before any broker call', async () => {
  for (const invalid of [
    app + ',' + app,
    app + '#fragment',
    app + '?debug=true',
    'x'.repeat(8200)
  ]) {
    env(true, invalid);
    const { ctx, calls } = setup();
    await assert.rejects(
      native.beforeSaiMutation(ctx, 'access-grants', resource, 'post'),
      e => e.type === 'ATPROTO_SAI_FENCE_CONFIG_INVALID'
    );
    assert.equal(calls.length, 0);
  }
});

'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const index = require('../utils/identitybinding-index-query');
const policy = require('../utils/identitybinding-fence-policy');

class MoleculerError extends Error {
  constructor(message, code, type) {
    super(message);
    this.code = code;
    this.type = type;
  }
}
function serviceModule() {
  const module = { exports: {} };
  const file = path.join(__dirname, '..', 'services', 'identitybindings.service.js');
  const imported = {
    'url-join': (...parts) => parts.join('/'),
    '@semapps/ldp': { ControlledContainerMixin: {} },
    '@semapps/mime-types': { MIME_TYPES: { JSON: 'application/json' } },
    '@semapps/triplestore': { sanitizeSparqlQuery: x => x },
    moleculer: { Errors: { MoleculerError } },
    '../utils/identitybinding-fence-policy': policy,
    '../utils/identitybinding-index-query': index
  };
  vm.runInNewContext(fs.readFileSync(file, 'utf8'), {
    module, exports: module.exports, URL, Buffer, console, process,
    require(name) {
      if (name === 'crypto') return require('node:crypto');
      if (Object.hasOwn(imported, name)) return imported[name];
      throw new Error('Unexpected require: ' + name);
    }
  }, { filename: file, timeout: 1500 });
  return module.exports;
}
const utc = '2026-11-11T11:00:00.000Z';
const id = n => 'https://paper.example.org/users/' + n;

test('only bounded server-side keyset pagination, no OFFSET or unconstrained API result', () => {
  const query = index.buildIndexPageQuery({ limit: 101 });
  assert.match(query, /LIMIT 101 \}/);
  assert.match(query, /ORDER BY STR\(\?updatedAt\) STR\(\?canonicalAccountId\)/);
  assert.doesNotMatch(query, /OFFSET|SELECT DISTINCT \?webId|LIMIT 10000/);
  assert.ok(query.indexOf('LIMIT 101') < query.indexOf('OPTIONAL { ?binding apods:webId'));
  assert.match(query, /AtprotoIdentityBindingIndex/);
  assert.throws(() => index.buildIndexPageQuery({ limit: 502 }), /Out-of-range/);
  assert.throws(() => index.buildIndexPageQuery({ limit: NaN }), /Out-of-range/);
});

test('keyset cursor is strict and cannot inject malicious SPARQL', () => {
  const q = index.buildIndexPageQuery({
    cursor: { updatedAt: utc, canonicalAccountId: id('alice') },
    limit: 2
  });
  assert.match(q, /FILTER\(STR\(\?updatedAt\) >/);
  assert.ok(q.includes(JSON.stringify(utc)));
  assert.ok(q.includes(JSON.stringify(id('alice'))));
  for (const bad of [
    { updatedAt: '2026-11-11" } UNION { ?x ?y ?z }', canonicalAccountId: id('alice') },
    { updatedAt: utc, canonicalAccountId: 'http://evil.example.org/a' },
    { updatedAt: utc, canonicalAccountId: id('alice') + '?x=1' },
    { updatedAt: utc, canonicalAccountId: 'https://evil.example.org/<inject>' }
  ]) {
    assert.throws(() => index.buildIndexPageQuery({ cursor: bad }), /Invalid/);
  }
});

test('real listing uses one bounded SPARQL request, no auth.account population fallback', async () => {
  const s = serviceModule();
  const actions = [];
  const ctx = {
    call: async (name, params) => {
      actions.push({ name, params });
      if (name !== 'triplestore.query') throw new Error('Unexpected cross-service population scan: ' + name);
      return ['a', 'b', 'c'].map(x => ({
        binding: { value: 'urn:binding:' + x },
        canonicalAccountId: { value: id(x) },
        updatedAt: { value: utc },
        atprotoDid: { value: 'did:plc:' + x.padEnd(24, 'a') }
      }));
    }
  };
  const instance = { ...s.methods, logger: { warn() {} } };
  const result = await s.methods._listBindingsWithSparql.call(instance, {
    ...ctx
  }, { since: null, limit: 2 });
  assert.equal(result.items.length, 2);
  assert.equal(result.items[0].canonicalAccountId, id('a'));
  assert.equal(actions.length, 1);
  assert.match(actions[0].params.query, /LIMIT 3 \}/);
  assert.equal(actions[0].params.dataset, 'settings');
  assert.ok(result.nextCursor);
  assert.deepEqual(
    { ...s.methods._parseCursor.call(instance, result.nextCursor) },
    { updatedAt: utc, canonicalAccountId: id('b') }
  );
});

test('index outage fails with bounded 503; indexed DID miss never enumerates accounts', async () => {
  const s = serviceModule();
  const instance = { ...s.methods, logger: { warn() {} } };
  const broken = { call: async () => { throw new Error('Jena temporarily unavailable'); } };
  await assert.rejects(
    s.methods._listBindingsWithSparql.call(instance, broken, { since: null, limit: 12 }),
    e => e.code === 503 && e.type === 'IDENTITY_BINDING_INDEX_UNAVAILABLE'
  );
  await assert.rejects(
    s.methods._findByIndexedFieldWithSparql.call(instance, broken, 'atprotoDid', 'did:plc:' + 'a'.repeat(24)),
    e => e.code === 503 && e.type === 'IDENTITY_BINDING_INDEX_UNAVAILABLE'
  );
  const getInstance = { _findByDidWithSparql: async () => null };
  assert.equal(
    await s.actions.getByDid.handler.call(getInstance, {
      params: { atprotoDid: 'did:plc:' + 'a'.repeat(24) },
      call() { throw new Error('Forbidden unbounded fallback'); }
    }),
    null
  );
});

test('oversized/invalid and untrusted page cursors fail before SPARQL', async () => {
  const s = serviceModule();
  const instance = { ...s.methods, logger: { warn() {} } };
  let calls = 0;
  const ctx = { call: async () => { calls++; return []; } };
  await assert.rejects(
    s.methods._listBindingsWithSparql.call(instance, ctx, { since: 'X'.repeat(5000), limit: 10 }),
    e => e.code === 400 && e.type === 'INVALID_CURSOR'
  );
  assert.equal(calls, 0);
});


test('terminal pages do not manufacture a cursor and malformed duplicate index pages fail', async () => {
  const s = serviceModule();
  const instance = { ...s.methods, logger: { warn() {} } };
  const row = n => ({
    binding: { value: 'urn:binding:' + n },
    canonicalAccountId: { value: id(n) },
    updatedAt: { value: utc }
  });
  let values = [row('a')];
  const ctx = { call: async () => values };
  const last = await s.methods._listBindingsWithSparql.call(instance, ctx, { since: null, limit: 2 });
  assert.equal(last.items.length, 1);
  assert.equal(last.nextCursor, null);
  values = [row('a'), row('a')];
  await assert.rejects(
    s.methods._listBindingsWithSparql.call(instance, ctx, { since: null, limit: 2 }),
    error => error.code === 503 && error.type === 'IDENTITY_BINDING_INDEX_INCONSISTENT'
  );
});

'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { test } = require('node:test');
const { resolvePlcDirectory, allowMockAtprotoIdentity } = require('../utils/atproto-plc-directory-policy');
const { submitPlcGenesis } = require('../utils/atproto-plc-submission');

test('corrupt durable identity records are retained and cannot become a fresh signup', async () => {
  const schema = require('../services/core/atproto-plc-submitter.service');
  for (const raw of ['', '{broken', 'null', '[]', 'false', '"not an object"']) {
    let deleted = false;
    await assert.rejects(schema.methods._loadJson.call({ redis: {
      get: async () => raw, del: async () => { deleted = true; }
    } }, 'private-account-key'), error => error.type === 'ATPROTO_PLC_STATE_CORRUPT' && error.data.retryable === false);
    assert.equal(deleted, false);
  }
});

test('one PLC directory is used for submission and resolution; conflicting or unsafe origins fail closed', () => {
  assert.equal(resolvePlcDirectory({}), 'https://plc.directory');
  for (const key of ['APODS_ATPROTO_PLC_DIRECTORY_URL', 'ATPROTO_PLC_DIRECTORY_URL']) {
    assert.equal(resolvePlcDirectory({ [key]: 'http://127.0.0.1:2582', NODE_ENV: 'test' }), 'http://127.0.0.1:2582');
  }
  assert.equal(resolvePlcDirectory({
    APODS_ATPROTO_PLC_DIRECTORY_URL: 'https://plc.example.org/',
    ATPROTO_PLC_DIRECTORY_URL: 'https://plc.example.org'
  }), 'https://plc.example.org');
  assert.throws(() => resolvePlcDirectory({
    APODS_ATPROTO_PLC_DIRECTORY_URL: 'https://plc.example.org',
    ATPROTO_PLC_DIRECTORY_URL: 'https://plc.directory'
  }), /disagree/);
  for (const value of ['', 'https://user:secret@plc.example.org', 'https://plc.example.org/?x=1',
    'https://plc.example.org/#fragment', 'https://plc.example.org/path', 'http://plc.example.org', 'not a URL']) {
    assert.throws(() => resolvePlcDirectory({ APODS_ATPROTO_PLC_DIRECTORY_URL: value }), /Invalid PLC directory origin/);
  }
  assert.throws(() => resolvePlcDirectory({ NODE_ENV: 'production', APODS_ATPROTO_PLC_DIRECTORY_URL: 'http://127.0.0.1:2582' }));
});

test('real PLC submission and production never allow synthetic DID fallback', () => {
  assert.equal(allowMockAtprotoIdentity({ NODE_ENV: 'test', APODS_ATPROTO_ALLOW_MOCK_IDENTITY: 'false' }), false);
  assert.equal(allowMockAtprotoIdentity({ NODE_ENV: 'test' }), true);
  for (const env of [
    { NODE_ENV: 'production', APODS_ATPROTO_ALLOW_MOCK_IDENTITY: 'true' },
    { NODE_ENV: 'test', APODS_ATPROTO_ENABLE_PLC_SUBMISSION: 'true', APODS_ATPROTO_ALLOW_MOCK_IDENTITY: 'true' }
  ]) assert.equal(allowMockAtprotoIdentity(env), false);
});

// An HTTP protocol simulator, not evidence of a real signed PLC registration.
// Real TCP bodies exercise redirects, streaming limits and abort cleanup.
test('PLC confirmation requires exact current operation readback under a single deadline', async t => {
  const op = { type: 'plc_operation', prev: null, rotationKeys: ['did:key:fixture'],
    verificationMethods: { atproto: 'did:key:fixture' }, alsoKnownAs: ['at://alice.example.org'],
    services: { atproto_pds: { type: 'AtprotoPersonalDataServer', endpoint: 'https://pds.example.org' } }, sig: 'fixture-signature' };
  const did = 'did:plc:' + 'a'.repeat(24);
  let postStatus = 200, readStatus = 200, readMode = 'match', redirected = 0;
  let posts = 0, reads = 0;
  const server = http.createServer(async (req, res) => {
    if (req.url === '/redirect-target') { redirected++; res.end('{}'); return; }
    if (req.method === 'POST') {
      posts++;
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      assert.deepEqual(JSON.parse(Buffer.concat(chunks)), op);
      res.writeHead(postStatus, postStatus === 302 ? { location: '/redirect-target' } : {});
      res.end(); return;
    }
    reads++;
    assert.equal(req.url, `/${did}/log/last`);
    res.writeHead(readStatus, { 'content-type': 'application/json' });
    if (readMode === 'stall') { res.flushHeaders(); return; }
    if (readMode === 'oversize') { res.end(' '.repeat(16385)); return; }
    if (readMode === 'invalid') { res.end('{'); return; }
    res.end(JSON.stringify(readMode === 'match' ? op : { ...op, sig: 'different-signature' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const attempt = (timeoutMs = 1000) => submitPlcGenesis({
    directory: `http://127.0.0.1:${server.address().port}`, did, signedOp: op, timeoutMs
  });
  for (const status of [200, 201, 400, 409]) {
    postStatus = status;
    assert.deepEqual(await attempt(), { kind: 'confirmed' });
  }
  readMode = 'mismatch';
  assert.deepEqual(await attempt(), { kind: 'failed', error: 'PLC_GENESIS_READBACK_MISMATCH' });
  readMode = 'match'; readStatus = 404;
  assert.equal((await attempt()).kind, 'retry');
  readStatus = 200;
  for (const mode of ['oversize', 'invalid', 'stall']) {
    readMode = mode;
    assert.equal((await attempt(mode === 'stall' ? 50 : 1000)).kind, 'retry');
  }
  readMode = 'match';
  const readsBefore = reads;
  for (const status of [302, 403, 429, 503]) {
    postStatus = status;
    const before = posts;
    assert.notEqual((await attempt()).kind, 'confirmed');
    assert.equal(posts, before + 1, 'the durable queue, not this request, owns retries');
  }
  assert.equal(reads, readsBefore);
  assert.equal(redirected, 0, 'signed operations must not follow redirects');
});

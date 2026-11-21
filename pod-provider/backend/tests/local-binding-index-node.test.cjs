'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createLocalBindingIndex } = require('../candidates/local-binding-index');

test('private binding index supports scoped writes and refuses ordinary and anonymous readers', async () => {
  const index = createLocalBindingIndex();
  assert.ok(index);
  await index.assertIsolated();
  const subject = '<urn:uuid:' + randomUUID() + '>';
  const triple = subject + ' <urn:fixture:private-index> "bound"';
  const params = { webId: 'system', dataset: 'settings' };
  const read = () => index.request('triplestore.query', {
    ...params, query: 'SELECT ?value WHERE { ' + subject + ' <urn:fixture:private-index> ?value }'
  });
  try {
    await index.request('triplestore.update', { ...params, query: 'INSERT DATA { ' + triple + ' }' });
    assert.deepEqual((await read()).map(row => row.value.value), ['bound']);
    for (const login of [undefined, 'admin:fixture-ordinary-only']) {
      const headers = { 'content-type': 'application/sparql-query' };
      if (login) headers.authorization = 'Basic ' + Buffer.from(login).toString('base64');
      const response = await fetch('http://127.0.0.1:3041/binding-index-proof/query', {
        method: 'POST', headers, body: 'ASK { ' + triple + ' }', redirect: 'error', signal: AbortSignal.timeout(3000)
      });
      await response.body?.cancel();
      assert.ok([401, 403].includes(response.status));
    }
  } finally {
    await index.request('triplestore.update', { ...params, query: 'DELETE DATA { ' + triple + ' }' });
  }
  assert.deepEqual(await read(), []);
});

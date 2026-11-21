'use strict';

const { localPodData } = require('./local-pod-data');

const origin = 'http://127.0.0.1:3041';
const path = '/binding-index-proof';
const maxBytes = 2 * 1024 * 1024;

function createLocalBindingIndex(env = process.env) {
  if (!env.PAPER_LOCAL_BROWSER_CONFIG) return undefined;
  if (!localPodData(env) || env.PAPER_LOCAL_NATIVE_AUTH !== 'confirmed' ||
      env.PAPER_LOCAL_BINDING_INDEX_PASSWORD !== 'fixture-binding-index-only') {
    throw new Error('Local binding index configuration refused');
  }
  const authorization = 'Basic ' + Buffer.from('fixture-binding-index:' + env.PAPER_LOCAL_BINDING_INDEX_PASSWORD).toString('base64');
  async function request(action, params) {
    const select = action === 'triplestore.query';
    if ((!select && action !== 'triplestore.update') || params.dataset !== 'settings' || params.webId !== 'system' ||
        typeof params.query !== 'string' || Buffer.byteLength(params.query) > 65536) throw new Error('Invalid binding index request');
    const response = await fetch(origin + path + (select ? '/query' : '/update'), {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
      headers: { authorization, 'content-type': select ? 'application/sparql-query' : 'application/sparql-update',
        accept: select ? 'application/sparql-results+json' : '*/*' }, body: params.query
    });
    try {
      if (!response.ok) throw new Error('Local binding index unavailable');
      if (!select) return;
      if (!/^application\/sparql-results\+json(?:;|$)/iu.test(response.headers.get('content-type') || '')) {
        throw new Error('Unexpected binding index result');
      }
      let size = 0;
      const parts = [];
      for await (const part of response.body) {
        size += part.byteLength;
        if (size > maxBytes) throw new Error('Binding index result exceeds limit');
        parts.push(part);
      }
      const rows = JSON.parse(Buffer.concat(parts).toString('utf8')).results?.bindings;
      if (!Array.isArray(rows)) throw new Error('Invalid binding index result');
      return rows;
    } catch { throw new Error('Local binding index operation unavailable'); }
    finally { await response.body?.cancel().catch(() => {}); }
  }
  async function assertIsolated() {
    const checks = [['/$/datasets', undefined], ['/protected-proof/query', 'ASK {}'], ['/ordinary-proof/query', 'ASK {}']];
    await Promise.all(checks.map(async ([route, body]) => {
      const response = await fetch(origin + route, {
        method: body ? 'POST' : 'GET', redirect: 'error', signal: AbortSignal.timeout(3000),
        headers: { authorization, 'content-type': 'application/sparql-query' }, body
      });
      await response.body?.cancel();
      if (response.status !== 401 && response.status !== 403) throw new Error('Local binding index credential exceeds scope');
    }));
    await request('triplestore.query', {dataset:'settings', webId:'system', query:'SELECT ?s WHERE { ?s ?p ?o } LIMIT 1'});
  }
  return Object.freeze({ request, assertIsolated });
}
module.exports = { createLocalBindingIndex };

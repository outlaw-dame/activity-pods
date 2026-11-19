'use strict';
const { assertDisposableProvider } = require('../services/utils/atproto-dataset-admin-delegation');
const origin = 'http://127.0.0.1:3041';
const claimDataset = /^claimtest-[a-z0-9]{8,24}$/u;

function localPodData(env = process.env) {
  if (env.PAPER_LOCAL_POD_DATA_PASSWORD === undefined) return undefined;
  assertDisposableProvider(env);
  if (env.SEMAPPS_SPARQL_ENDPOINT !== origin || env.SEMAPPS_JENA_USER ||
      env.PAPER_LOCAL_POD_DATA_PASSWORD !== 'fixture-ordinary-only') {
    throw new Error('Invalid disposable Pod data configuration');
  }
  const password = env.PAPER_LOCAL_POD_DATA_PASSWORD;
  const authorization = 'Basic ' + Buffer.from('admin:' + password).toString('base64');
  async function request(path, query) {
    return fetch(origin + path, {
      method: query ? 'POST' : 'GET', redirect:'error', signal:AbortSignal.timeout(2500),
      headers:{ authorization, 'content-type':'application/sparql-query', accept:'application/sparql-results+json',
        'X-SemappsUser':'system' }, body:query
    });
  }
  async function assertIsolated() {
    for (const [path, query] of [['/$/datasets'], ['/protected-proof/query','ASK {}']]) {
      const response = await request(path, query);
      await response.body?.cancel();
      if (![401,403].includes(response.status)) throw new Error('Pod data credentials exceed their scope');
    }
  }
  // SemApps normally asks the Fuseki administration API whether a dataset exists.
  // A scoped data login can establish readiness through its own SPARQL route.
  async function exists(dataset) {
    if (typeof dataset !== 'string' || !claimDataset.test(dataset)) throw new Error('Dataset outside signed signup scope');
    const response = await request('/' + dataset + '/query', 'ASK {}');
    if (response.status !== 200) {
      await response.body?.cancel();
      if (response.status === 404) return false;
      throw new Error('Pod data endpoint unavailable');
    }
    const reader = response.body.getReader();
    const parts = [];
    let size = 0;
    try {
      for (;;) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 512) throw new Error('Invalid Pod readiness response');
        parts.push(Buffer.from(value));
      }
      if (JSON.parse(Buffer.concat(parts).toString('utf8')).boolean !== true) throw new Error('Pod readiness refused');
      return true;
    } finally {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }
  return { settings:{url:origin,user:'admin',password}, assertIsolated, exists };
}
module.exports = { localPodData };

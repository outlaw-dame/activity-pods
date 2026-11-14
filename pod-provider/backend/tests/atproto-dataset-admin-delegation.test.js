'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const {
  assertDisposableProvider, validateTicket, createDelegatedDisposableDataset
} = require('../services/utils/atproto-dataset-admin-delegation');

const dataset = 'claimtest-abcdef123456';
const env = Object.freeze({
  NODE_ENV: 'test', APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE: 'confirmed',
  ATPROTO_REPO_PROOF_DISPOSABLE: 'confirmed',
  ATPROTO_FUSEKI_ISOLATION_DISPOSABLE: 'confirmed',
  FUSEKI_ISOLATION_URL: 'http://127.0.0.1:3041'
});
const now = 1794690000000;
function ticket(opts = {}) {
  return {
    claim: {
      version: 1, issuer: 'https://paper.example.org/provider',
      audience: 'urn:activitypods:dataset-admin:v1', dataset,
      ownerWebid: 'https://paper.example.org/users/' + dataset,
      reservationId: crypto.randomUUID(), nonce: crypto.randomUUID(),
      issuedAtMs: now, expiresAtMs: now + 120000, ...opts
    }, signature: 'A'.repeat(86)
  };
}
class MoleculerError extends Error {
  constructor(message, code, type, data) {
    super(message); this.code = code; this.type = type; this.data = data;
  }
}
function loadRealService(client) {
  // Compile the actual provider service action with a narrow import map.
  // This checks routing precedence and preservation of WebACL bootstrap
  // without loading a broker, Redis, Fuseki or user-account data.
  const source = fs.readFileSync(path.join(__dirname,
    '../services/core/dataset-provisioning.js'), 'utf8');
  const module = { exports: {} };
  const factory = vm.runInNewContext('(function(require, module) {\n' +
    source + '\n})', {process, Buffer, Date, URLSearchParams, console});
  factory(name => {
    if (name === 'moleculer') return {Errors: {MoleculerError}};
    if (name === 'url-join') return (...parts) => parts.join('/');
    if (name === 'node-fetch') return () => {throw Error('unexpected network')};
    if (name === '../../config/config') return {
      SPARQL_ENDPOINT: 'http://127.0.0.1:3041/',
      JENA_USER: 'admin', JENA_PASSWORD: 'fixture-admin-only'
    };
    if (name === '../utils/atproto-dataset-admin-delegation') {
      return {createDelegatedDisposableDataset: client};
    }
    throw Error('Unexpected provider import: ' + name);
  }, module);
  return module.exports;
}
async function setting(value, fn) {
  const before = process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE;
  try {
    if (value === undefined) delete process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE;
    else process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE = value;
    return await fn();
  } finally {
    if (before === undefined) delete process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE;
    else process.env.APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE = before;
  }
}
test('delegated admin cannot be enabled in production or in a process with privileged passwords', () => {
  expect(() => assertDisposableProvider(env)).not.toThrow();
  for (const changed of [
    {...env, NODE_ENV: 'production'},
    {...env, NODE_ENV: 'development'},
    {...env, APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE: 'true'},
    {...env, FUSEKI_ISOLATION_URL: 'http://another-host:3041'},
    {...env, SEMAPPS_JENA_PASSWORD: 'secret'},
    {...env, ATPROTO_REPO_PROOF_DSN: 'postgres://superuser'},
    {...env, DATASET_ADMIN_AGENT_DSN: 'postgres://restricted'},
    {...env, DATASET_ADMIN_SIGNER_PRIVATE_KEY: 'ed25519-secret'}
  ]) {
    expect(() => assertDisposableProvider(changed)).toThrow();
  }
});
test('reject malformed and mismatched ticket claims before sending any network request', async () => {
  let calls = 0;
  const fetchImpl = async () => {calls++; throw Error('should not fetch');};
  for (const bad of [
    undefined, null, {claim: {}, signature: 'A'.repeat(86)},
    {...ticket(), signature: 'invalid'},
    ticket({ownerWebid: 'https://paper.example.org/users/other'}),
    ticket({audience: 'urn:wrong'}),
    ticket({issuer: 'https://evil.example'}),
    ticket({dataset: 'claimtest-aaaaaaaaaaaa'}),
    ticket({expiresAtMs: now-1}),
    ticket({issuedAtMs: now+31000}),
    ticket({nonce: crypto.randomUUID().toUpperCase()})
  ]) {
    await expect(createDelegatedDisposableDataset({
      dataset, ticket: bad, env, fetchImpl, now
    })).rejects.toMatchObject({code: 'DATASET_ADMIN_DELEGATION_CLAIM_INVALID'});
  }
  expect(calls).toBe(0);
});
test('fixed-route request contains only the signed ticket and refuses unexpected HTTP responses', async () => {
  const t = ticket();
  const seen = [];
  const reply = (status, body) => async (url, options) => {
    seen.push({url,options});
    return new Response(body, {status});
  };
  const valid = await createDelegatedDisposableDataset({
    dataset, ticket: t, env, now,
    fetchImpl: reply(200, JSON.stringify({created:true,idempotent:false}))
  });
  expect(valid).toEqual({
    dataset, created:true, idempotent:false,
    strategy:'isolated_claim_admin_disposable'
  });
  expect(seen[0].url).toBe('http://127.0.0.1:3042/v1/provision');
  expect(seen[0].options.method).toBe('POST');
  expect(seen[0].options.redirect).toBe('manual');
  expect(seen[0].options.headers).toEqual({'content-type': 'application/json'});
  expect(JSON.parse(seen[0].options.body)).toEqual({ticket:t});
  for (const [status, body, expectedCode] of [
    [409,'{}','DATASET_ADMIN_DELEGATION_CONFLICT'],
    [403,'{}','DATASET_ADMIN_DELEGATION_REJECTED'],
    [503,'{}','DATASET_ADMIN_DELEGATION_UNAVAILABLE'],
    [302,'{}','DATASET_ADMIN_DELEGATION_UNAVAILABLE'],
    [200,'{}','DATASET_ADMIN_DELEGATION_RESPONSE_INVALID'],
    [200,'not json','DATASET_ADMIN_DELEGATION_RESPONSE_INVALID'],
    [200,JSON.stringify({created:true,idempotent:false,adminSecret:'leak'}),'DATASET_ADMIN_DELEGATION_RESPONSE_INVALID'],
    [200,'x'.repeat(513),'DATASET_ADMIN_DELEGATION_RESPONSE_TOO_LARGE']
  ]) {
    await expect(createDelegatedDisposableDataset({
      dataset,ticket:t,env,now,fetchImpl:reply(status,body)
    })).rejects.toMatchObject({code: expectedCode});
  }
});
test('real Moleculer dataset service delegates before any existence or privileged creation path', async () => {
  const observed = [];
  const t = ticket();
  const delegated = jest.fn().mockResolvedValue({
    dataset,created:true,idempotent:false,strategy:'isolated_claim_admin_disposable'
  });
  const service = loadRealService(delegated);
  const ctx = {
    params:{dataset,datasetAdminTicket:t},meta:{unrelated:'preserve'} ,
    call:jest.fn(async (action, args, opts) => {
      observed.push({action,args,opts});
      if (action !== 'triplestore.dataset.waitForCreation') throw Error('Unexpected action');
    })
  };
  const state = {ensureSemappsNamedGraphs:jest.fn(async () => {})};
  await setting('confirmed', async () => {
    expect(await service.actions.ensureSecureDataset.handler.call(state,ctx)).toEqual({
      dataset,created:true,strategy:'isolated_claim_admin_disposable'
    });
  });
  expect(delegated).toHaveBeenCalledWith({dataset,ticket:t});
  expect(observed.map(x=>x.action)).toEqual(['triplestore.dataset.waitForCreation']);
  expect(ctx.meta).toEqual({unrelated:'preserve'});
  expect(observed[0].args).toEqual({dataset});
  expect(Object.hasOwn(observed[0].opts,'meta')).toBe(false);
  expect(observed[0].opts.timeout).toBe(5000);
  expect(state.ensureSemappsNamedGraphs).toHaveBeenCalledWith(ctx,dataset);
});
test('no ticket means refusal and no fallback to legacy or an existing dataset', async () => {
  const client = jest.fn(async () => {throw Error('unsigned or unissued claim');});
  const service=loadRealService(client);
  const ctx={params:{dataset},meta:{atprotoDatasetTicket:ticket()},call:jest.fn()};
  await setting('confirmed',async()=>{
    await expect(service.actions.ensureSecureDataset.handler.call({
      ensureSemappsNamedGraphs:jest.fn()
    },ctx)).rejects.toThrow(/unsigned or unissued/);
  });
  expect(client).toHaveBeenCalledWith({dataset,ticket:undefined});
  expect(ctx.meta.atprotoDatasetTicket).toBeDefined();
  expect(ctx.call).not.toHaveBeenCalled();
});
test('without the disposable switch, existing storage and SemApps behavior is unchanged', async () => {
  const client=jest.fn();
  const service=loadRealService(client);
  const ctx={
    params:{dataset:'ordinary-user'},
    call:jest.fn(async action=>action==='triplestore.dataset.exist')
  };
  const state={ensureSemappsNamedGraphs:jest.fn(async()=>{})};
  await setting(undefined,async()=>{
    expect(await service.actions.ensureSecureDataset.handler.call(state,ctx)).toEqual({
      dataset:'ordinary-user',created:false,strategy:'already_exists'
    });
  });
  expect(client).not.toHaveBeenCalled();
  expect(ctx.call).toHaveBeenCalledWith('triplestore.dataset.exist',{dataset:'ordinary-user'});
  expect(state.ensureSemappsNamedGraphs).toHaveBeenCalled();
});

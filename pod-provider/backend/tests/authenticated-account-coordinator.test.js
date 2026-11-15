'use strict';

const crypto=require('node:crypto');
const {ServiceBroker}=require('moleculer');
const api=require('../services/unified-account-api.service');
const provider=require('../services/provider-capabilities.service');
const accounts=require('../services/accounts.service');
const wire=require('../services/utils/atproto-account-coordinator-client');

const APP='https://app.paper.example/atlas';
const ORIGIN='https://app.paper.example';
const REDIRECT='https://app.paper.example/callback';
const USER='claimtest-aabbccddeeff';
const AUTH='app-bearer-secret-abcdefgh';
const VERIFY='verification-token-abcdefgh';
const KEY='durable-key-001';
const PWD='correct-horse-account-password';
const FIXTURE_FLAGS={
  NODE_ENV:'test',
  ATPROTO_REPO_PROOF_DISPOSABLE:'confirmed',
  ATPROTO_FUSEKI_ISOLATION_DISPOSABLE:'confirmed',
  FUSEKI_ISOLATION_URL:'http://127.0.0.1:3041',
  APODS_ACCOUNT_RESERVATION_DISPOSABLE:'confirmed',
  APODS_ACCOUNT_COORDINATOR_DISPOSABLE:'confirmed',
  APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE:'confirmed'
};
function ticket(){
  const now=Date.now();
  return {
    claim:{
      version:1,issuer:'https://paper.example.org/provider',
      audience:'urn:activitypods:dataset-admin:v1',
      dataset:USER,
      ownerWebid:'https://paper.example.org/users/'+USER,
      reservationId:crypto.randomUUID(),
      nonce:crypto.randomUUID(),
      issuedAtMs:now-1000,expiresAtMs:now+100000
    },
    signature:'A'.repeat(86)
  };
}
function app(overrides={}){
  return {
    clientId:APP,bearerTokens:[AUTH],verificationTokens:[VERIFY],
    allowedOrigins:[ORIGIN],allowedRedirectUris:[REDIRECT],
    allowAtproto:true,allowUnsigned:false,maxAccountsPerDay:3,
    ...overrides
  };
}
function issueSignedChallenge(params){
  const helper=require('../services/utils/atproto-account-coordinated-signup');
  const normalized=api.methods.normalizeAccountCreateParams.call(
    api.methods,params);
  const protocols=api.methods.requestedProtocolsFromAccountParams.call(
    api.methods,normalized);
  const fp=helper.fingerprint({
    api:api.methods,appClientId:params.appClientId,
    redirectUri:params.redirectUri,accountParams:normalized,
    protocols,env:process.env
  });
  const now=Date.now();
  const payload={
    version:1,purpose:'activitypods:new-account:v1',
    appClientId:params.appClientId,username:params.username,
    email:params.email||'',origin:ORIGIN,
    redirectUri:params.redirectUri,idempotencyKey:params.idempotencyKey,
    requestFingerprint:fp,
    issuedAtMs:now,expiresAtMs:now+60000,
    nonce:crypto.randomUUID()
  };
  const data=Buffer.from(JSON.stringify(payload),'utf8').toString('base64url');
  const signature=crypto.createHmac('sha256',
    Buffer.from(process.env.APODS_ACCOUNT_VERIFICATION_HMAC_KEY,'base64url'))
    .update('activitypods:durable-user-verification:v1\0')
    .update(data).digest('base64url');
  return data+'.'+signature;
}
function request(overrides={}){
  const params={
    appClientId:APP,redirectUri:REDIRECT,
    idempotencyKey:KEY,
    username:USER,email:'new-account@example.net',password:PWD,
    profile:{displayName:'A new account'},
    ...overrides
  };
  if(!Object.hasOwn(overrides,'verification')){
    params.verification={method:'provider-signed',
      challengeToken:issueSignedChallenge(params)};
  }
  return params;
}
function headers(overrides={}){
  return {
    authorization:'Bearer '+AUTH,origin:ORIGIN,
    'idempotency-key':KEY,
    ...overrides
  };
}
let priorEnv;
const KEYS=[...Object.keys(FIXTURE_FLAGS),
  'APODS_ACCOUNT_COORDINATOR_SHARED_KEY','APODS_ACCOUNT_REQUEST_FINGERPRINT_KEY',
  'APODS_ACCOUNT_VERIFICATION_HMAC_KEY'];
beforeEach(()=>{
  priorEnv=Object.fromEntries(KEYS.map(k=>[k,process.env[k]]));
  for(const [k,v] of Object.entries(FIXTURE_FLAGS))process.env[k]=v;
  process.env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY=
    crypto.randomBytes(32).toString('base64url');
  process.env.APODS_ACCOUNT_REQUEST_FINGERPRINT_KEY=
    crypto.randomBytes(32).toString('base64url');
  process.env.APODS_ACCOUNT_VERIFICATION_HMAC_KEY=
    crypto.randomBytes(32).toString('base64url');
});
afterEach(()=>{
  for(const k of KEYS){
    if(priorEnv[k]===undefined)delete process.env[k];
    else process.env[k]=priorEnv[k];
  }
});

async function setup({appConfig=app(), onCreate=()=>({webId:'synthetic'})}={}){
  const broker=new ServiceBroker({logger:false});
  const addRoute=jest.fn(()=>true);
  const create=jest.fn(onCreate);
  broker.createService({name:'api',actions:{addRoute}});
  broker.createService({
    ...provider,
    settings:{
      ...provider.settings,
      accountProvisioningEnabled:true,
      atprotoEnabled:true,requiresApprovedApps:true,
      requiresUserVerification:true,requireBearerToken:true,
      allowTrustedVerification:false,approvedApps:[appConfig],
      verificationTokens:[],verificationSecret:''
    }
  });
  broker.createService({name:'unified-account',actions:{create}});
  broker.createService(api);
  await broker.start();
  return{broker,create};
}
function makeFetch({status=200, ticketValue=ticket()}={}){
  return jest.fn(async(url,options)=>{
    expect(url).toBe('http://127.0.0.1:3043/v1/reserve');
    expect(options.method).toBe('POST');
    expect(options.redirect).toBe('manual');
    expect(options.headers['content-type']).toBe('application/json');
    expect(wire.verifyMac(process.env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
      'client',options.body,options.headers['x-paper-auth'])).toBe(true);
    const body=JSON.parse(options.body);
    wire.validateMessage(body);
    expect(body.username).toBe(USER);
    expect(body).not.toHaveProperty('password');
    expect(body).not.toHaveProperty('authorization');
    expect(body).not.toHaveProperty('verification');
    const admission={
      appScope:body.appScope,
      username:body.username,
      idempotencyKey:body.idempotencyKey,
      requestFingerprint:body.requestFingerprint,
      reservationId:ticketValue.claim.reservationId
    };
    const raw=JSON.stringify({ticket:ticketValue,admission});
    const signed=wire.computeMac(process.env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
      'worker-response',raw);
    return new Response(status===200?raw:JSON.stringify({error:'denied'}),{
      status,headers:{'content-type':'application/json','x-paper-auth':signed}
    });
  });
}
test('real API authorizes approved app and user, calls coordinator, forwards only ticket, and refuses 201 without attestation',async()=>{
  const f=makeFetch(),orig=global.fetch;
  global.fetch=f;
  const {broker,create}=await setup();
  try{
    await expect(broker.call('unified-account-api.create',request(),{
      meta:{$headers:headers(),untrusted:'external-data'}
    })).rejects.toMatchObject({
      type:'ACCOUNT_COMPLETION_ATTESTATION_PENDING',
      code:503,data:{retryable:false}
    });
    expect(f).toHaveBeenCalledTimes(1);
    expect(create).toHaveBeenCalledTimes(1);
    const call=create.mock.calls[0][0];
    const params=call.params, meta=call.meta;
    expect(params.datasetAdminTicket.claim.dataset).toBe(USER);
    expect(params.accountCoordinatorAdmission.reservationId)
      .toBe(params.datasetAdminTicket.claim.reservationId);
    expect(params.password).toBe(PWD);
    expect(params.accountProvisioning).toBeUndefined();
    expect(meta.accountProvisioning).toMatchObject({
      allowed:true,approvedApp:true,verifiedUser:true,
      appClientId:APP,username:USER
    });
    expect(meta.$headers).toBeUndefined();
    expect(meta.untrusted).toBeUndefined();
    expect(JSON.stringify(meta)).not.toContain(AUTH);
    expect(JSON.stringify(meta)).not.toContain(VERIFY);
    expect(JSON.stringify(meta)).not.toContain('signature');
    expect(JSON.stringify(meta)).not.toContain(PWD);
    expect(JSON.stringify(meta)).not.toContain('fenceToken');
    expect(JSON.stringify(meta)).not.toContain('accountCoordinatorAdmission');
  }finally{await broker.stop();global.fetch=orig;}
});
test('wrong app credentials, missing origin, redirect mismatch and user verification shortcut cannot reserve',async()=>{
  const f=makeFetch(),orig=global.fetch;global.fetch=f;
  const {broker,create}=await setup();
  try{
    for(const [payload,hdr] of [
      [request(),headers({authorization:'Bearer wrong-app-token'})],
      [request(),headers({origin:''})],
      [request({redirectUri:'https://malicious.example/return'}),headers()],
      [request({verification:{verified:true}}),headers()],
      [request({verification:{method:'app'}}),headers()],
      [request({verification:{method:'app',challengeToken:VERIFY}}),headers()],
      [request({
        idempotencyKey:'durable-key-other',
        verification:request().verification
      }),headers()],
      [request({username:'Claimtest-noncanonical'}),headers()]
    ]){
      await expect(broker.call('unified-account-api.create',payload,
        {meta:{$headers:hdr}})).rejects.toMatchObject({
        code:expect.any(Number)
      });
    }
    expect(f).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  }finally{await broker.stop();global.fetch=orig;}
});
test('an external ticket, fence or grant is rejected without authorizing or contacting the coordinator',async()=>{
  const f=makeFetch(),orig=global.fetch;global.fetch=f;
  const {broker,create}=await setup();
  try{
    for(const injected of [
      {datasetAdminTicket:ticket()},
      {accountProvisioning:{allowed:true}},
      {fenceToken:crypto.randomUUID()},
      {reservationId:crypto.randomUUID()},
      {requestFingerprint:'a'.repeat(64)}
    ]){
      await expect(broker.call('unified-account-api.create',
        request(injected),{meta:{$headers:headers()}}))
        .rejects.toMatchObject({
          code:400,type:'ACCOUNT_COORDINATOR_INPUT_DENIED'
        });
    }
    expect(f).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  }finally{await broker.stop();global.fetch=orig;}
});
test('lost coordinator acknowledgement and second worker conflict never create another identity',async()=>{
  const orig=global.fetch;
  const f=makeFetch({status:409});
  global.fetch=f;
  const {broker,create}=await setup();
  try{
    await expect(broker.call('unified-account-api.create',request(),{
      meta:{$headers:headers()}
    })).rejects.toMatchObject({
      type:'ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED',code:409
    });
    expect(create).not.toHaveBeenCalled();
    expect(f).toHaveBeenCalledTimes(1);
    const resultError=makeFetch({status:503});
    global.fetch=resultError;
    await expect(broker.call('unified-account-api.create',
      request(),{meta:{$headers:headers()}})).rejects.toMatchObject({
        type:'ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED',
        code:503
      });
    expect(create).not.toHaveBeenCalled();
  }finally{await broker.stop();global.fetch=orig;}
});
test('a caller-supplied, unkeyed SHA-256 request hash is not used for durable password fingerprints',async()=>{
  const f=makeFetch(),orig=global.fetch;global.fetch=f;
  const {broker}=await setup();
  try{
    await expect(broker.call('unified-account-api.create',request(),{
      meta:{$headers:headers()}
    })).rejects.toMatchObject({code:503});
    const msg=JSON.parse(f.mock.calls[0][1].body);
    expect(msg.requestFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(msg.requestFingerprint).not.toBe(
      crypto.createHash('sha256').update(PWD).digest('hex'));
    expect(JSON.stringify(msg)).not.toContain(PWD);
  }finally{await broker.stop();global.fetch=orig;}
});
test('real accounts adapter forwards signed ticket to auth.signup but not account profile or returned data',async()=>{
  const seen=jest.fn();
  const broker=new ServiceBroker({logger:false});
  broker.createService({name:'auth',actions:{
    signup:seen.mockImplementation(async()=>({
      webId:'https://paper.example.org/users/'+USER,
      activityPubActorId:'https://paper.example.org/users/'+USER,
      atprotoDid:'did:plc:'+'a'.repeat(24),
      atprotoRepoInitialized:true
    }))
  }});
  broker.createService({name:'auth.account',actions:{
    findByUsername:()=>null,
    findByWebId:()=>({createdAt:new Date(0).toISOString()})
  }});
  broker.createService(accounts);
  await broker.start();
  try{
    const signed=ticket();
    const result=await broker.call('accounts.create',{
      username:USER,email:'new-account@example.net',password:PWD,
      profile:{displayName:'A new account'},
      datasetAdminTicket:signed,
      accountCoordinatorAdmission:{
        appScope:'a'.repeat(64),username:USER,
        idempotencyKey:KEY,
        requestFingerprint:'b'.repeat(64),
        reservationId:signed.claim.reservationId
      }
    });
    expect(seen).toHaveBeenCalledTimes(1);
    const forwarded=seen.mock.calls[0][0].params;
    expect(forwarded.datasetAdminTicket).toEqual(signed);
    expect(forwarded.accountCoordinatorAdmission.reservationId)
      .toBe(signed.claim.reservationId);
    expect(forwarded.password).toBe(PWD);
    expect(forwarded.name).toBe('A new account');
    expect(JSON.stringify(result)).not.toContain('signature');
    expect(JSON.stringify(result)).not.toContain(KEY);
    expect(JSON.stringify(result)).not.toContain(PWD);
  }finally{await broker.stop();}
});
test('the production guard cannot be bypassed by disposable coordinator flags',async()=>{
  const previous=process.env.NODE_ENV;
  process.env.NODE_ENV='production';
  const f=makeFetch(),orig=global.fetch;global.fetch=f;
  const {broker,create}=await setup();
  try{
    await expect(broker.call('unified-account-api.create',request(),{
      meta:{$headers:headers()}
    })).rejects.toMatchObject({
      type:'UNIFIED_ACCOUNT_RELEASE_GATE_CLOSED',code:503
    });
    expect(create).not.toHaveBeenCalled();
    expect(f).not.toHaveBeenCalled();
  }finally{
    await broker.stop();global.fetch=orig;
    process.env.NODE_ENV=previous;
  }
});

test('one-time invocation verifies bound ticket and MAC response, and refuses consumed or forged claims',async()=>{
  const signed=ticket();
  const admission={
    appScope:'a'.repeat(64),
    username:USER,
    idempotencyKey:KEY,
    requestFingerprint:'b'.repeat(64),
    reservationId:signed.claim.reservationId
  };
  const env={...FIXTURE_FLAGS,
    APODS_ACCOUNT_COORDINATOR_SHARED_KEY:
      process.env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY};
  const calls=[];
  const fetchImpl=async(url,options)=>{
    calls.push({url,options});
    expect(url).toBe('http://127.0.0.1:3043/v1/consume');
    expect(options.method).toBe('POST');
    expect(options.redirect).toBe('manual');
    expect(wire.verifyMac(env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
      'consume',options.body,options.headers['x-paper-auth'])).toBe(true);
    const msg=JSON.parse(options.body);
    expect(msg.ticket).toEqual(signed);
    expect(msg.reservationId).toBe(admission.reservationId);
    expect(msg).not.toHaveProperty('password');
    expect(msg).not.toHaveProperty('appBearer');
    const raw=JSON.stringify({admitted:true});
    return new Response(raw,{status:200,headers:{
      'x-paper-auth':wire.computeMac(
        env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
        'consume-response',raw)
    }});
  };
  const admitted=await wire.consumeCoordinatedSignup({
    ticket:signed,admission,dataset:USER,env,fetchImpl
  });
  expect(admitted).toEqual({admitted:true});
  expect(calls).toHaveLength(1);
  for(const bad of [
    {...admission,reservationId:crypto.randomUUID()},
    {...admission,username:'claimtest-other000000'},
    {...admission,requestFingerprint:'not-a-fingerprint'}
  ]){
    await expect(wire.consumeCoordinatedSignup({
      ticket:signed,admission:bad,dataset:USER,env,fetchImpl
    })).rejects.toMatchObject({code:'ACCOUNT_COORDINATOR_INVOCATION_INVALID'});
  }
  expect(calls).toHaveLength(1);
  await expect(wire.consumeCoordinatedSignup({
    ticket:signed,admission,dataset:USER,env,
    fetchImpl:async()=>new Response('{"error":"denied"}',{status:409})
  })).rejects.toMatchObject({
    code:'ACCOUNT_COORDINATOR_INVOCATION_ALREADY_CLAIMED'
  });
  await expect(wire.consumeCoordinatedSignup({
    ticket:signed,admission,dataset:USER,env,
    fetchImpl:async()=>new Response(JSON.stringify({admitted:true}),{
      status:200,headers:{'x-paper-auth':'A'.repeat(43)}
    })
  })).rejects.toMatchObject({
    code:'ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED'
  });
});

'use strict';

const crypto=require('node:crypto');
const {ServiceBroker}=require('moleculer');
const ApiGateway=require('moleculer-web');
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
      ownerWebid:'https://paper.example.org/'+USER,
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

async function setup({appConfig=app(), onCreate=()=>({webId:'synthetic'}), beginEnrollment, browserTransaction}={}){
  const broker=new ServiceBroker({logger:false});
  const addRoute=jest.fn(()=>true);
  const create=jest.fn(onCreate);
  const gateway = beginEnrollment
    ? broker.createService({ mixins: [ApiGateway], settings: {
      port: 0, ip: '127.0.0.1', routes: [], log4XXResponses: false, logRequest: null, logResponse: null
    } })
    : broker.createService({name:'api',actions:{addRoute}});
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
  broker.createService(beginEnrollment ? { ...api, created() { this.localBrowserSignupTransaction = browserTransaction; }, methods: { ...api.methods, beginDisposableEnrollment: beginEnrollment } } : api);
  await broker.start();
  return{broker,create,gateway};
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
    const raw=JSON.stringify({
      ticket:ticketValue,admission,
      requestSha256:crypto.createHash('sha256')
        .update(options.body,'utf8').digest('hex'),
      nonce:body.nonce
    });
    const signed=wire.computeMac(process.env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
      'worker-response',raw);
    return new Response(status===200?raw:JSON.stringify({error:'denied'}),{
      status,headers:{'content-type':'application/json','x-paper-auth':signed}
    });
  });
}
test('signup HTTP response carries a pending session cookie only for a matching provider result', async () => {
  const ticketValue = ticket();
  const webId = ticketValue.claim.ownerWebid;
  const reserve = makeFetch({ ticketValue });
  const original = global.fetch;
  const cookie = '__Host-paper-enrollment=test-session; Path=/; Secure; HttpOnly; SameSite=Strict';
  let correctActor = true;
  const beginEnrollment = jest.fn(async ({ setCookie }) => {
    setCookie(cookie);
    return { state: 'awaiting_consent', csrfToken: 'private-to-view' };
  });
  const { broker, gateway } = await setup({ beginEnrollment, onCreate: () => ({
    canonicalAccountId: webId, webId, solid: { webId },
    activitypub: { actorId: correctActor ? webId : webId + '-other' },
    atproto: { repoInitialized: true }
  }) });
  global.fetch = reserve;
  try {
    const endpoint = 'http://127.0.0.1:' + gateway.server.address().port + '/api/accounts/create';
    const submit = () => original(endpoint, {
      method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
      body: JSON.stringify(request())
    });
    const pending = await submit();
    expect(pending.status).toBe(202);
    expect(pending.headers.get('set-cookie')).toBe(cookie);
    expect(pending.headers.get('cache-control')).toBe('no-store');
    expect(await pending.json()).toEqual({ state: 'awaiting_consent' });
    expect(beginEnrollment).toHaveBeenCalledWith({
      reservationId: ticketValue.claim.reservationId, appClientId: APP, redirectUri: REDIRECT,
      username: USER, webId, setCookie: expect.any(Function)
    });
    correctActor = false;
    const mismatched = await submit();
    expect(mismatched.status).toBe(503);
    expect(mismatched.headers.get('set-cookie')).toBeNull();
    expect(beginEnrollment).toHaveBeenCalledTimes(1);
  } finally {
    global.fetch = original;
    await broker.stop();
  }
});

test('browser posts account fields and a private session cookie without app credentials', async () => {
  const ticketValue = ticket(), webId = ticketValue.claim.ownerWebid;
  const original = global.fetch;
  const signed = request();
  const consume = jest.fn(async ({ cookie, origin, fingerprint }) => {
    expect(cookie).toBe('__Host-paper-signup=private-browser-session');
    expect(origin).toBe(ORIGIN);
    expect(fingerprint).toBe(JSON.parse(Buffer.from(signed.verification.challengeToken.split('.')[0], 'base64url')).requestFingerprint);
    return { idempotencyKey: KEY, challengeToken: signed.verification.challengeToken };
  });
  const { broker, gateway, create } = await setup({
    beginEnrollment: async ({ setCookie }) => { setCookie('__Host-paper-enrollment=issued; Secure; HttpOnly; Path=/'); return { state: 'awaiting_consent' }; },
    browserTransaction: { appClientId: APP, redirectUri: REDIRECT, bearer: AUTH, consume },
    onCreate: () => ({ canonicalAccountId: webId, webId, solid: { webId }, activitypub: { actorId: webId }, atproto: { repoInitialized: true } })
  });
  global.fetch = makeFetch({ ticketValue });
  try {
    const endpoint = 'http://127.0.0.1:' + gateway.server.address().port + '/api/accounts/create';
    const submit = extra => original(endpoint, { method: 'POST', headers: {
      'content-type':'application/json', origin:ORIGIN, cookie:'__Host-paper-signup=private-browser-session'
    }, body:JSON.stringify({ browserSignupTransaction:true, username:signed.username, email:signed.email,
      password:signed.password, profile:signed.profile, ...extra }) });
    expect((await submit({ appClientId:APP })).status).toBe(400);
    expect(consume).not.toHaveBeenCalled();
    const response = await submit({});
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({ state:'awaiting_consent' });
    expect(create).toHaveBeenCalledTimes(1);
    consume.mockRejectedValueOnce(new Error('already consumed'));
    expect((await submit({})).status).toBe(403);
    expect(create).toHaveBeenCalledTimes(1);
  } finally { global.fetch = original; await broker.stop(); }
});

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
    for(const [caseName,payload,hdr] of [
      ['wrong-app-bearer',request(),headers({authorization:'Bearer wrong-app-token'})],
      ['missing-origin',request(),headers({origin:''})],
      ['redirect-not-allowed',request({redirectUri:'https://malicious.example/return'}),headers()],
      ['trusted-boolean-only',request({verification:{verified:true}}),headers()],
      ['missing-challenge',request({verification:{method:'app'}}),headers()],
      ['reusable-static-challenge',request({verification:{method:'app',challengeToken:VERIFY}}),headers()],
      ['wrong-idempotency-binding',request({
        idempotencyKey:'durable-key-other',
        verification:request().verification
      }),headers()],
      ['noncanonical-username',request({username:'Claimtest-noncanonical'}),headers()]
    ]){
      const callsBefore=f.mock.calls.length;
      await expect(broker.call('unified-account-api.create',payload,
        {meta:{$headers:hdr}})).rejects.toMatchObject({
        code:expect.any(Number)
      });
      if(f.mock.calls.length!==callsBefore){
        throw Error('Invalid credential case contacted coordinator: '+caseName);
      }
    }
    expect(f).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  }finally{await broker.stop();global.fetch=orig;}
});
test('conflicting header and body idempotency keys are refused before coordinator admission',async()=>{
  const f=makeFetch(),original=global.fetch;
  global.fetch=f;
  const{broker,create}=await setup();
  try{
    await expect(broker.call('unified-account-api.create',
      request({idempotencyKey:'different-durable-key'}),
      {meta:{$headers:headers()}})).rejects.toMatchObject({
      code:400,type:'ACCOUNT_COORDINATOR_IDEMPOTENCY_SCOPE_CONFLICT',
      data:{retryable:false}
    });
    expect(f).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  }finally{await broker.stop();global.fetch=original;}
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
test('a captured, correctly MACed reservation response cannot be reused for another request nonce',async()=>{
  const actualFetch=makeFetch();
  let recorded=null;
  const capture=async(url,options)=>{
    const reply=await actualFetch(url,options);
    recorded={
      raw:await reply.text(),
      mac:reply.headers.get('x-paper-auth'),
      request:options.body
    };
    return new Response(recorded.raw,{status:200,headers:{
      'x-paper-auth':recorded.mac
    }});
  };
  const grant={
    allowed:true,approvedApp:true,verifiedUser:true,
    capabilityId:'provider.account.provisioning',
    appClientId:APP,username:USER,
    idempotencyKey:KEY,requestFingerprint:'a'.repeat(64),
    dailyLimit:3
  };
  const env={...FIXTURE_FLAGS,
    APODS_ACCOUNT_COORDINATOR_SHARED_KEY:
      process.env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY
  };
  const first=await wire.reserveCoordinatedDataset({
    grant,username:USER,appClientId:APP,env,fetchImpl:capture
  });
  expect(first.ticket.claim.dataset).toBe(USER);
  let nextRequest=null;
  await expect(wire.reserveCoordinatedDataset({
    grant,username:USER,appClientId:APP,env,
    fetchImpl:async(_url,options)=>{
      nextRequest=options.body;
      return new Response(recorded.raw,{status:200,headers:{
        'x-paper-auth':recorded.mac
      }});
    }
  })).rejects.toMatchObject({
    code:'ACCOUNT_COORDINATOR_RESPONSE_INVALID'
  });
  expect(nextRequest).not.toBe(recorded.request);
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
      webId:'https://paper.example.org/'+USER,
      activityPubActorId:'https://paper.example.org/'+USER,
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
  let previouslySigned;
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
    const raw=JSON.stringify({
      admitted:true,
      requestSha256:crypto.createHash('sha256')
        .update(options.body,'utf8').digest('hex'),
      reservationId:msg.reservationId,
      nonce:msg.nonce
    });
    const mac=wire.computeMac(env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
      'consume-response',raw);
    previouslySigned={raw,mac,request:options.body};
    return new Response(raw,{status:200,headers:{'x-paper-auth':mac}});
  };
  const admitted=await wire.consumeCoordinatedSignup({
    ticket:signed,admission,dataset:USER,env,fetchImpl
  });
  expect(admitted).toEqual({admitted:true});
  expect(calls).toHaveLength(1);
  // Replay a cryptographically valid, prior HTTP 200 response. A previous
  // request cannot be used to acknowledge a different nonce or scope.
  const captured=previouslySigned;
  let replayRequest=null;
  await expect(wire.consumeCoordinatedSignup({
    ticket:signed,admission,dataset:USER,env,
    fetchImpl:async(_url,options)=>{
      replayRequest=options.body;
      return new Response(captured.raw,{status:200,headers:{
        'x-paper-auth':captured.mac
      }});
    }
  })).rejects.toMatchObject({
    code:'ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED'
  });
  expect(replayRequest).not.toBe(captured.request);
  const forgedButSigned=JSON.stringify({
    admitted:true,
    requestSha256:crypto.createHash('sha256')
      .update(captured.request).digest('hex'),
    reservationId:crypto.randomUUID(),
    nonce:JSON.parse(captured.request).nonce
  });
  await expect(wire.consumeCoordinatedSignup({
    ticket:signed,admission,dataset:USER,env,
    fetchImpl:async()=>new Response(forgedButSigned,{
      status:200,headers:{'x-paper-auth':wire.computeMac(
        env.APODS_ACCOUNT_COORDINATOR_SHARED_KEY,
        'consume-response',forgedButSigned)}
    })
  })).rejects.toMatchObject({
    code:'ACCOUNT_COORDINATOR_RECONCILIATION_REQUIRED'
  });
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

describe('approved app signup quota', () => {
  const policy = { settings: { maxAccountsPerAppPerDay: 17 } };
  test.each([[{}, 17], [{ maxAccountsPerDay: null }, 17], [{ maxAccountsPerDay: 1 }, 1],
    [{ maxAccountsPerDay: 5 }, 5], [{ maxAccountsPerDay: 0 }, 1]])(
    'resolves %j to %i reservations per day', (approvedApp, expected) => {
      expect(provider.methods.resolveDailyLimit.call(policy, approvedApp)).toBe(expected);
    }
  );
});

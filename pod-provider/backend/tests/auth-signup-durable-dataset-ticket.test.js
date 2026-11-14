'use strict';

const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const crypto=require('node:crypto');

class MoleculerError extends Error{
  constructor(message,code,type,data){
    super(message);this.code=code;this.type=type;this.data=data;
  }
}
function loadSignup(){
  const source=fs.readFileSync(path.join(__dirname,'../services/core/auth.js'),'utf8');
  const out={exports:{}};
  const factory=vm.runInNewContext('(function(require,module){\n'+source+'\n})',
    {process,Buffer,console});
  factory(name=>{
    if(name==='path')return require('node:path');
    if(name==='url-join')return(...parts)=>parts.join('/');
    if(name==='moleculer')return{Errors:{MoleculerError}};
    if(name==='@semapps/auth')return{AuthLocalService:{}};
    if(name==='../../config/config')return{
      BASE_URL:'https://paper.example.org',AUTH_ACCOUNTS_DATASET:'settings',
      AUTH_RESERVED_USER_NAMES:[],FRONTEND_URL:null,FROM_NAME:'Paper',
      FROM_EMAIL:'noreply@example.org'
    };
    if(name==='../../config/transport')return{};
    if(name==='../../utils/account-signup-rollback-policy')return{
      mustPreserveFailedSignup:()=>false
    };
    throw Error('Unexpected signup module: '+name);
  },out);
  return out.exports;
}
async function withFlags(values,fn){
  const keys=['NODE_ENV','APODS_ACCOUNT_RESERVATION_DISPOSABLE',
    'APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE'];
  const prior=Object.fromEntries(keys.map(x=>[x,process.env[x]]));
  try{
    for(const key of keys){
      if(values[key]===undefined)delete process.env[key];
      else process.env[key]=values[key];
    }
    return await fn();
  }finally{
    for(const key of keys){
      if(prior[key]===undefined)delete process.env[key];
      else process.env[key]=prior[key];
    }
  }
}
const ticket=()=>({
  claim:{version:1,dataset:'claimtest-abc123def456',
    ownerWebid:'https://paper.example.org/users/claimtest-abc123def456',
    reservationId:crypto.randomUUID()},
  signature:'A'.repeat(86)
});
function ctxWithTicket(datasetAdminTicket){
  const events=[],calls=[];
  const ctx={
    params:{username:'claimtest-abc123def456',password:'safe-password',
      email:'person@example.org',datasetAdminTicket,name:'A Person'},
    meta:{unrelated:'preserved'},calls,events,
    call:jest.fn(async(name,params,opts)=>{
      calls.push({name,params,opts});
      if(name==='username-moderation.assertSafe')return true;
      if(name==='dataset-provisioning.ensureSecureDataset')return{created:true};
      if(name==='triplestore.dataset.exist')return true;
      if(name==='auth.account.create')return{
        '@id':'urn:test:canonical',username:'claimtest-abc123def456',email:'person@example.org'
      };
      if(name==='webid.createWebId')return'https://paper.example.org/users/claimtest-abc123def456';
      if(name==='auth.account.attachWebId')return{
        '@id':'urn:test:canonical',username:'claimtest-abc123def456'
      };
      if(name==='activitypub-provisioning.provisionForAccount')return{
        actorId:'https://paper.example.org/users/claimtest-abc123def456'
      };
      if(name==='auth.jwt.generateServerSignedToken')return 'session-redacted';
      throw Error('Unexpected action '+name);
    }),
    emit:jest.fn((name,payload,opts)=>events.push({name,payload,opts}))
  };
  const state={
    settings:{atproto:{autoProvisionOnSignup:false}},
    logger:{info:jest.fn(),error:jest.fn(),warn:jest.fn()},
    pickAccountData:jest.fn(rest=>rest),
    pickWebIdData:jest.fn(rest=>rest),
    _waitForKeyContainerWithTimeout:jest.fn().mockResolvedValue(undefined)
  };
  return{ctx,state};
}

test('signed claim is rejected outside the exact disposable gate before side effects',async()=>{
  const service=loadSignup();
  await withFlags({NODE_ENV:'test'},async()=>{
    const {ctx,state}=ctxWithTicket(ticket());
    await expect(service.actions.signup.call(state,ctx))
      .rejects.toMatchObject({type:'ACCOUNT_DATASET_CLAIM_NOT_RELEASED'});
    expect(ctx.call).not.toHaveBeenCalled();
  });
  await withFlags({
    NODE_ENV:'test',APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE:'confirmed'
  },async()=>{
    const {ctx,state}=ctxWithTicket(ticket());
    await expect(service.actions.signup.call(state,ctx))
      .rejects.toMatchObject({type:'ACCOUNT_RESERVATION_REQUIRED'});
    expect(ctx.call).not.toHaveBeenCalled();
  });
  await withFlags({
    NODE_ENV:'production',APODS_ACCOUNT_RESERVATION_DISPOSABLE:'confirmed',
    APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE:'confirmed'
  },async()=>{
    const {ctx,state}=ctxWithTicket(ticket());
    await expect(service.actions.signup.call(state,ctx))
      .rejects.toMatchObject({type:'ATPROTO_PDS_REPOSITORY_NOT_READY'});
    expect(ctx.call).not.toHaveBeenCalled();
  });
});
test('no claim is refused before moderation, dataset creation, WebID or DID',async()=>{
  const service=loadSignup();
  await withFlags({
    NODE_ENV:'test',APODS_ACCOUNT_RESERVATION_DISPOSABLE:'confirmed',
    APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE:'confirmed'
  },async()=>{
    const {ctx,state}=ctxWithTicket(undefined);
    await expect(service.actions.signup.call(state,ctx))
      .rejects.toMatchObject({type:'ACCOUNT_RESERVATION_REQUIRED'});
    expect(ctx.call).not.toHaveBeenCalled();
  });
});
test('real auth.signup passes ticket only as dataset action param, not account/WebID/profile/meta/event',async()=>{
  const service=loadSignup();
  await withFlags({
    NODE_ENV:'test',APODS_ACCOUNT_RESERVATION_DISPOSABLE:'confirmed',
    APODS_ATPROTO_DATASET_ADMIN_DELEGATION_DISPOSABLE:'confirmed'
  },async()=>{
    const claim=ticket(),{ctx,state}=ctxWithTicket(claim);
    const result=await service.actions.signup.call(state,ctx);
    expect(result.webId).toBe('https://paper.example.org/users/claimtest-abc123def456');
    const delegation=ctx.calls.filter(x=>
      x.name==='dataset-provisioning.ensureSecureDataset');
    expect(delegation).toHaveLength(1);
    expect(delegation[0].params).toEqual({
      dataset:'claimtest-abc123def456',datasetAdminTicket:claim
    });
    expect(delegation[0].opts).toBeUndefined();
    expect(state.pickAccountData).toHaveBeenCalled();
    expect(state.pickAccountData.mock.calls[0][0].datasetAdminTicket)
      .toBeUndefined();
    expect(state.pickWebIdData).toHaveBeenCalled();
    expect(state.pickWebIdData.mock.calls[0][0].datasetAdminTicket)
      .toBeUndefined();
    expect(ctx.meta).toEqual({unrelated:'preserved',skipObjectsWatcher:true});
    expect(JSON.stringify(ctx.events)).not.toContain(claim.signature);
    expect(JSON.stringify(ctx.calls.filter(x=>
      x.name!=='dataset-provisioning.ensureSecureDataset')))
      .not.toContain(claim.signature);
  });
});

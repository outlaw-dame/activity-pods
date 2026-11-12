'use strict';

/**
 * Non-activated two-process Moleculer/Redis parent→child authorization proof.
 * Unlike the standalone Redis test, this uses actual Moleculer ctx.call
 * propagation and routing across two independently started brokers.
 * No real SAI mutation is performed and no production service is registered.
 */
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const {ServiceBroker}=require('moleculer');
const {PROOF_KEY}=require('../services/utils/atproto-sai-distributed-owner-proof');
const {
  authorizeOwnerSaiActionForBroker,
  hasAuthorizedOwnerParentForBroker
}=require('../services/utils/atproto-sai-owner-context');
const {closeDistributedSaiOwnerProof}=
  require('../services/utils/atproto-sai-distributed-owner-runtime');

if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_SAI_OWNER_REDIS_PROOF_DISPOSABLE!=='confirmed'){
  throw Error('SAI Moleculer proof requires an isolated disposable provider');
}
const redisUrl=new URL(process.env.SEMAPPS_REDIS_OIDC_PROVIDER_URL||
  'redis://redis:6379/13');
if(redisUrl.protocol!=='redis:'||
   !['redis','127.0.0.1'].includes(redisUrl.hostname)||
   redisUrl.port!=='6379'||redisUrl.username||redisUrl.password||
   redisUrl.hash){
  throw Error('SAI Moleculer proof refuses external Redis transport');
}
redisUrl.pathname='/14';
const transport=redisUrl.toString();
const owner='https://paper-e2e.test:3443/alice';
const app='https://app-e2e.test:3443/clients/paper';
const otherApp='https://app-e2e.test:3443/clients/other';
const namespace=process.env.SAI_OWNER_MOLECULER_NAMESPACE;
const namePattern=/^sai-proof-[a-f0-9]{12}$/u;

if(process.argv[2]==='worker' && !namePattern.test(namespace||'')){
  throw Error('Worker requires isolated test namespace');
}
function makeBroker(nodeID){
  return new ServiceBroker({
    nodeID,namespace:process.env.SAI_OWNER_MOLECULER_NAMESPACE,
    transporter:transport,
    logger:false,metrics:false,tracing:false,
    requestTimeout:8000,
    heartbeatInterval:3,heartbeatTimeout:7,
    registry:{preferLocal:true},
    retryPolicy:{enabled:false}
  });
}
const runCheck=async(ctx)=>{
  const [authorized,wrongApp,wrongRequest]=await Promise.all([
    hasAuthorizedOwnerParentForBroker(ctx,{owner,app}),
    hasAuthorizedOwnerParentForBroker(ctx,{owner,app:otherApp}),
    hasAuthorizedOwnerParentForBroker(
      {...ctx,requestID:crypto.randomUUID()},
      {owner,app}
    )
  ]);
  return {
    authorized,wrongApp,wrongRequest,
    requestID:ctx.requestID,
    workerPid:process.pid,
    delegatedTokenPresent:typeof ctx.meta?.[PROOF_KEY]==='string'
  };
};
async function worker(){
  const broker=makeBroker('sai-proof-child');
  broker.createService({
    name:'sai-proof-child',
    actions:{
      check:{
        handler:runCheck
      }
    }
  });
  try{
    await broker.start();
    process.stdout.write('SAI_MOLECULER_WORKER_READY\n');
    await new Promise(resolve=>{
      process.once('SIGTERM',resolve);
      process.once('SIGINT',resolve);
    });
  }finally{
    await broker.stop().catch(()=>{});
    await closeDistributedSaiOwnerProof();
  }
}
async function startChild(){
  const child=spawn(process.execPath,[__filename,'worker'],{
    env:process.env,
    stdio:['ignore','pipe','pipe']
  });
  let stdout='';
  let stderr='';
  const ready=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{
      reject(Error('Remote Moleculer worker startup timeout'));
    },15000);
    const complete=(err,ok)=>{
      clearTimeout(timer);
      if(err)reject(err);else resolve(ok);
    };
    child.stdout.on('data',chunk=>{
      stdout+=chunk.toString('utf8');
      if(stdout.length>4096){
        complete(Error('Oversized child output'));
      }else if(stdout.includes('SAI_MOLECULER_WORKER_READY')){
        complete(null,true);
      }
    });
    child.stderr.on('data',chunk=>{
      stderr+=(chunk.toString('utf8').slice(0,1500));
      if(stderr.length>3000)stderr=stderr.slice(0,3000);
    });
    child.once('error',complete);
    child.once('exit',code=>{
      complete(Error('Remote Moleculer worker stopped before ready (exit '+code+')'));
    });
  });
  assert.equal(ready,true);
  return child;
}
async function stopChild(child){
  if(!child)return;
  if(child.exitCode!==null||child.signalCode!==null)return;
  child.kill('SIGTERM');
  await Promise.race([
    new Promise(resolve=>child.once('exit',resolve)),
    new Promise(resolve=>setTimeout(resolve,4000))
  ]);
  if(child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');
}
async function main(){
  const secret=crypto.randomBytes(32).toString('base64url');
  process.env.APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED='true';
  process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED='true';
  process.env.APODS_ATPROTO_TEST_STORAGE_DISPOSABLE='confirmed';
  process.env.APODS_ATPROTO_SAI_FENCED_APPS=app;
  process.env.APODS_SAI_DISTRIBUTED_OWNER_HMAC_KEY=secret;
  process.env.APODS_SAI_DISTRIBUTED_OWNER_REDIS_URL='redis://'+
    redisUrl.hostname+':6379/15';
  process.env.SAI_OWNER_MOLECULER_NAMESPACE=
    'sai-proof-'+crypto.randomBytes(6).toString('hex');
  const broker=makeBroker('sai-proof-parent');
  let child;
  broker.createService({
    name:'sai-proof-parent',
    actions:{
      authorize:async(ctx)=>{
        const release=await authorizeOwnerSaiActionForBroker(
          ctx,{owner,app}
        );
        try {
          const check=await ctx.call('sai-proof-child.check',{});
          if(check.requestID!==ctx.requestID){
            throw Error('Moleculer did not preserve authenticated parent request ID');
          }
          return check;
        }finally{await release();}
      }
    }
  });
  try{
    child=await startChild();
    await broker.start();
    await broker.waitForServices(['sai-proof-child'],15000);
    const response=await broker.call('sai-proof-parent.authorize',{},{
      meta:{webId:owner}
    });
    assert.deepEqual({
      authorized:response.authorized,
      wrongApp:response.wrongApp,
      wrongRequest:response.wrongRequest,
      delegatedTokenPresent:response.delegatedTokenPresent
    },{
      authorized:true,wrongApp:false,wrongRequest:false,
      delegatedTokenPresent:true
    });
    assert.notEqual(response.workerPid,process.pid);
    assert.equal(typeof response.requestID,'string');
    console.log(JSON.stringify({
      success:true,scope:'disposable-real-moleculer-two-broker-sai-proof',
      independentNodeProcesses:2,
      remoteNodeVerifiedAuthorizedParent:true,
      exactMoleculerRequestIdPreserved:true,
      crossAppAndRequestForgeryDenied:true,
      redisTransportDatabase:14,proofDatabase:15,
      productionActivation:false
    }));
  }finally{
    await broker.stop().catch(()=>{});
    await stopChild(child);
    await closeDistributedSaiOwnerProof();
    delete process.env.APODS_SAI_DISTRIBUTED_OWNER_HMAC_KEY;
  }
}
(process.argv[2]==='worker'?worker():main()).catch(e=>{
  console.error('Moleculer cross-node owner SAI proof failed:',e?.code||e?.name||'UNKNOWN');
  process.exitCode=1;
});

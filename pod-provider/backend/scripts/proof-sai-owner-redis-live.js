'use strict';
/** Disposable two-process ioredis verification; no production Redis allowed. */
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const Redis=require('ioredis');
const {createSaiDistributedOwnerProof,PROOF_KEY}=
  require('../services/utils/atproto-sai-distributed-owner-proof');
if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_SAI_OWNER_REDIS_PROOF_DISPOSABLE!=='confirmed'){
  throw Error('Disposable SAI owner proof marker required');
}
const original=process.env.SEMAPPS_REDIS_OIDC_PROVIDER_URL||'redis://redis:6379/13';
const u=new URL(original);
if(u.protocol!=='redis:'||!['redis','127.0.0.1'].includes(u.hostname)||
   u.port!=='6379'||u.username||u.password||u.hash) {
  throw Error('Refusing external Redis endpoint');
}
u.pathname='/15';
const owner='https://paper-e2e.test:3443/alice';
const app='https://app-e2e.test:3443/clients/paper';
const makeRedis=()=>new Redis(u.toString(),{
  lazyConnect:true,enableOfflineQueue:false,
  connectTimeout:2500,maxRetriesPerRequest:1,retryStrategy:()=>null
});
async function childMain(){
  const input=[];
  let bytes=0;
  for await(const chunk of process.stdin){
    bytes+=chunk.length;
    if(bytes>2048)throw Error('Oversized IPC proof');
    input.push(chunk);
  }
  const {nonce,requestID}=JSON.parse(Buffer.concat(input).toString('utf8'));
  const client=makeRedis();
  try{
    await client.connect();
    const verifier=createSaiDistributedOwnerProof({
      redis:client,secret:process.env.SAI_REDIS_TEST_HMAC
    });
    const ctx={requestID,meta:{webId:'system',[PROOF_KEY]:nonce}};
    const valid=await verifier.verify(ctx,{owner,app});
    const wrongApp=await verifier.verify(ctx,{
      owner,app:'https://app-e2e.test:3443/clients/different'
    });
    const wrongRequest=await verifier.verify({...ctx,requestID:'wrong-id'},{owner,app});
    process.stdout.write(JSON.stringify({valid,wrongApp,wrongRequest}));
  }finally{client.disconnect();}
}
async function childProof(secret,requestID,nonce) {
  const child=spawn(process.execPath,[__filename,'verify'],{
    env:{...process.env,SAI_REDIS_TEST_HMAC:secret},
    stdio:['pipe','pipe','ignore']
  });
  const received=[];let size=0;
  child.stdout.on('data',chunk=>{
    size+=chunk.length;
    if(size<=4096)received.push(chunk);
  });
  child.stdin.end(JSON.stringify({requestID,nonce}));
  const code=await new Promise(resolve=>child.on('exit',resolve));
  assert.equal(code,0,'Remote verification process failed');
  assert(size<=4096,'Remote result exceeded limit');
  return JSON.parse(Buffer.concat(received).toString('utf8'));
}
async function main(){
  const secret=crypto.randomBytes(32).toString('base64url');
  const client=makeRedis();
  let release;
  try{
    await client.connect();
    const issuer=createSaiDistributedOwnerProof({redis:client,secret});
    const requestID=crypto.randomUUID();
    const parent={requestID,meta:{webId:owner}};
    release=await issuer.issue(parent,{owner,app});
    const nonce=parent.meta[PROOF_KEY];
    assert.deepEqual(await childProof(secret,requestID,nonce),{
      valid:true,wrongApp:false,wrongRequest:false
    });
    await release();release=null;
    assert.deepEqual(await childProof(secret,requestID,nonce),{
      valid:false,wrongApp:false,wrongRequest:false
    });
    assert.equal(issuer.inFlight(),0);
    console.log(JSON.stringify({
      success:true,scope:'real-redis-two-node-sai-owner-proof',
      independentNodeProcesses:2,ownerAppRequestScoped:true,
      atomicRedisNxAndTtl:true,parentCompletionRevokes:true,
      redisDatabase:15,productionActive:false
    }));
  }finally{
    if(release)await release().catch(()=>{});
    client.disconnect();
  }
}
(process.argv[2]==='verify'?childMain():main()).catch(e=>{
  console.error('Cross-process SAI proof failed:',e?.code||e?.name||'UNKNOWN');
  process.exitCode=1;
});

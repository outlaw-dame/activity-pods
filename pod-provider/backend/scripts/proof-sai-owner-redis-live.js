'use strict';

/**
 * Disposable real Redis / two Node-process SAI owner integration proof.
 * Uses the *runtime* auth-agent and child-hook adapters, not just the
 * standalone proof primitive. Production startup release fuse stays closed.
 */
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const {PROOF_KEY}=require('../services/utils/atproto-sai-distributed-owner-proof');
const {
  authorizeOwnerSaiActionForBroker,hasAuthorizedOwnerParentForBroker
}=require('../services/utils/atproto-sai-owner-context');
const {closeDistributedSaiOwnerProof}=
  require('../services/utils/atproto-sai-distributed-owner-runtime');

if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_SAI_OWNER_REDIS_PROOF_DISPOSABLE!=='confirmed'){
  throw Error('Disposable SAI integration proof marker required');
}
const input=process.env.SEMAPPS_REDIS_OIDC_PROVIDER_URL||'redis://redis:6379/13';
const uri=new URL(input);
if(uri.protocol!=='redis:'||!['redis','127.0.0.1'].includes(uri.hostname)||
   uri.port!=='6379'||uri.username||uri.password||uri.hash){
  throw Error('SAI owner integration proof refuses external Redis');
}
uri.pathname='/15';
process.env.APODS_SAI_DISTRIBUTED_OWNER_REDIS_URL=uri.toString();
process.env.APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED='true';
process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED='true';
process.env.APODS_ATPROTO_TEST_STORAGE_DISPOSABLE='confirmed';

const owner='https://paper-e2e.test:3443/alice';
const app='https://app-e2e.test:3443/clients/paper';
async function child(){
  let length=0;const data=[];
  for await(const chunk of process.stdin){
    length+=chunk.length;
    if(length>2048)throw Error('Oversized test command');
    data.push(chunk);
  }
  const {nonce,requestID}=JSON.parse(Buffer.concat(data).toString('utf8'));
  const ctx={requestID,meta:{webId:'system',[PROOF_KEY]:nonce}};
  try{
    const valid=await hasAuthorizedOwnerParentForBroker(ctx,{owner,app});
    const wrongRequest=await hasAuthorizedOwnerParentForBroker(
      {...ctx,requestID:'not-parent'}, {owner,app});
    const wrongApp=await hasAuthorizedOwnerParentForBroker(
      ctx,{owner,app:'https://app-e2e.test:3443/clients/different'});
    process.stdout.write(JSON.stringify({valid,wrongRequest,wrongApp}));
  }finally{await closeDistributedSaiOwnerProof();}
}
async function runChild(nonce,requestID){
  const proc=spawn(process.execPath,[__filename,'verify'],{
    stdio:['pipe','pipe','ignore'],env:process.env
  });
  const chunks=[];let size=0;
  proc.stdout.on('data',chunk=>{
    size+=chunk.length;if(size<=4096)chunks.push(chunk);
  });
  proc.stdin.end(JSON.stringify({nonce,requestID}));
  const code=await new Promise(resolve=>proc.on('exit',resolve));
  assert.equal(code,0,'Independent verifier node did not complete');
  assert(size<=4096);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
async function main(){
  process.env.APODS_SAI_DISTRIBUTED_OWNER_HMAC_KEY=
    crypto.randomBytes(32).toString('base64url');
  const requestID=crypto.randomUUID();
  const ctx={requestID,meta:{webId:owner}};
  let release;
  try{
    release=await authorizeOwnerSaiActionForBroker(ctx,{owner,app});
    const nonce=ctx.meta[PROOF_KEY];
    assert.deepEqual(await runChild(nonce,requestID),{
      valid:true,wrongRequest:false,wrongApp:false
    });
    await release();release=null;
    assert.deepEqual(await runChild(nonce,requestID),{
      valid:false,wrongRequest:false,wrongApp:false
    });
    console.log(JSON.stringify({
      success:true,scope:'real-redis-native-sai-parent-child-adapter',
      independentNodeProcesses:2,exactOwnerAppRequest:true,
      staleCapabilityDenied:true,redisDatabase:15,
      sourceGateRemainsClosed:true
    }));
  }finally{
    if(release)await release().catch(()=>{});
    await closeDistributedSaiOwnerProof();
    delete process.env.APODS_SAI_DISTRIBUTED_OWNER_HMAC_KEY;
  }
}
(process.argv[2]==='verify'?child():main()).catch(err=>{
  console.error('SAI runtime Redis proof failed:',err?.code||err?.name||'UNKNOWN');
  process.exitCode=1;
});

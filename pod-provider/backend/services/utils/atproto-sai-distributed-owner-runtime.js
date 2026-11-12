'use strict';

/**
 * TEST-ONLY provider Redis binding for cross-node owner proof.
 * The trust boundary is enforced before initialization and at every
 * operation. The credential is never shared with ordinary apps/federation.
 * The source-controlled release gate prohibits production activation.
 */
const {
  createSaiDistributedOwnerProof
}=require('./atproto-sai-distributed-owner-proof');
let live=null;
let initializing=null;
let closing=false;

function refusal(code) {
  const error=new Error('Distributed SAI owner proof is unavailable');
  error.code=code;throw error;
}
function assertFixture(env=process.env){
  if(env.APODS_ATPROTO_SAI_OWNER_DISTRIBUTED_ENABLED!=='true' ||
     env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED!=='true' ||
     env.NODE_ENV!=='test' ||
     env.APODS_ATPROTO_TEST_STORAGE_DISPOSABLE!=='confirmed') {
    refusal('SAI_DISTRIBUTED_NOT_RELEASED');
  }
}
async function getDistributedSaiOwnerProof() {
  assertFixture();
  if(closing)refusal('SAI_DISTRIBUTED_STOPPING');
  if(live)return live.proof;
  if(!initializing){
    initializing=(async()=>{
      const urlText=process.env.APODS_SAI_DISTRIBUTED_OWNER_REDIS_URL;
      const secret=process.env.APODS_SAI_DISTRIBUTED_OWNER_HMAC_KEY;
      let url;
      try{url=new URL(urlText)}
      catch{refusal('SAI_DISTRIBUTED_CONFIG_INVALID')}
      if(url.protocol!=='redis:'||!['redis','127.0.0.1'].includes(url.hostname)||
         url.port!=='6379'||url.pathname!=='/15'||url.search||
         url.hash||url.username||url.password)refusal('SAI_DISTRIBUTED_CONFIG_INVALID');
      const Redis=require('ioredis');
      const redis=new Redis(url.toString(),{
        lazyConnect:true,enableOfflineQueue:false,
        connectTimeout:2500,maxRetriesPerRequest:1,
        retryStrategy:()=>null
      });
      try{
        await redis.connect();
        const proof=createSaiDistributedOwnerProof({redis,secret});
        if(closing)refusal('SAI_DISTRIBUTED_STOPPING');
        live={redis,proof};
        return proof;
      }catch{
        redis.disconnect();
        refusal('SAI_DISTRIBUTED_STORE_UNAVAILABLE');
      }
    })().finally(()=>{initializing=null});
  }
  return initializing;
}
async function issueDistributedOwnerProof(ctx,scope) {
  const proof=await getDistributedSaiOwnerProof();
  return proof.issue(ctx,scope);
}
async function verifyDistributedOwnerProof(ctx,scope) {
  const proof=await getDistributedSaiOwnerProof();
  return proof.verify(ctx,scope);
}
async function closeDistributedSaiOwnerProof() {
  closing=true;
  try{
    const pending=initializing;
    if(pending)await pending.catch(()=>{});
    const current=live;live=null;
    if(current)current.redis.disconnect();
  }finally{closing=false;}
}
module.exports={
  getDistributedSaiOwnerProof,issueDistributedOwnerProof,
  verifyDistributedOwnerProof,closeDistributedSaiOwnerProof,
  assertFixture
};

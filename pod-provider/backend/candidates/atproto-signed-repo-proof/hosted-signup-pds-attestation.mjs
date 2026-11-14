/**
 * NONACTIVATED hosted-PDS attestation for a NEW unified account.
 *
 * This tests a real network-visible XRPC sync response against the actual
 * provider-signed genesis CAR, current resolved DID/handle/key, PostgreSQL
 * signed head, and protected Jena projection. It is read-only and cannot
 * authorize HTTP login or promote an account to ready.
 *
 * A trusted provider MUST inject a fixed-origin, DNS-pinned, no-redirect,
 * bounded egress adapter for XRPC. Nothing from the public signup request
 * supplies a URL. The test adapter uses a local loopback HTTP listener.
 */
import {Buffer} from 'node:buffer';
import {verifySignedEmptyRepo} from './genesis.mjs';

const DID=/^did:plc:[a-z2-7]{24}$/u;
const CID=/^bafyre[a-z2-7]{53}$/u;
const REV=/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const MAX_CAR=256*1024;
const MAX_JSON=2048;
function deny(code){
  const e=new Error('Hosted account PDS readiness unavailable');
  e.code=code;throw e;
}
function canonicalUrl(value, origin=false) {
  if(typeof value!=='string'||value.length<8||value.length>2048){
    deny('HOSTED_PDS_PROOF_INVALID_SCOPE');
  }
  let u;
  try{u=new URL(value);}catch{deny('HOSTED_PDS_PROOF_INVALID_SCOPE');}
  if(u.protocol!=='https:'||!u.hostname||u.username||u.password||
     u.search||u.hash||(origin?u.origin!==value:u.href!==value)) {
    deny('HOSTED_PDS_PROOF_INVALID_SCOPE');
  }
}
function expectedShape(x){
  if(!x||typeof x!=='object'||!DID.test(x.did||'')||
     !CID.test(x.commitCid||'')||!CID.test(x.rootCid||'')||
     !REV.test(x.rev||'')||typeof x.handle!=='string'||
     x.handle.length>244||!x.handle.includes('.')) {
    deny('HOSTED_PDS_PROOF_INVALID_SCOPE');
  }
  canonicalUrl(x.webId);
  canonicalUrl(x.pdsOrigin,true);
  if(typeof x.projectionFence!=='string'||
     !/^[1-9][0-9]{0,18}$/u.test(x.projectionFence)) {
    deny('HOSTED_PDS_PROOF_INVALID_SCOPE');
  }
}
function matchAuthority(repo,projection,x){
  if(repo?.verified!==true||repo.accountId!==x.webId||
     repo.did!==x.did||repo.pdsOrigin!==x.pdsOrigin||
     repo.commitCid!==x.commitCid||repo.rootCid!==x.rootCid||
     repo.rev!==x.rev||!['pending','delivered'].includes(repo.outboxStatus)||
     projection?.ready!==true||projection.accountId!==x.webId||
     projection.did!==x.did||projection.headCid!==x.commitCid||
     projection.rootCid!==x.rootCid||projection.rev!==x.rev||
     projection.fence!==x.projectionFence||
     projection.outboxStatus!==repo.outboxStatus) {
    deny('HOSTED_PDS_PROOF_AUTHORITY_CHANGED');
  }
}
async function boundedBody(response,max,kind){
  if(response?.status!==200||response.redirected===true||
     !response.headers||typeof response.headers.get!=='function') {
    deny('HOSTED_PDS_PROOF_HTTP_UNAVAILABLE');
  }
  const type=String(response.headers.get('content-type')||'').toLowerCase();
  if(kind==='car' ? !type.startsWith('application/vnd.ipld.car') :
    !type.startsWith('application/json')) {
    deny('HOSTED_PDS_PROOF_CONTENT_TYPE_INVALID');
  }
  const len=response.headers.get('content-length');
  if(len!==null&&(!/^[0-9]+$/u.test(len)||Number(len)>max)){
    deny('HOSTED_PDS_PROOF_BODY_TOO_LARGE');
  }
  if(!response.body||typeof response.body[Symbol.asyncIterator]!=='function'){
    deny('HOSTED_PDS_PROOF_BODY_INVALID');
  }
  const chunks=[];let size=0;
  for await(const chunk of response.body){
    size+=chunk.byteLength;
    if(size>max)deny('HOSTED_PDS_PROOF_BODY_TOO_LARGE');
    chunks.push(Buffer.from(chunk));
  }
  if(!size)deny('HOSTED_PDS_PROOF_BODY_INVALID');
  return Buffer.concat(chunks,size);
}
async function json(response){
  const bytes=await boundedBody(response,MAX_JSON,'json');
  try{
    const value=JSON.parse(bytes.toString('utf8'));
    if(value===null||typeof value!=='object'||Array.isArray(value))throw Error();
    return value;
  }catch{deny('HOSTED_PDS_PROOF_JSON_INVALID');}
}
export function createHostedSignupPdsAttestation({
  repositoryAuthority,projectionAuthority,resolvePublicKey,requestPds,
  fixtureOnly=false
}={}){
  const available=()=>fixtureOnly===true&&
    process.env.NODE_ENV==='test'&&
    process.env.PAPER_ACCOUNTS_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_PDS_ATTESTATION_DISPOSABLE==='confirmed';
  const unavailable=async()=>deny('HOSTED_PDS_PROOF_NOT_RELEASED');
  if(!available())return Object.freeze({verify:unavailable});
  if(typeof repositoryAuthority?.verifyReady!=='function'||
     typeof projectionAuthority?.readiness!=='function'||
     typeof resolvePublicKey!=='function'||
     typeof requestPds!=='function') {
    deny('HOSTED_PDS_PROOF_CONFIGURATION_INVALID');
  }
  async function verify(x) {
    if(!available())deny('HOSTED_PDS_PROOF_NOT_RELEASED');
    expectedShape(x);
    const key=await resolvePublicKey({accountId:x.webId,did:x.did});
    if(typeof key!=='string'||key.length>4096){
      deny('HOSTED_PDS_PROOF_PUBLIC_KEY_UNAVAILABLE');
    }
    const query={canonicalAccountId:x.webId,did:x.did,handle:x.handle};
    const [beforeRepo,beforeProjection]=await Promise.all([
      repositoryAuthority.verifyReady(query),
      projectionAuthority.readiness({accountId:x.webId,did:x.did})
    ]);
    matchAuthority(beforeRepo,beforeProjection,x);
    const path='/xrpc/com.atproto.sync.';
    const qs='?did='+encodeURIComponent(x.did);
    // The provider-owned requestPds implementation fixes HTTPS origin and
    // rejects redirects/DNS rebinding. Never pass it arbitrary user URLs.
    const call=method=>requestPds({
      expectedOrigin:x.pdsOrigin,method:'GET',
      path:path+method+qs,redirect:'manual'
    });
    const latest=await json(await call('getLatestCommit'));
    if(latest.cid!==x.commitCid||latest.rev!==x.rev) {
      deny('HOSTED_PDS_PROOF_LATEST_COMMIT_MISMATCH');
    }
    const status=await json(await call('getRepoStatus'));
    if(status.did!==x.did||status.active!==true||
       status.rev!==x.rev)deny('HOSTED_PDS_PROOF_HOSTING_INACTIVE');
    const car=await boundedBody(await call('getRepo'),MAX_CAR,'car');
    let verified;
    try {
      verified=await verifySignedEmptyRepo({
        did:x.did,carBytes:car,publicKeyPem:key
      });
    }catch{deny('HOSTED_PDS_PROOF_SIGNED_CAR_INVALID');}
    if(verified.valid!==true||verified.did!==x.did||
       verified.commitCid!==x.commitCid||
       verified.rootCid!==x.rootCid||verified.rev!==x.rev) {
      deny('HOSTED_PDS_PROOF_SIGNED_CAR_MISMATCH');
    }
    // Network calls are NOT a cross-store atomic snapshot. Re-read the
    // actual PostgreSQL+RDF authority after all HTTP I/O, then the v4
    // completion transaction must lock and compare its canonical records.
    const [afterRepo,afterProjection]=await Promise.all([
      repositoryAuthority.verifyReady(query),
      projectionAuthority.readiness({accountId:x.webId,did:x.did})
    ]);
    matchAuthority(afterRepo,afterProjection,x);
    return Object.freeze({
      status:'hosted_genesis_evidence_only',hostedPdsVerified:true,
      webId:x.webId,did:x.did,pdsOrigin:x.pdsOrigin,
      commitCid:x.commitCid,rootCid:x.rootCid,rev:x.rev,
      projectionFence:x.projectionFence,productionReady:false
    });
  }
  return Object.freeze({verify});
}

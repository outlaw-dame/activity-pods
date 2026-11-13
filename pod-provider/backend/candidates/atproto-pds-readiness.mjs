/**
 * NON-ACTIVATED ATProto PDS account readiness verifier.
 * Reconcile an *already submitted* PLC DID against the configured PDS.
 * No identity creation, PLC mutation, account password or private key access.
 *
 * Egress firewall must also allowlist expected PDS/PLC origins; local URL
 * validation alone cannot defend against DNS rebinding.
 */
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { verifySignedGenesisEvidence } from './atproto-repo-genesis.mjs';

const DID = /^did:plc:[a-z2-7]{24}$/;
const HANDLE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,61}$/;
const KEY = /^z[1-9A-HJ-NP-Za-km-z]{30,160}$/;
const MAX_DOC = 64 * 1024;
const MAX_REPO = 256 * 1024;
function fail(code) {
  const err = new Error(code);
  err.code = code;
  throw err;
}
function origin(input, fixture=false) {
  let u;
  try { u=new URL(input); } catch { fail('PDS_PROOF_INVALID_ORIGIN'); }
  const host=u.hostname.toLowerCase().replace(/\.$/,'');
  const local=host==='localhost'||host.endsWith('.test');
  if (!u.hostname || !host || u.username || u.password ||
      u.search || u.hash || u.pathname!=='/' ||
      (!fixture && (u.protocol!=='https:' || isIP(host) || local ||
        host.endsWith('.local') || host.endsWith('.internal'))) ||
      (fixture && !['http:','https:'].includes(u.protocol))) {
    fail('PDS_PROOF_INVALID_ORIGIN');
  }
  return u.origin;
}
async function limitedBody(response,limit) {
  if (response.status!==200 || !response.body) fail('PDS_PROOF_RESPONSE_INVALID');
  const reported=Number(response.headers.get('content-length')||0);
  if (reported>limit) fail('PDS_PROOF_RESPONSE_TOO_LARGE');
  const reader=response.body.getReader();
  const chunks=[];
  let size=0;
  try {
    while(true) {
      const chunk=await reader.read();
      if (chunk.done) break;
      size+=chunk.value.byteLength;
      if (size>limit) fail('PDS_PROOF_RESPONSE_TOO_LARGE');
      chunks.push(Buffer.from(chunk.value));
    }
  } finally {
    await reader.cancel().catch(()=>{});
    reader.releaseLock();
  }
  return Buffer.concat(chunks,size);
}
async function getBounded(fetchFn,url,accept,limit) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),5000);
  timer.unref?.();
  try {
    const response=await fetchFn(url,{
      method:'GET',headers:{accept},
      redirect:'manual',cache:'no-store',
      signal:controller.signal,
    });
    // Reject 30x rather than following an untrusted redirect target.
    return await limitedBody(response,limit);
  } catch(err) {
    if(err?.code) throw err;
    fail('PDS_PROOF_UNAVAILABLE');
  } finally {
    clearTimeout(timer);
  }
}
function json(bytes) {
  try { return JSON.parse(bytes.toString('utf8')); }
  catch { fail('PDS_PROOF_INVALID_JSON'); }
}
function canonicalDidDoc(doc,did,handle,pds) {
  if(!doc||doc.id!==did||
      !Array.isArray(doc.alsoKnownAs) ||
      !doc.alsoKnownAs.includes(`at://${handle}`) ||
      !Array.isArray(doc.verificationMethod) ||
      !Array.isArray(doc.service)) fail('PDS_PROOF_DID_DOCUMENT_MISMATCH');
  const method=doc.verificationMethod.find(m=>
    m?.id===did+'#atproto'&&m?.controller===did&&KEY.test(m?.publicKeyMultibase||''));
  const service=doc.service.find(s=>s?.id===did+'#atproto_pds' &&
    s?.type==='AtprotoPersonalDataServer'&&s?.serviceEndpoint===pds);
  if(!method||!service) fail('PDS_PROOF_DID_DOCUMENT_MISMATCH');
  return 'did:key:'+method.publicKeyMultibase;
}
/**
 * Verify a real PDS is serving the same signed, CID-valid genesis committed
 * in the local ledger. Do NOT accept user-provided host/key authority.
 */
export async function verifyPdsReadiness({
  did,handle,expectedPdsUrl,plcDirectoryUrl='https://plc.directory',
  expectedRootCid,expectedRev,fetchImpl=fetch,allowFixture=false,
  resolveHandle
}={}) {
  const fixture=allowFixture===true&&process.env.NODE_ENV!=='production';
  if(!DID.test(did||'')||!HANDLE.test(handle||'')) fail('PDS_PROOF_INVALID_IDENTITY');
  const pds=origin(expectedPdsUrl,fixture);
  const plc=origin(plcDirectoryUrl,fixture);
  if(typeof expectedRootCid!=='string'||!expectedRootCid.startsWith('bafy')||
      typeof expectedRev!=='string'||expectedRev.length<12) {
    fail('PDS_PROOF_INVALID_EXPECTATION');
  }
  if(typeof fetchImpl!=='function') fail('PDS_PROOF_INVALID_TRANSPORT');
  // The DID document claiming at://handle is necessary but insufficient.
  // The handle must independently resolve back to this DID, through an
  // authorized DNS TXT or HTTPS well-known resolver. Never rely solely on
  // a PDS's own resolveHandle response, nor resolve arbitrary hostnames
  // directly from an untrusted new-signup request in this module.
  if(typeof resolveHandle!=='function') fail('PDS_PROOF_HANDLE_RESOLVER_REQUIRED');
  const handleController=new AbortController();
  const handleTimer=setTimeout(()=>handleController.abort(),5000);
  handleTimer.unref?.();
  let resolvedDid;
  try {
    resolvedDid=await Promise.race([
      Promise.resolve().then(()=>resolveHandle(handle,{signal:handleController.signal})),
      new Promise((_,reject)=>{
        handleController.signal.addEventListener('abort',()=>{
          reject(Object.assign(new Error('PDS_PROOF_HANDLE_LOOKUP_TIMEOUT'),{
            code:'PDS_PROOF_HANDLE_LOOKUP_TIMEOUT'
          }));
        },{once:true});
      })
    ]);
  } catch (_) {
    fail('PDS_PROOF_HANDLE_RESOLUTION_UNAVAILABLE');
  } finally {
    clearTimeout(handleTimer);
    handleController.abort();
  }
  if(resolvedDid!==did) fail('PDS_PROOF_HANDLE_MISMATCH');
  const doc=json(await getBounded(
    fetchImpl,`${plc}/${encodeURIComponent(did)}`,'application/did+ld+json, application/json',MAX_DOC
  ));
  const trustedKeyDid=canonicalDidDoc(doc,did,handle,pds);
  const latest=json(await getBounded(
    fetchImpl,`${pds}/xrpc/com.atproto.sync.getLatestCommit?did=${encodeURIComponent(did)}`,
    'application/json',MAX_DOC
  ));
  if(latest?.cid!==expectedRootCid||latest?.rev!==expectedRev) {
    fail('PDS_PROOF_LATEST_COMMIT_MISMATCH');
  }
  const car=await getBounded(
    fetchImpl,`${pds}/xrpc/com.atproto.sync.getRepo?did=${encodeURIComponent(did)}`,
    'application/vnd.ipld.car',MAX_REPO
  );
  const validated=await verifySignedGenesisEvidence({
    did,rootCid:expectedRootCid,rev:expectedRev,car,trustedKeyDid
  });
  return Object.freeze({
    did,handle,pdsUrl:pds,rootCid:validated.rootCid,rev:validated.rev,
    keyDid:trustedKeyDid,
    carSha256:createHash('sha256').update(car).digest(),
    verifiedAt:new Date().toISOString(),
  });
}

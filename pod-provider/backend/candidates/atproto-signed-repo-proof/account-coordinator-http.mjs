/**
 * Shared disposable HTTP admission surface for the separately credentialed
 * coordinator and the Ed25519 issuer. No production service is registered.
 * Fixed localhost ports, bounded requests, constant-time MACs, no redirects.
 */
import http from 'node:http';
import assert from 'node:assert/strict';
import wire from '../../services/utils/atproto-account-coordinator-client.js';

export function refuse(status=403){
  const err=Error('Admission rejected');
  err.status=status;
  throw err;
}
export function exact(value,keys){
  return Boolean(value && typeof value==='object'&&!Array.isArray(value) &&
    Object.getPrototypeOf(value)===Object.prototype &&
    Object.keys(value).length===keys.length &&
    keys.every((k,i)=>Object.keys(value)[i]===k));
}
export async function readRequest(req,{domain,secret,route,keys}){
  if(req.method!=='POST'||req.url!==route ||
     req.headers['content-type']!=='application/json' ||
     typeof req.headers['x-paper-auth']!=='string' ||
     (req.headers['content-length']!==undefined &&
       (!/^\d{1,4}$/.test(req.headers['content-length']) ||
        Number(req.headers['content-length'])>2048))) refuse();
  let body='',length=0;
  for await(const chunk of req){
    length+=chunk.length;
    if(length>2048)refuse(413);
    body+=chunk.toString('utf8');
  }
  if(!length || Buffer.byteLength(body,'utf8')!==length ||
     !wire.verifyMac(secret,domain,body,req.headers['x-paper-auth']))refuse();
  let data;
  try{data=JSON.parse(body);}catch{refuse();}
  if(JSON.stringify(data)!==body||!exact(data,keys))refuse();
  return data;
}
export function respond(res,status,payload,{secret,domain}={}){
  if(res.headersSent||res.destroyed)return;
  const raw=JSON.stringify(payload);
  assert(Buffer.byteLength(raw,'utf8')<=2048);
  const headers={'content-type':'application/json','cache-control':'no-store',
    'content-length':Buffer.byteLength(raw,'utf8'),
    'x-content-type-options':'nosniff'};
  if(secret&&domain)headers['x-paper-auth']=wire.computeMac(secret,domain,raw);
  res.writeHead(status,headers);
  res.end(raw);
}
export function server({port,handler}){
  const api=http.createServer(async(req,res)=>{
    // One bounded request per connection; no error bodies containing secrets.
    const deadline=setTimeout(()=>{if(!res.writableEnded)res.destroy();},8000);
    try{
      await handler(req,res);
    }catch(e){
      respond(res,e?.status===409?409:e?.status===413?413:403,
        {error:'denied'});
    }finally{clearTimeout(deadline);}
  });
  api.requestTimeout=6000;
  api.headersTimeout=6000;
  api.keepAliveTimeout=1000;
  api.maxRequestsPerSocket=20;
  api.maxConnections=16;
  return new Promise((resolve,reject)=>{
    api.once('error',reject);
    api.listen(port,'127.0.0.1',()=>{api.off('error',reject);resolve(api);});
  });
}
export function checkFixtureEnv(role,keys){
  assert.equal(process.env.NODE_ENV,'test');
  assert.equal(process.env.ATPROTO_REPO_PROOF_DISPOSABLE,'confirmed');
  assert.equal(process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE,'confirmed');
  assert.equal(process.env.FUSEKI_ISOLATION_URL,'http://127.0.0.1:3041');
  assert.equal(process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE,'confirmed');
  assert.equal(process.env.APODS_DATASET_CLAIM_ISSUER_DISPOSABLE,'confirmed');
  assert.equal(process.env.APODS_ACCOUNT_COORDINATOR_DISPOSABLE,'confirmed');
  assert.deepEqual(Object.keys(process.env).sort(),keys.slice().sort(),
    role+' must not inherit any unrelated credential or ambient environment');
}

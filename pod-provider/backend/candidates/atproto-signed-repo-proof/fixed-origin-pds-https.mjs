/**
 * ActivityPods-owned fixed-origin HTTPS requester for read-only PDS
 * signup attestation. No environment proxy, redirect, user-selected URL,
 * bearer token, private key, or alternative account authority.
 *
 * Production construction requires an operator-approved public-IP allowlist.
 * DNS answers are checked against it and pinned on the actual TLS socket.
 * A loopback/private address and a test CA are permitted ONLY behind the
 * explicit disposable-test gate. This module is not autoloaded or routed.
 */
import {lookup as systemLookup} from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';

const DID=/^did:plc:[a-z2-7]{24}$/u;
const METHODS=new Set(['getRepo','getLatestCommit','getRepoStatus']);
const MAX_APPROVED=16;
const MAX_RESPONSE_BYTES=262144;
function deny(code) {
  const e=new Error('The approved hosted PDS cannot be contacted safely');
  e.code=code;
  throw e;
}
function testGate() {
  return process.env.NODE_ENV==='test'&&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_PDS_EGRESS_TEST_DISPOSABLE==='confirmed';
}
function publicIp(ip) {
  const family=net.isIP(ip);
  if(family===4) {
    const [a,b,c]=ip.split('.').map(Number);
    return !(a===0||a===10||a===127||a>=224||
      (a===100&&b>=64&&b<=127)||
      (a===169&&b===254)||(a===172&&b>=16&&b<=31)||
      (a===192&&(b===168||b===0||(b===88&&c===99)))||
      (a===198&&(b===18||b===19||(b===51&&c===100)))||
      (a===203&&b===0&&c===113));
  }
  if(family===6) {
    const canonical=new URL('http://['+ip+']/').hostname.slice(1,-1);
    const first=parseInt(canonical.split(':')[0],16);
    // Only global-unicast 2000::/3; exclude protocol-test and
    // transition ranges. IPv4-mapped and private IPv6 never pass.
    if(!(first>=0x2000&&first<=0x3fff))return false;
    if(canonical.startsWith('2001:db8:')||canonical.startsWith('2001:0:'))return false;
    return true;
  }
  return false;
}
function approvedIp(ip,disposable){
  if(net.isIP(ip)===0)deny('PDS_EGRESS_IP_INVALID');
  const loopback=ip==='127.0.0.1'||ip==='::1';
  if(!publicIp(ip)&&!(disposable&&loopback)) {
    deny('PDS_EGRESS_ADDRESS_FORBIDDEN');
  }
  return ip;
}
function checkedOrigin(value,disposable){
  let u;
  try{u=new URL(value);}catch{deny('PDS_EGRESS_ORIGIN_INVALID');}
  if(typeof value!=='string'||value.length>512||
     u.origin!==value||u.protocol!=='https:'||
     !u.hostname||net.isIP(u.hostname)!==0||
     u.username||u.password||u.search||u.hash||
     (!disposable&&u.port!=='')) {
    deny('PDS_EGRESS_ORIGIN_INVALID');
  }
  return u;
}
function checkedPath(path){
  if(typeof path!=='string'||path.length>180||
     path.includes('#')||path.includes('..')||
     path.includes('%2f')||path.includes('%2F')||
     path.includes('%5c')||path.includes('%5C')) {
    deny('PDS_EGRESS_PATH_INVALID');
  }
  const u=new URL(path,'https://proof.invalid');
  if(!METHODS.has(u.pathname.slice('/xrpc/com.atproto.sync.'.length))||
     !u.pathname.startsWith('/xrpc/com.atproto.sync.')||
     [...u.searchParams.keys()].length!==1){
    deny('PDS_EGRESS_PATH_INVALID');
  }
  const did=u.searchParams.get('did');
  if(!DID.test(did||'')||
     path!==u.pathname+'?did='+encodeURIComponent(did)) {
    deny('PDS_EGRESS_PATH_INVALID');
  }
  return path;
}
function headerView(headers){
  return Object.freeze({
    get(name){
      const key=String(name).toLowerCase();
      const value=headers[key];
      return typeof value==='string'?value:
        Array.isArray(value)?value.join(', '):null;
    }
  });
}
function validateAddressAnswers(answers,allowed,disposable){
  if(!Array.isArray(answers)||answers.length<1||
     answers.length>MAX_APPROVED)deny('PDS_EGRESS_DNS_INVALID');
  for(const a of answers){
    if(!a||typeof a.address!=='string'||net.isIP(a.address)!==a.family) {
      deny('PDS_EGRESS_DNS_INVALID');
    }
    approvedIp(a.address,disposable);
    if(!allowed.has(a.address))deny('PDS_EGRESS_DNS_NOT_APPROVED');
  }
  // Deterministic pinned first approved answer; no subsequent resolver
  // lookups by Node, proxies, TLS, or the backend on this request.
  return answers[0];
}

export function createFixedOriginPdsHttpsRequester({
  origin,approvedAddresses,resolveAddresses,
  tlsCaForTest,fixtureOnly=false,
  deadlineMs=4500,maxConcurrent=4,maxResponseBytes=MAX_RESPONSE_BYTES
}={}){
  const disposable=fixtureOnly===true&&testGate();
  if(fixtureOnly===true&&!disposable) {
    deny('PDS_EGRESS_DISPOSABLE_NOT_RELEASED');
  }
  if(resolveAddresses!==undefined&&!disposable){
    deny('PDS_EGRESS_INJECTED_RESOLVER_FORBIDDEN');
  }
  if(tlsCaForTest!==undefined&&!disposable) {
    deny('PDS_EGRESS_TEST_CA_FORBIDDEN');
  }
  const url=checkedOrigin(origin,disposable);
  if(!Array.isArray(approvedAddresses)||
     approvedAddresses.length<1||approvedAddresses.length>MAX_APPROVED||
     !Number.isSafeInteger(maxConcurrent)||maxConcurrent<1||
     maxConcurrent>8||!Number.isSafeInteger(deadlineMs)||
     deadlineMs<250||deadlineMs>15000||
     !Number.isSafeInteger(maxResponseBytes)||
     maxResponseBytes<2048||maxResponseBytes>MAX_RESPONSE_BYTES){
    deny('PDS_EGRESS_CONFIGURATION_INVALID');
  }
  const allowed=new Set(approvedAddresses.map(ip=>approvedIp(ip,disposable)));
  if(allowed.size!==approvedAddresses.length)deny('PDS_EGRESS_CONFIGURATION_INVALID');
  if(tlsCaForTest!==undefined &&
     (typeof tlsCaForTest!=='string'||tlsCaForTest.length>16384||
      !tlsCaForTest.includes('-----BEGIN CERTIFICATE-----'))) {
    deny('PDS_EGRESS_CONFIGURATION_INVALID');
  }
  const resolver=resolveAddresses??((host)=>systemLookup(host,{all:true}));
  if(typeof resolver!=='function')deny('PDS_EGRESS_CONFIGURATION_INVALID');
  let inFlight=0;
  async function requestPds({expectedOrigin,method,path,redirect}={}){
    if(fixtureOnly===true&&!testGate()) {
      deny('PDS_EGRESS_DISPOSABLE_NOT_RELEASED');
    }
    if(expectedOrigin!==origin||method!=='GET'||redirect!=='manual'){
      deny('PDS_EGRESS_REQUEST_INVALID');
    }
    checkedPath(path);
    if(inFlight>=maxConcurrent)deny('PDS_EGRESS_CAPACITY_EXCEEDED');
    inFlight++;
    let released=false;
    const release=()=>{if(!released){released=true;inFlight--;}};
    try{
      let timer;
      const answers=await Promise.race([
        Promise.resolve().then(()=>resolver(url.hostname)),
        new Promise((_,reject)=>{
          timer=setTimeout(()=>reject(new Error('DNS deadline')),deadlineMs);
          timer.unref?.();
        })
      ]).finally(()=>clearTimeout(timer));
      const pinned=validateAddressAnswers(answers,allowed,disposable);
      const family=pinned.family,ip=pinned.address;
      return await new Promise((resolve,reject)=>{
        const options={
          protocol:'https:',hostname:url.hostname,
          port:url.port?Number(url.port):443,
          path,method:'GET',agent:false,
          servername:url.hostname,rejectUnauthorized:true,
          minVersion:'TLSv1.2',maxHeaderSize:8192,
          lookup:(host,_opts,callback)=>{
            if(host!==url.hostname){
              callback(new Error('Unexpected host lookup'));
              return;
            }
            callback(null,ip,family);
          },
          headers:{accept:'application/json, application/vnd.ipld.car',
            'user-agent':'ActivityPods-Hosted-PDS-Proof/1.0',
            connection:'close'}
        };
        if(disposable&&tlsCaForTest!==undefined)options.ca=tlsCaForTest;
        const req=https.request(options,res=>{
          const status=res.statusCode||0;
          const headers=headerView(res.headers);
          const reported=res.headers['content-length'];
          if(reported!==undefined&&
             (!/^[0-9]+$/u.test(String(reported))||
              Number(reported)>maxResponseBytes)){
            res.destroy();
            release();reject(new Error('PDS_EGRESS_BODY_TOO_LARGE'));
            return;
          }
          if(status!==200){
            // Includes 3xx: never follow Location; never consume a different
            // authority, and never forward its headers or URL to a caller.
            res.destroy();release();
            resolve({status,redirected:status>=300&&status<400,
              headers,body:(async function*(){})()});
            return;
          }
          res.once('close',release);
          res.once('end',release);
          const body=(async function*(){
            let size=0;
            try{
              for await(const bytes of res){
                size+=bytes.length;
                if(size>maxResponseBytes){
                  req.destroy();
                  deny('PDS_EGRESS_BODY_TOO_LARGE');
                }
                yield bytes;
              }
            }finally{
              if(!res.destroyed)res.destroy();
              release();
            }
          })();
          resolve({status,redirected:false,headers,body});
        });
        const deadline=setTimeout(()=>{
          req.destroy(new Error('PDS_EGRESS_DEADLINE_EXCEEDED'));
        },deadlineMs);
        deadline.unref?.();
        req.once('close',()=>clearTimeout(deadline));
        req.once('error',err=>{
          release();
          // Do not leak private hostnames, IP addresses or certificates in
          // error messages; caller knows only the stable PDS refusal code.
          const wrapped=new Error('PDS_EGRESS_CONNECTION_UNAVAILABLE');
          wrapped.code='PDS_EGRESS_CONNECTION_UNAVAILABLE';
          reject(wrapped);
        });
        req.end();
      });
    }catch(e) {
      release();
      if(e?.code&&String(e.code).startsWith('PDS_EGRESS_'))throw e;
      deny('PDS_EGRESS_UNAVAILABLE');
    }
  }
  return Object.freeze({requestPds});
}

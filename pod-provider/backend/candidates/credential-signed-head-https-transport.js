'use strict';

/**
 * NONACTIVATED HTTPS transport for a separately operated credential-head
 * signer. This transports a new random challenge; the existing pinned
 * Ed25519 verifier performs cryptographic validation. TLS authenticity and
 * cryptographic response freshness are different from signer-state
 * monotonicity, which requires an independent custodian + durable audit.
 *
 * No automatic retry, redirect, cached positive result or HTTP fallback.
 */
const https = require('node:https');
const net = require('node:net');
const {Buffer} = require('node:buffer');

const HEX=/^[a-f0-9]{64}$/u;
const NONCE=/^[a-zA-Z0-9_-]{43}$/u;
const B64=/^[a-zA-Z0-9_-]+$/u;
const ENDPOINT_PATH='/v1/credential-head';
const MAX_WIRE=2048;

function deny(code='CREDENTIAL_TRANSPORT_UNAVAILABLE'){
  const error=new Error('Independent credential witness transport unavailable');
  error.code=code;
  throw error;
}
function allowed(fixtureOnly){
  return fixtureOnly===true && process.env.NODE_ENV==='test' &&
    process.env.PAPER_CREDENTIAL_HEAD_DISPOSABLE==='confirmed' &&
    process.env.PAPER_CREDENTIAL_HTTPS_DISPOSABLE==='confirmed';
}
function decode(value,min,max){
  if(typeof value!=='string'||value.length<min||value.length>max||
     !B64.test(value))deny('CREDENTIAL_TRANSPORT_RESPONSE_INVALID');
  let data;
  try {data=Buffer.from(value,'base64url');}
  catch{deny('CREDENTIAL_TRANSPORT_RESPONSE_INVALID')}
  if(data.length===0||data.toString('base64url')!==value)
    deny('CREDENTIAL_TRANSPORT_RESPONSE_INVALID');
  return data;
}

function createDisposableCredentialHeadHttpsTransport({
  endpoint,fixtureOnly=false,timeoutMs=2200,
  testCaPem=null
}={}){
  if(!allowed(fixtureOnly))deny('CREDENTIAL_TRANSPORT_NOT_RELEASED');
  if(typeof endpoint!=='string'||endpoint.length<20||endpoint.length>512||
     !Number.isSafeInteger(timeoutMs)||timeoutMs<150||timeoutMs>3500)
    deny('CREDENTIAL_TRANSPORT_CONFIG_INVALID');
  let u;
  try {u=new URL(endpoint);}
  catch{deny('CREDENTIAL_TRANSPORT_CONFIG_INVALID')}
  if(u.protocol!=='https:'||!u.hostname||u.username||u.password||
     u.search||u.hash||u.pathname!==ENDPOINT_PATH||u.href!==endpoint||
     !/^[a-z0-9.-]{3,253}$/u.test(u.hostname)||
     (net.isIP(u.hostname)!==0&&u.hostname!=='127.0.0.1'))
    deny('CREDENTIAL_TRANSPORT_CONFIG_INVALID');
  if(testCaPem!==null && (u.hostname!=='127.0.0.1'||
      typeof testCaPem!=='string'||Buffer.byteLength(testCaPem)>4096||
      !/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/u.test(testCaPem)))
    deny('CREDENTIAL_TRANSPORT_CA_INVALID');
  if(u.hostname==='127.0.0.1'&&testCaPem===null)
    deny('CREDENTIAL_TRANSPORT_CONFIG_INVALID');
  const trust=testCaPem?{ca:testCaPem}:{};

  async function readHead(challenge){
    if(!allowed(fixtureOnly))deny('CREDENTIAL_TRANSPORT_NOT_RELEASED');
    if(!challenge||challenge.kind!=='paper.credential.challenge.v1'||
       !HEX.test(challenge.subject||'')||!NONCE.test(challenge.nonce||'')||
       typeof challenge.signal?.aborted!=='boolean'||challenge.signal.aborted)
      deny('CREDENTIAL_TRANSPORT_SCOPE_INVALID');
    const payload=Buffer.from(JSON.stringify({
      kind:challenge.kind,subject:challenge.subject,nonce:challenge.nonce
    }));
    let response;
    try{
      response=await new Promise((resolve,reject)=>{
        let settled=false;
        const done=(error,result)=>{
          if(settled)return;
          settled=true;
          if(error)reject(error);else resolve(result);
        };
        const request=https.request({
          protocol:'https:',hostname:u.hostname,port:u.port||443,
          path:ENDPOINT_PATH,method:'POST',rejectUnauthorized:true,
          signal:challenge.signal,
          headers:{
            'Content-Type':'application/json',
            'Accept':'application/json',
            'Cache-Control':'no-store',
            'Pragma':'no-cache',
            'Content-Length':String(payload.length)
          },
          ...trust
        },res=>{
          if(res.statusCode!==200||
             String(res.headers['content-type']||'').toLowerCase()!=='application/json'||
             (res.headers['content-encoding']&&res.headers['content-encoding']!=='identity')||
             (res.headers['content-length']!==undefined&&
              (!/^[0-9]{1,5}$/u.test(String(res.headers['content-length']))||
               Number(res.headers['content-length'])>MAX_WIRE))){
            res.resume();
            done(Error('Unexpected witness HTTP response'));
            return;
          }
          const chunks=[];let size=0;
          res.on('data',part=>{
            if(!(part instanceof Uint8Array)){
              res.destroy();
              done(Error('Invalid witness stream chunk'));
              return;
            }
            size+=part.length;
            if(size>MAX_WIRE){
              res.destroy();
              done(Error('Witness response too large'));
              return;
            }
            chunks.push(Buffer.from(part));
          });
          res.on('error',done);
          res.on('end',()=>done(null,Buffer.concat(chunks,size)));
          res.on('aborted',()=>done(Error('Witness response interrupted')));
        });
        request.setTimeout(timeoutMs,()=>request.destroy(Error('Witness deadline')));
        request.on('error',done);
        request.end(payload);
      });
    }catch{deny()}
    let record;
    try{record=JSON.parse(response.toString('utf8'));}
    catch{deny('CREDENTIAL_TRANSPORT_RESPONSE_INVALID')}
    if(!record||Array.isArray(record)||typeof record!=='object'||
       Object.keys(record).sort().join(',')!=='body,signature')
      deny('CREDENTIAL_TRANSPORT_RESPONSE_INVALID');
    const body=decode(record.body,225,1400);
    const signature=decode(record.signature,86,86);
    if(body.length<170||body.length>1024||signature.length!==64)
      deny('CREDENTIAL_TRANSPORT_RESPONSE_INVALID');
    return Object.freeze({body,signature});
  }
  return Object.freeze({readHead,releaseAccepted:false});
}
module.exports={createDisposableCredentialHeadHttpsTransport};

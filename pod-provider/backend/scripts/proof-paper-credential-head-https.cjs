'use strict';
// NONACTIVATED real TLS transport proof. Uses an ephemeral self-signed cert
// generated in a disposable private directory; no production keys or users.
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const https=require('node:https');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
const {createDisposableCredentialHeadHttpsTransport}=
  require('../candidates/credential-signed-head-https-transport');
const {createDisposableCredentialHeadAuthority}=
  require('../candidates/credential-signed-latest-head');

if(process.env.NODE_ENV!=='test'||
   process.env.PAPER_CREDENTIAL_HEAD_DISPOSABLE!=='confirmed'||
   process.env.PAPER_CREDENTIAL_HTTPS_DISPOSABLE!=='confirmed'||
   process.env.CI!=='true')
  throw Error('Credential HTTPS transport proof is not released');

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'paper-witness-tls-'));
fs.chmodSync(dir,0o700);
const keyPath=path.join(dir,'tls-key.pem'),certPath=path.join(dir,'tls-cert.pem');
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes',
  '-keyout',keyPath,'-out',certPath,'-days','1','-subj','/CN=127.0.0.1',
  '-addext','subjectAltName=IP:127.0.0.1'],{stdio:'ignore'});
const privateTls=fs.readFileSync(keyPath);
const trustedCa=fs.readFileSync(certPath,'utf8');
const clock=1800000000,webId='https://paper.example.org/users/remote-proof';
const authority='separate.custodian.example';
const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
const bogus=crypto.generateKeyPairSync('ed25519');
const domain=Buffer.from('paper:credential:attest:v1\0');
let mode='good',cached=null,calls=0;
const sign=(request,key=privateKey)=>{
  const body=Buffer.from(JSON.stringify({
    kind:'paper.credential.head.v1',authority,subject:request.subject,
    epoch:'3',state:'disabled',digest:'f'.repeat(64),nonce:request.nonce,
    issuedAt:clock
  }));
  return {body:body.toString('base64url'),
    signature:crypto.sign(null,Buffer.concat([domain,body]),key).toString('base64url')};
};
const server=https.createServer({key:privateTls,cert:trustedCa},(req,res)=>{
  calls++;
  let bytes=0,parts=[];
  req.on('data',data=>{
    bytes+=data.length;
    if(bytes>2048){req.destroy();return;}
    parts.push(data);
  });
  req.on('end',()=>{
    if(req.url!=='/v1/credential-head'||req.method!=='POST'||
       req.headers['cache-control']!=='no-store'){
      res.writeHead(400);res.end();return;
    }
    let challenge;
    try{challenge=JSON.parse(Buffer.concat(parts).toString('utf8'));}
    catch{res.writeHead(400);res.end();return;}
    if(challenge?.kind!=='paper.credential.challenge.v1'||
       !/^[0-9a-f]{64}$/u.test(challenge.subject||'')||
       !/^[a-zA-Z0-9_-]{43}$/u.test(challenge.nonce||'')){
      res.writeHead(400);res.end();return;
    }
    if(mode==='redirect'){
      res.writeHead(302,{Location:'https://elsewhere.invalid/v1/credential-head'});
      res.end();return;
    }
    if(mode==='oversize'){
      res.writeHead(200,{'Content-Type':'application/json'});
      res.end('x'.repeat(2100));return;
    }
    if(mode==='invalid-json'){
      res.writeHead(200,{'Content-Type':'application/json'});
      res.end('not JSON');return;
    }
    if(mode==='slow'){
      setTimeout(()=>{
        if(res.destroyed)return;
        res.writeHead(200,{'Content-Type':'application/json'});
        res.end(JSON.stringify(sign(challenge)));
      },500);
      return;
    }
    let reply=sign(challenge,mode==='forged'?bogus.privateKey:privateKey);
    if(mode==='replay'){
      if(!cached)cached=reply;
      reply=cached;
    }
    res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});
    res.end(JSON.stringify(reply));
  });
});

async function denies(fn,code){
  await assert.rejects(fn,e=>e?.code===code,
    'Expected fail-closed error '+code);
}
async function run(){
  try{
    await new Promise((resolve,reject)=>server.listen(0,'127.0.0.1',err=>
      err?reject(err):resolve()));
    const endpoint='https://127.0.0.1:'+server.address().port+'/v1/credential-head';
    const transport=createDisposableCredentialHeadHttpsTransport({
      endpoint,fixtureOnly:true,testCaPem:trustedCa,timeoutMs:250
    });
    const reader=createDisposableCredentialHeadAuthority({
      readHead:transport.readHead,trustedPublicKey:publicKey,
      authority,fixtureOnly:true,now:()=>clock,timeoutMs:1000
    });
    assert.deepEqual((await reader.readFresh(webId)).state,'disabled');
    assert.equal((await reader.readFresh(webId)).epoch,'3');
    assert.equal((await Promise.all(Array.from({length:8},()=>
      reader.readFresh(webId)))).length,8);
    mode='replay';
    await reader.readFresh(webId);
    await denies(()=>reader.readFresh(webId),'CREDENTIAL_HEAD_SCOPE_INVALID');
    mode='forged';cached=null;
    await denies(()=>reader.readFresh(webId),'CREDENTIAL_HEAD_SIGNATURE_INVALID');
    mode='redirect';
    await denies(()=>reader.readFresh(webId),'CREDENTIAL_HEAD_UNAVAILABLE');
    mode='oversize';
    await denies(()=>transport.readHead({
      kind:'paper.credential.challenge.v1',
      subject:'a'.repeat(64),nonce:'b'.repeat(43),
      signal:new AbortController().signal
    }),'CREDENTIAL_TRANSPORT_UNAVAILABLE');
    mode='invalid-json';
    await denies(()=>reader.readFresh(webId),'CREDENTIAL_HEAD_UNAVAILABLE');
    mode='slow';
    await denies(()=>reader.readFresh(webId),'CREDENTIAL_HEAD_UNAVAILABLE');
    const aborted=new AbortController();aborted.abort();
    await denies(()=>transport.readHead({
      kind:'paper.credential.challenge.v1',subject:'a'.repeat(64),
      nonce:'b'.repeat(43),signal:aborted.signal
    }),'CREDENTIAL_TRANSPORT_SCOPE_INVALID');
    await denies(()=>Promise.resolve().then(()=>
      createDisposableCredentialHeadHttpsTransport({
        endpoint:'http://127.0.0.1:4444/v1/credential-head',fixtureOnly:true,
        testCaPem:trustedCa
      })),'CREDENTIAL_TRANSPORT_CONFIG_INVALID');
    await denies(()=>Promise.resolve().then(()=>
      createDisposableCredentialHeadHttpsTransport({
        endpoint: endpoint+'?admin=true',fixtureOnly:true,testCaPem:trustedCa
      })),'CREDENTIAL_TRANSPORT_CONFIG_INVALID');
    await denies(()=>Promise.resolve().then(()=>
      createDisposableCredentialHeadHttpsTransport({
        endpoint,fixtureOnly:true,testCaPem:privateTls.toString('utf8')
      })),'CREDENTIAL_TRANSPORT_CA_INVALID');
    assert.equal(transport.releaseAccepted,false);
    assert.ok(calls>=14);
    console.log('PASS: real TLS signed nonce head, replay/forgery/redirect/oversize/timeout/CA refusal and bounded challenge; NONACTIVATED');
  }finally{
    server.closeAllConnections();
    await new Promise(resolve=>server.close(()=>resolve()));
    fs.rmSync(dir,{recursive:true,force:true});
  }
}
run().catch(error=>{
  console.error('HTTPS credential head proof failed:',error?.code||error?.name);
  process.exitCode=1;
});

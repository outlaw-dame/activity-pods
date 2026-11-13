import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Secp256k1Keypair } from '@atproto/crypto';
import { generateSignedGenesis } from '../candidates/atproto-repo-genesis.mjs';
import { createProviderHandleResolver } from '../candidates/provider-handle-resolver.mjs';
import { verifyPdsReadiness } from '../candidates/atproto-pds-readiness.mjs';

// Disposable loopback-only integration with real HTTP requests, real
// signed v3 CAR, and an independently simulated provider DNS TXT record.
// This is NOT a deployable PDS, PLC directory, or public federation fixture.
const did='did:plc:abcdefghijklmnopqrstuvwx';
const handle='alice.pds.example';
const key=await Secp256k1Keypair.create({exportable:false});
const genesis=await generateSignedGenesis({
  did,signer:{keyDid:key.did(),sign:data=>key.sign(data)}
});
let mode='healthy';
let pdsOrigin='',plcOrigin='';
let repoCalls=0,plcCalls=0;
const pdsServer=createServer((req,res)=>{
  const u=new URL(req.url,'http://127.0.0.1');
  if(req.method!=='GET'||u.searchParams.get('did')!==did) {
    res.writeHead(400).end();return;
  }
  if(u.pathname==='/xrpc/com.atproto.sync.getLatestCommit') {
    assert(req.headers.accept?.includes('application/json'));
    res.writeHead(200,{'content-type':'application/json'});
    res.end(JSON.stringify({
      cid:mode==='wrongCID'?'bafy'+'a'.repeat(40):genesis.rootCid,
      rev:genesis.rev
    }));
    return;
  }
  if(u.pathname==='/xrpc/com.atproto.sync.getRepo') {
    repoCalls++;
    assert(req.headers.accept?.includes('application/vnd.ipld.car'));
    assert(!req.headers.authorization,'Public repo GET must be credential-free');
    if(mode==='redirect') {
      res.writeHead(302,{location:'http://169.254.169.254/latest/meta-data/'});
      res.end();return;
    }
    if(mode==='oversize') {
      res.writeHead(200,{'content-type':'application/vnd.ipld.car'});
      res.end(Buffer.alloc(256*1024+1));return;
    }
    res.writeHead(200,{'content-type':'application/vnd.ipld.car'});
    res.end(genesis.car);return;
  }
  res.writeHead(404).end();
});
const plcServer=createServer((req,res)=>{
  plcCalls++;
  if(req.method!=='GET'||decodeURIComponent(req.url)!=='/'+did) {
    res.writeHead(404).end();return;
  }
  const doc={
    id:did,alsoKnownAs:['at://'+handle],
    verificationMethod:[{
      id:did+'#atproto',type:'Multikey',controller:did,
      publicKeyMultibase:key.did().slice('did:key:'.length)
    }],
    service:[{
      id:did+'#atproto_pds',type:'AtprotoPersonalDataServer',
      serviceEndpoint:pdsOrigin
    }]
  };
  res.writeHead(200,{'content-type':'application/json'});
  res.end(JSON.stringify(doc));
});
async function bind(server){
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  return 'http://127.0.0.1:'+server.address().port;
}
try {
  pdsOrigin=await bind(pdsServer);
  plcOrigin=await bind(plcServer);
  let dnsCalls=0;
  const resolveHandle=createProviderHandleResolver({
    providerDomain:'pds.example',allowFixture:true,
    lookupTxt:async name=>{
      dnsCalls++;
      assert.equal(name,'_atproto.'+handle);
      return [['did='+did]];
    }
  });
  const input={
    did,handle,expectedPdsUrl:pdsOrigin,plcDirectoryUrl:plcOrigin,
    expectedRootCid:genesis.rootCid,expectedRev:genesis.rev,
    resolveHandle,allowFixture:true
  };
  const valid=await verifyPdsReadiness(input);
  assert.equal(valid.did,did);
  assert.equal(valid.rootCid,genesis.rootCid);
  assert.equal(valid.rev,genesis.rev);
  assert.equal(valid.keyDid,key.did());
  assert.equal(valid.carSha256.length,32);
  assert.equal(dnsCalls,1);
  assert.equal(repoCalls,1);
  assert.equal(plcCalls,1);
  const rejects=async(state,code)=>{
    mode=state;
    await assert.rejects(verifyPdsReadiness(input),err=>err.code===code);
    mode='healthy';
  };
  await rejects('wrongCID','PDS_PROOF_LATEST_COMMIT_MISMATCH');
  await rejects('redirect','PDS_PROOF_RESPONSE_INVALID');
  await rejects('oversize','PDS_PROOF_RESPONSE_TOO_LARGE');
  assert.equal(mode,'healthy');
  console.log('atproto_live_loopback_plc_pds_xrpc_and_signed_car_passed');
  console.log('atproto_live_loopback_redirect_cid_size_refusals_passed');
} finally {
  await Promise.all([pdsServer,plcServer].map(server=>new Promise(resolve=>{
    if(!server.listening)return resolve();
    server.close(()=>resolve());
    server.closeAllConnections?.();
  })));
}

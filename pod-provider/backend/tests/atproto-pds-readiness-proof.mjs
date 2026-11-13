import assert from 'node:assert/strict';
import { Secp256k1Keypair } from '@atproto/crypto';
import { generateSignedGenesis } from '../candidates/atproto-repo-genesis.mjs';
import { verifyPdsReadiness } from '../candidates/atproto-pds-readiness.mjs';

const did='did:plc:abcdefghijklmnopqrstuvwx';
const handle='alice.pds.example';
const pds='https://pds.example';
const plc='https://plc.example';
const key=await Secp256k1Keypair.create();
const genesis=await generateSignedGenesis({
  did, signer:{keyDid:key.did(),sign:bytes=>key.sign(bytes)}
});
const doc={
  id:did,alsoKnownAs:[`at://${handle}`],
  verificationMethod:[{
    id:did+'#atproto',controller:did,type:'Multikey',
    publicKeyMultibase:key.did().replace('did:key:','')
  }],
  service:[{id:did+'#atproto_pds',type:'AtprotoPersonalDataServer',serviceEndpoint:pds}]
};
const latest={cid:genesis.rootCid,rev:genesis.rev};
const routes={
  [plc+'/'+encodeURIComponent(did)]:new Response(JSON.stringify(doc),{status:200,headers:{'content-type':'application/json'}}),
  [pds+'/xrpc/com.atproto.sync.getLatestCommit?did='+encodeURIComponent(did)]:
    new Response(JSON.stringify(latest),{status:200,headers:{'content-type':'application/json'}}),
  [pds+'/xrpc/com.atproto.sync.getRepo?did='+encodeURIComponent(did)]:
    new Response(genesis.car,{status:200,headers:{'content-type':'application/vnd.ipld.car'}})
};
const options={
  did,handle,expectedPdsUrl:pds,plcDirectoryUrl:plc,
  expectedRootCid:genesis.rootCid,expectedRev:genesis.rev,
  // A trusted fixture resolver represents DNS TXT or HTTPS well-known
  // lookup outside the PDS; the DID document alone is insufficient.
  resolveHandle:async claimed=>claimed===handle ? did : 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb',
  fetchImpl:async (url, opts)=>{
    assert.equal(opts.redirect,'manual');
    assert.equal(opts.method,'GET');
    const item=routes[url];
    assert(item,'Unexpected URL '+url);
    return item.clone();
  }
};
const verified=await verifyPdsReadiness(options);
assert.equal(verified.rootCid,genesis.rootCid);
assert.equal(verified.rev,genesis.rev);
assert.equal(verified.keyDid,key.did());
assert.equal(verified.carSha256.length,32);
console.log('atproto_pds_plc_repo_and_car_consistency_passed');
const expectError=async (modified,code)=>assert.rejects(
  verifyPdsReadiness({...options,...modified}),err=>err.code===code);
await expectError({resolveHandle:undefined},'PDS_PROOF_HANDLE_RESOLVER_REQUIRED');
await expectError({resolveHandle:async()=> 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb'},
  'PDS_PROOF_HANDLE_MISMATCH');
await expectError({resolveHandle:async()=>{throw new Error('DNS unavailable');}},
  'PDS_PROOF_HANDLE_RESOLUTION_UNAVAILABLE');
await expectError({expectedRootCid:'bafy'+'a'.repeat(50)},'PDS_PROOF_LATEST_COMMIT_MISMATCH');
await expectError({expectedPdsUrl:'http://127.0.0.1:4000'},'PDS_PROOF_INVALID_ORIGIN');
await expectError({allowFixture:true,expectedPdsUrl:'http://169.254.169.254'},
  'PDS_PROOF_INVALID_ORIGIN');
await expectError({allowFixture:true,expectedPdsUrl:'http://192.168.1.10:4000'},
  'PDS_PROOF_INVALID_ORIGIN');
await expectError({allowFixture:true,expectedPdsUrl:'http://evil.test:4000'},
  'PDS_PROOF_INVALID_ORIGIN');
await expectError({expectedPdsUrl:'https://user:pass@pds.example'},'PDS_PROOF_INVALID_ORIGIN');
await expectError({expectedPdsUrl:'https://pds.example/redirect'},'PDS_PROOF_INVALID_ORIGIN');
await expectError({handle:'bob.pds.example'},'PDS_PROOF_HANDLE_MISMATCH');
await expectError({
  handle:'bob.pds.example',resolveHandle:async()=>did
},'PDS_PROOF_DID_DOCUMENT_MISMATCH');
await expectError({fetchImpl:async()=>new Response('',{status:302,headers:{location:'https://evil.example/'}})},
  'PDS_PROOF_RESPONSE_INVALID');
const changedKey=await Secp256k1Keypair.create();
const wrongDoc={...doc,verificationMethod:[{
  id:did+'#atproto',controller:did,
  type:'Multikey',publicKeyMultibase:changedKey.did().replace('did:key:','')
}]};
await expectError({fetchImpl:async url=>(
  url===plc+'/'+encodeURIComponent(did) ? new Response(JSON.stringify(wrongDoc)) : routes[url].clone()
)},'REPO_GENESIS_SIGNATURE_NOT_VERIFIED');
await expectError({fetchImpl:async url=>(
  url===pds+'/xrpc/com.atproto.sync.getRepo?did='+encodeURIComponent(did) ?
  new Response(new Uint8Array(256*1024+1)) : routes[url].clone()
)},'PDS_PROOF_RESPONSE_TOO_LARGE');
console.log('atproto_pds_readiness_refusal_and_bounded_io_passed');

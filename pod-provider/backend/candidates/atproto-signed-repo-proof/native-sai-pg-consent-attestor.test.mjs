import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createDisposableNativeSaiPgAttestor,queryNativeSaiEvidence,
  verifyNativeSaiEvidence} from './native-sai-pg-consent-attestor.mjs';

const flags=['NODE_ENV','ATPROTO_SAI_ACTIVATION_DISPOSABLE',
  'ATPROTO_FUSEKI_ISOLATION_DISPOSABLE'];
const saved=Object.fromEntries(flags.map(key=>[key,process.env[key]]));
function enabled(){
  process.env.NODE_ENV='test';
  process.env.ATPROTO_SAI_ACTIVATION_DISPOSABLE='confirmed';
  process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE='confirmed';
}
enabled();
process.on('exit',()=>{
  for(const [name,value] of Object.entries(saved)){
    if(value===undefined)delete process.env[name];
    else process.env[name]=value;
  }
});
const owner='https://paper.example.org/native-owner';
const app='https://app-e2e.test:3443/app';
const needGroup='https://app-e2e.test:3443/access-need';
const prefix='http://activitypods.org/ns/core#';
const required=['CreateGroup','ManageMembers','ReadGroups'].map(x=>prefix+x);
const scope={owner,app,needGroup,requiredRights:required};
const grant=owner+'/data/access-grants/g1';
const registration=owner+'/data/app-registrations/g1';
const uri=value=>({type:'uri',value});
const valid=()=>required.map(right=>({
  registration:uri(registration),grant:uri(grant),
  registeredBy:uri(owner),registeredAgent:uri(app),
  grantedBy:uri(owner),grantee:uri(app),need:uri(needGroup),
  right:uri(right)
}));
const expectedCode=(fn,code='SAI_ACTIVATION_EVIDENCE_INVALID')=>
  assert.throws(fn,error=>error?.code===code);

test('native SAI attestation requires explicit disposable consent scope',()=>{
  const previous=process.env.NODE_ENV;
  try{
    process.env.NODE_ENV='production';
    expectedCode(()=>verifyNativeSaiEvidence(valid(),scope),'SAI_ACTIVATION_NOT_RELEASED');
    expectedCode(()=>queryNativeSaiEvidence(scope),'SAI_ACTIVATION_NOT_RELEASED');
  }finally{process.env.NODE_ENV=previous;}
});
test('canonical SPARQL query is fixed, bounded and scoped to authentic owner',()=>{
  enabled();
  const query=queryNativeSaiEvidence(scope);
  assert.match(query,/LIMIT 65/);
  assert.ok(query.includes('<'+owner+'>'));
  assert.ok(query.includes('i:registeredAgent <'+app+'>'));
  assert.ok(query.includes('i:hasAccessNeedGroup <'+needGroup+'>'));
  assert.match(query,/i:hasRegistrySet\/i:hasAgentRegistry/);
  assert.match(query,/i:hasAccessGrant/);
  assert.match(query,/OPTIONAL \{ \?grant apods:hasSpecialRights \?right/);
  const result=verifyNativeSaiEvidence(valid().reverse(),scope);
  assert.equal(result.grant,grant);
  assert.equal(result.registration,registration);
  assert.deepEqual(result.rights,required);
  assert.equal(result.digest.length,32);
  assert.deepEqual(result.digest,verifyNativeSaiEvidence(valid(),scope).digest);
});
test('invalid owner or app never builds SPARQL with user-submitted syntax',()=>{
  enabled();
  for(const bad of [
    {...scope,owner:'https://paper.example.org/a> ?s ?p ?o'},
    {...scope,app:'https://app-e2e.test:3443/app?hack=true'},
    {...scope,owner:'http://paper.example.org/non-tls'},
    {...scope,needGroup:'https://example.org/g#part'},
    {...scope,requiredRights:['http://evil.example/grant']},
    {...scope,requiredRights:[]},
    {...scope,requiredRights:required.concat(required[0])},
    {...scope,requiredRights:'CreateGroup'},
    {...scope,optionalRights:[required[1]]}
  ])expectedCode(()=>queryNativeSaiEvidence(bad));
});
test('typed native SAI evidence fails closed on duplicates, missing and contradictory grants',()=>{
  enabled();
  const row=(change,index=0)=>{
    const copy=valid();
    copy[index]={...copy[index],...change};
    return copy;
  };
  for(const malformed of [
    [],
    valid().slice(1),
    [...valid(),valid()[0]],
    [...valid(),{...valid()[0],grant:uri(owner+'/data/access-grants/second')}],
    row({registeredBy:uri('https://other.example/user')}),
    row({registeredAgent:uri('https://other.example/app')}),
    row({grantee:uri('https://other.example/app')}),
    row({grantedBy:uri('https://other.example/user')}),
    row({need:uri('https://app-e2e.test:3443/wrong-need')}),
    row({registration:uri('https://other.example/app-reg')}),
    row({grant:uri('https://other.example/grant')}),
    row({right:uri(prefix+'UnapprovedAdmin')}),
    row({right:{type:'literal',value:required[0]}}),
    row({registration:{type:'literal',value:registration}}),
    Array.from({length:65},()=>valid()[0])
  ])expectedCode(()=>verifyNativeSaiEvidence(malformed,scope));
});
const pgRole=()=>({
  self_login:true,restricted:true,attestor:true,
  issuer_member:false,importer_member:false,revoker_member:false,
  dml:false,attest_exec:true,confirm_exec:true,begin_exec:false
});
test('privileged or cross-role SQL attestor login is rejected before RDF query',async()=>{
  enabled();
  let read=0;
  const create=async role=>createDisposableNativeSaiPgAttestor({
    config:scope,fixtureOnly:true,
    readNativeSai:async()=>{read++;return valid();},
    pool:{query:async()=>({rowCount:1,rows:[role]})}
  });
  for(const role of [
    {...pgRole(),issuer_member:true},
    {...pgRole(),attestor:false},
    {...pgRole(),dml:true},
    {...pgRole(),confirm_exec:false},
    {...pgRole(),begin_exec:true}
  ]){
    await assert.rejects(create(role),
      e=>e?.code==='SAI_ACTIVATION_ATTESTOR_PRIVILEGES_UNSAFE');
  }
  assert.equal(read,0);
});
test('independent PG confirmation denies a revocation between Jena readback and return',async()=>{
  enabled();
  const operationId='0c716788-f719-4f25-a313-51152720d879';
  let reads=0,confirmations=0;
  const pool={async query(text){
    if(text.includes('FROM pg_catalog.pg_roles'))return{rowCount:1,rows:[pgRole()]};
    if(text.includes('attest_owner_consent'))return{rowCount:1,rows:[{accepted:true}]};
    if(text.includes('confirm_owner_consent')){
      confirmations++;
      return{rowCount:1,rows:[{accepted:false}]};
    }
    assert.fail('Unexpected privileged SQL access');
  }};
  const attestor=await createDisposableNativeSaiPgAttestor({
    pool,config:scope,fixtureOnly:true,
    readNativeSai:async()=>{reads++;return valid();}
  });
  await assert.rejects(attestor.attest({
    did:'did:plc:'+'a'.repeat(24),operationId
  }),e=>e?.code==='SAI_ACTIVATION_PENDING_OR_REVOKED');
  assert.equal(reads,2);
  assert.equal(confirmations,1);
});

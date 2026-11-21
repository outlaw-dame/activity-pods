import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createDisposableJournalBoundSaiAttestor} from './journal-bound-sai-pg-attestor.mjs';
const flags=['NODE_ENV','ATPROTO_SAI_ACTIVATION_DISPOSABLE',
 'ATPROTO_FUSEKI_ISOLATION_DISPOSABLE','PAPER_JOURNAL_BOUND_SAI_DISPOSABLE'];
const saved=Object.fromEntries(flags.map(k=>[k,process.env[k]]));
process.on('exit',()=>{
 for(const [k,v] of Object.entries(saved)){
  if(v===undefined)delete process.env[k];else process.env[k]=v;
 }
});
function enabled(){
 process.env.NODE_ENV='test';
 process.env.ATPROTO_SAI_ACTIVATION_DISPOSABLE='confirmed';
 process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE='confirmed';
 process.env.PAPER_JOURNAL_BOUND_SAI_DISPOSABLE='confirmed';
}
enabled();
const owner='https://paper.example.org/member01';
const app='https://app-e2e.test:3443/app';
const needGroup='https://app-e2e.test:3443/need';
const registration=owner+'/data/app-registrations/one';
const grant=owner+'/data/access-grants/one';
const required=['CreateGroup','ReadGroups','ManageMembers'].map(r=>
 'http://activitypods.org/ns/core#'+r);
const config={owner,app,needGroup,requiredRights:required};
const row=v=>({type:'uri',value:v});
const evidence=()=>required.map(right=>({
 registration:row(registration),grant:row(grant),
 registeredBy:row(owner),registeredAgent:row(app),
 grantedBy:row(owner),grantee:row(app),
 need:row(needGroup),right:row(right)
}));
const role=()=>({
 version:180000,own_login:true,restricted:true,member:true,
 can_switch:false,issuer:false,importer:false,revoker:false,
 schema_create:false,table_rights:false,column_rights:false,
 attest:true,confirm:true,begin:false,legacy_begin:false,legacy_attest:false,
 memberships:1,unsafe_memberships:0,parent_memberships:0
});
const ids={reservationId:'e15441be-fda9-43f2-af94-9738d97cd1a8',
 operationId:'136fbe40-4eb1-4a89-b6d0-e96fbc71aebb'};
function fixture({roleData=role(),reads,pg={attest:true,confirm:true}}={}){
 const calls=[];const released=[];let next=0,leases=0;
 const pool={async connect(){
  const id=++leases;
  return {
   async query(sql,values){
    calls.push({sql,values,lease:id});
    if(sql.includes('FROM pg_catalog.pg_roles'))return {rowCount:1,rows:[roleData]};
    if(sql.includes('attest_bound_owner_consent'))return {rowCount:1,rows:[{accepted:pg.attest}]};
    if(sql.includes('confirm_bound_owner_consent'))return {rowCount:1,rows:[{accepted:pg.confirm}]};
    assert.fail('Unexpected PG SQL');
   },
   release(discard=false){released.push({lease:id,discard});}
  };
 }};
 const readNativeSai=async()=>reads?reads[next++]||reads.at(-1):evidence();
 return {pool,calls,released,readNativeSai};
}
const fails=(fn,code)=>assert.rejects(fn(),e=>e?.code===code);
test('fails closed in production even with synthetic fixture credentials',async()=>{
 process.env.NODE_ENV='production';
 const f=fixture();
 await fails(()=>createDisposableJournalBoundSaiAttestor({
  ...f,config,fixtureOnly:true}),'JOURNAL_SAI_NOT_RELEASED');
 enabled();
});
test('requires exact narrow Postgres attestor role with no legacy execute',async()=>{
 enabled();
 for(const bad of [
  {issuer:true},{can_switch:true},{table_rights:true},{column_rights:true},
  {legacy_attest:true},{legacy_begin:true},{attest:false},{confirm:false},
  {memberships:2},{unsafe_memberships:1},{parent_memberships:1},
  {version:170000},{importer:true},{revoker:true}
 ]){
  const f=fixture({roleData:{...role(),...bad}});
  await fails(()=>createDisposableJournalBoundSaiAttestor({
   ...f,config,fixtureOnly:true}),'JOURNAL_SAI_ATTESTOR_ROLE_UNSAFE');
  assert.equal(f.calls.length,1);
 }
});
test('two real typed reads precede bounded PG attestation and current journal confirmation',async()=>{
 enabled();
 const f=fixture();
 const attestor=await createDisposableJournalBoundSaiAttestor({
  ...f,config,fixtureOnly:true});
 const result=await attestor.attest(ids);
 assert.equal(result.attested,true);
 assert.equal(result.productionReady,false);
 assert.equal(result.status,'evidence_only');
 assert.equal(result.grantUri,grant);
 assert.equal(result.registrationUri,registration);
 assert.equal(result.evidenceSha256.length,64);
 assert.equal(f.calls.length,4);
 assert.deepEqual(f.calls.map(c=>c.lease),[1,2,2,2],
   'Role audit and both privileged CAS checks share one connection');
 assert.deepEqual(f.released,[{lease:1,discard:false},{lease:2,discard:false}]);
 const attest=f.calls[2],confirm=f.calls[3];
 assert.match(attest.sql,/attest_bound_owner_consent/);
 assert.match(confirm.sql,/confirm_bound_owner_consent/);
 assert.equal(attest.values[0],ids.reservationId);
 assert.equal(attest.values[1],ids.operationId);
 assert.equal(attest.values[2],registration);
 assert.equal(attest.values[3],grant);
 assert.equal(confirm.values[4].toString('hex'),attest.values[4].toString('hex'));
});
test('attestor cannot report success if the owner revoked before final PG confirm',async()=>{
 enabled();
 const f=fixture({pg:{attest:true,confirm:false}});
 const attestor=await createDisposableJournalBoundSaiAttestor({
  ...f,config,fixtureOnly:true});
 await fails(()=>attestor.attest(ids),'JOURNAL_SAI_SCOPE_STALE_OR_REVOKED');
 assert.equal(f.calls.length,4);
 assert.deepEqual(f.released,[{lease:1,discard:false},{lease:2,discard:true}]);
});
test('changed Jena rights after initial PG CAS are never a successful attestation',async()=>{
 enabled();
 const f=fixture({reads:[evidence(),evidence().slice(0,2)]});
 const attestor=await createDisposableJournalBoundSaiAttestor({
  ...f,config,fixtureOnly:true});
 await fails(()=>attestor.attest(ids),'SAI_ACTIVATION_EVIDENCE_INVALID');
 assert.equal(f.calls.length,3,'No stale final PG confirmation after bad RDF');
});
test('changed registration or unexpected right is denied without a final PG confirmation',async()=>{
 enabled();
 const changed=evidence().map(x=>({...x,registration:row(owner+'/data/app-registrations/changed')}));
 const f=fixture({reads:[evidence(),changed]});
 const attestor=await createDisposableJournalBoundSaiAttestor({
  ...f,config,fixtureOnly:true});
 await fails(()=>attestor.attest(ids),'JOURNAL_SAI_RDF_CHANGED');
 assert.equal(f.calls.length,3);
});
test('neither client-supplied UUID nor missing SQL attestation can authorize',async()=>{
 enabled();
 const f=fixture({pg:{attest:false,confirm:true}});
 const attestor=await createDisposableJournalBoundSaiAttestor({
  ...f,config,fixtureOnly:true});
 await fails(()=>attestor.attest({...ids,reservationId:'foreign-reservation'}),
  'JOURNAL_SAI_OPERATION_INVALID');
 await fails(()=>attestor.attest(ids),'JOURNAL_SAI_SCOPE_STALE_OR_REVOKED');
 assert.equal(f.calls.length,3);
});

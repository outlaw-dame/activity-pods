'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createDisposableJournalBoundConsentIssuer}=require('./journal-bound-consent-issuer');
const stored=Object.fromEntries(['NODE_ENV','PAPER_ACCOUNTS_DISPOSABLE',
  'PAPER_JOURNAL_BOUND_SAI_DISPOSABLE'].map(x=>[x,process.env[x]]));
process.on('exit',()=>{
  for(const [key,value] of Object.entries(stored)){
    if(value===undefined)delete process.env[key];
    else process.env[key]=value;
  }
});
function enabled(){
  process.env.NODE_ENV='test';
  process.env.PAPER_ACCOUNTS_DISPOSABLE='confirmed';
  process.env.PAPER_JOURNAL_BOUND_SAI_DISPOSABLE='confirmed';
}
enabled();
const providerId='https://paper.example.org';
const browserOrigin='https://app-e2e.test:3443';
const tokenHash=Buffer.alloc(32,0xa4);
const approved=()=>({
  version:180000,own_login:true,restricted:true,issuer:true,can_switch:false,
  attestor:false,importer:false,revoker:false,schema_create:false,
  table_access:false,column_access:false,begin_session:true,
  begin_raw:false,begin_legacy:false,attest:false,confirm:false,
  memberships:1,bad_options:0,parent_roles:0
});
function fixture({loginByLease,allowed=true,failStatement=false}={}){
  let n=0;const calls=[],releases=[];
  const pool={async connect(){
    const lease=++n,permissions=loginByLease?.[lease-1]||approved();
    return {
      async query(input){
        const sql=typeof input==='string'?input:input.text;
        calls.push({lease,sql,values:input?.values||[]});
        if(sql.includes('FROM pg_catalog.pg_roles'))return {rowCount:1,rows:[permissions]};
        if(sql.includes('begin_session_owner_consent')){
          if(failStatement)throw Error('backend transient error with hidden DSN');
          return {rowCount:1,rows:[{allowed}]};
        }
        assert.fail('Unexpected SQL statement');
      },
      release(discard=false){releases.push({lease,discard});}
    };
  }};
  const options={pool,providerId,browserOrigin,fixtureOnly:true};
  const request={providerId,origin:browserOrigin,tokenHash};
  return {options,request,calls,releases};
}
const refuses=(fn,code)=>assert.rejects(fn(),e=>e?.code===code);

test('production/incorrect flags prevent construction and SQL work',()=>{
  const old=process.env.NODE_ENV;
  process.env.NODE_ENV='production';
  try{
    assert.throws(()=>createDisposableJournalBoundConsentIssuer(fixture().options),
      e=>e?.code==='OWNER_CONSENT_ISSUER_NOT_RELEASED');
  }finally{process.env.NODE_ENV=old;}
});
test('only actual authorized browser scope passes to SQL, never raw reservation IDs',async()=>{
  enabled();
  const f=fixture(),service=createDisposableJournalBoundConsentIssuer(f.options);
  for(const wrong of [
    {...f.request,providerId:'https://another.example.org'},
    {...f.request,origin:'https://attacker.example.org'},
    {...f.request,tokenHash:Buffer.alloc(31)},
    {...f.request,tokenHash:Buffer.alloc(33)},
    {...f.request,tokenHash:'a'.repeat(64)}
  ])await refuses(()=>service.reserve(wrong),'OWNER_CONSENT_ISSUER_SCOPE_INVALID');
  assert.equal(f.calls.length,0,'Invalid scope cannot acquire a PG connection');
  assert.equal(await service.reserve(f.request),true);
  assert.deepEqual(f.calls.map(x=>x.lease),[1,1]);
  assert.match(f.calls[0].sql,/pg_catalog\.pg_roles/);
  assert.match(f.calls[1].sql,/begin_session_owner_consent/);
  assert.deepEqual(f.calls[1].values,[providerId,browserOrigin,tokenHash]);
  assert.deepEqual(f.releases,[{lease:1,discard:false}]);
});
test('multiple pooled sessions recheck current LOGIN before every CAS',async()=>{
  enabled();
  const f=fixture({loginByLease:[approved(),{...approved(),attestor:true}]});
  const service=createDisposableJournalBoundConsentIssuer(f.options);
  assert.equal(await service.reserve(f.request),true);
  await refuses(()=>service.reserve(f.request),'OWNER_CONSENT_ISSUER_ROLE_UNSAFE');
  assert.deepEqual(f.calls.map(x=>x.lease),[1,1,2]);
  assert.deepEqual(f.releases,[{lease:1,discard:false},{lease:2,discard:true}]);
});
test('reject privileges that could bypass a session-scoped SQL grant',async()=>{
  enabled();
  for(const bad of [
    {can_switch:true},{attestor:true},{importer:true},{revoker:true},
    {schema_create:true},{table_access:true},{column_access:true},
    {begin_session:false},{begin_raw:true},{begin_legacy:true},
    {attest:true},{confirm:true},{memberships:2},
    {bad_options:1},{parent_roles:1},{version:170000}
  ]){
    const f=fixture({loginByLease:[{...approved(),...bad}]});
    const service=createDisposableJournalBoundConsentIssuer(f.options);
    await refuses(()=>service.reserve(f.request),'OWNER_CONSENT_ISSUER_ROLE_UNSAFE');
    assert.equal(f.calls.length,1,'Unsafe SQL role must not execute pending grant CAS');
    assert.deepEqual(f.releases,[{lease:1,discard:true}]);
  }
});
test('SQL denial and ambiguous backend failure never produce an approved grant',async()=>{
  enabled();
  const denied=fixture({allowed:false});
  const deniedService=createDisposableJournalBoundConsentIssuer(denied.options);
  await refuses(()=>deniedService.reserve(denied.request),
    'OWNER_CONSENT_ISSUER_JOURNAL_NOT_CURRENT');
  assert.equal(denied.calls.length,2);
  assert.deepEqual(denied.releases,[{lease:1,discard:true}]);
  const failed=fixture({failStatement:true});
  const service=createDisposableJournalBoundConsentIssuer(failed.options);
  await refuses(()=>service.reserve(failed.request),'OWNER_CONSENT_ISSUER_UNAVAILABLE');
  assert.equal(failed.calls.length,2,'Never retry an ambiguous SQL write');
  assert.deepEqual(failed.releases,[{lease:1,discard:true}]);
});

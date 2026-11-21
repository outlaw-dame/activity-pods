/**
 * NON-ACTIVATED: independent native SAI readback before canonical PG consent
 * activation. No ordinary SemApps credential or browser may call this code.
 * This candidate requires an explicit disposable provider test marker.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const INTEROP='http://www.w3.org/ns/solid/interop#';
const APODS='http://activitypods.org/ns/core#';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const DID=/^did:plc:[a-z2-7]{24}$/u;
const MAX_ROWS=64;
function fail(code='SAI_ACTIVATION_EVIDENCE_INVALID'){
  const e=new Error('Owner-consent protected native SAI evidence refused');
  e.code=code;throw e;
}
function guard(){
  if(process.env.NODE_ENV!=='test'||
      process.env.ATPROTO_SAI_ACTIVATION_DISPOSABLE!=='confirmed'||
      process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'){
    fail('SAI_ACTIVATION_NOT_RELEASED');
  }
}
function https(value){
  if(typeof value!=='string'||value.length<8||value.length>2048)fail();
  let u;
  try{u=new URL(value);}catch{fail();}
  if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash||
      u.href!==value)fail();
  return value;
}
function scope(value){
  if(!value||typeof value!=='object')fail();
  const owner=https(value.owner);
  const app=https(value.app);
  const needGroup=https(value.needGroup);
  const required=value.requiredRights,optional=value.optionalRights||[];
  const rights=[...required||[],...optional];
  if(!Array.isArray(required)||required.length<1||required.length>16||
      !Array.isArray(optional)||optional.length>32||
      rights.length>48||new Set(rights).size!==rights.length||
      rights.some(v=>typeof v!=='string'||!v.startsWith(APODS)||
        !/^[A-Za-z][A-Za-z0-9]*$/u.test(v.slice(APODS.length)))){
    fail();
  }
  return Object.freeze({owner,app,needGroup,
    requiredRights:Object.freeze([...required].sort()),
    optionalRights:Object.freeze([...optional].sort())});
}
function bindingUri(row,name){
  const entry=row?.[name];
  if(!entry||entry.type!=='uri'||typeof entry.value!=='string')fail();
  return entry.value;
}
export function queryNativeSaiEvidence(config){
  guard();const s=scope(config);
  // Restrict to the authentic owner's registry; OPTIONAL keeps empty-rights
  // grants visible as contradictions. At the cap, reject instead of silently
  // accepting a partial SPARQL result.
  return [
    'PREFIX i: <'+INTEROP+'>',
    'PREFIX apods: <'+APODS+'>',
    'SELECT ?registration ?grant ?registeredBy ?registeredAgent',
    ' ?grantedBy ?grantee ?need ?right WHERE {',
    ' <'+s.owner+'> i:hasRegistrySet/i:hasAgentRegistry ?registry .',
    ' ?registry i:hasApplicationRegistration ?registration .',
    ' ?registration a i:ApplicationRegistration ;',
    '   i:registeredBy ?registeredBy ; i:registeredAgent ?registeredAgent ;',
    '   i:hasAccessGrant ?grant .',
    ' ?grant a i:AccessGrant ; i:grantedBy ?grantedBy ;',
    '   i:grantee ?grantee ; i:hasAccessNeedGroup ?need .',
    ' OPTIONAL { ?grant apods:hasSpecialRights ?right . }',
    '} LIMIT '+(MAX_ROWS+1)
  ].join('\n');
}
export function verifyNativeSaiEvidence(bindings,config){
  guard();const s=scope(config);
  if(!Array.isArray(bindings)||bindings.length<1||bindings.length>MAX_ROWS)fail();
  const registrations=new Set(),grants=new Set(),rights=new Set();
  const allow=new Set([...s.requiredRights,...s.optionalRights]);
  for(const row of bindings){
    const registration=https(bindingUri(row,'registration'));
    const grant=https(bindingUri(row,'grant'));
    // Bound every row, not just one randomly selected matching grant.
    if(bindingUri(row,'registeredBy')!==s.owner ||
       bindingUri(row,'registeredAgent')!==s.app ||
       bindingUri(row,'grantedBy')!==s.owner ||
       bindingUri(row,'grantee')!==s.app ||
       bindingUri(row,'need')!==s.needGroup ||
       !registration.startsWith(s.owner+'/')||
       !grant.startsWith(s.owner+'/'))fail();
    registrations.add(registration);grants.add(grant);
    if(row.right!==undefined){
      const right=bindingUri(row,'right');
      if(!allow.has(right)||rights.has(right))fail();
      rights.add(right);
    }
  }
  if(registrations.size!==1||grants.size!==1||
     s.requiredRights.some(right=>!rights.has(right)))fail();
  const registration=[...registrations][0],grant=[...grants][0];
  const canonical=JSON.stringify([s.owner,s.app,s.needGroup,registration,
    grant,[...rights].sort()]);
  const digest=crypto.createHash('sha256')
    .update('paper:protected-native-sai:readback:v1\0')
    .update(canonical).digest();
  return Object.freeze({owner:s.owner,app:s.app,registration,grant,
    rights:Object.freeze([...rights].sort()),digest});
}
export function createDisposableNativeSaiReader({
  origin,username,password,fixtureOnly=false
}={}){
  guard();
  if(fixtureOnly!==true||origin!=='http://127.0.0.1:3041'||
     username!=='fixture-attestor'||password!=='fixture-attestor-only')fail();
  const auth='Basic '+Buffer.from(username+':'+password).toString('base64');
  return async config=>{
    const query=queryNativeSaiEvidence(config);
    const res=await fetch(origin+'/protected-proof/query',{
      method:'POST',redirect:'error',signal:AbortSignal.timeout(6000),
      headers:{authorization:auth,'content-type':'application/sparql-query',
        accept:'application/sparql-results+json'},
      body:query
    });
    if(res.status!==200||!/^application\/sparql-results\+json(?:;|$)/iu.test(
      res.headers.get('content-type')||''))fail('SAI_ACTIVATION_JENA_UNAVAILABLE');
    let size=0;const buffers=[];
    if(!res.body)fail('SAI_ACTIVATION_JENA_UNAVAILABLE');
    try{
      for await(const chunk of res.body){
        size+=chunk.byteLength;
        if(size>65536)fail('SAI_ACTIVATION_JENA_OVERSIZE');
        buffers.push(Buffer.from(chunk));
      }
    }finally{await res.body.cancel().catch(()=>{});}
    let data;
    try{data=JSON.parse(Buffer.concat(buffers).toString('utf8'));}
    catch{fail('SAI_ACTIVATION_JENA_INVALID');}
    return data?.results?.bindings;
  };
}
export async function createDisposableNativeSaiPgAttestor({
  pool,readNativeSai,config,fixtureOnly=false
}={}){
  guard();
  const s=scope(config);
  if(fixtureOnly!==true||typeof pool?.query!=='function'||
     typeof readNativeSai!=='function')fail('SAI_ACTIVATION_CONFIGURATION_INVALID');
  // Independent SQL LOGIN: cannot change PG tables, mint initial receipts,
  // SET ROLE to schema owner, or inherit the issuer/revoker privileges.
  const q=await pool.query(
    "SELECT current_user=session_user AS self_login, "+
    "NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR "+
    "r.rolreplication OR r.rolbypassrls) AS restricted, "+
    "pg_catalog.pg_has_role(current_user,'paper_atproto_consent_attestor','USAGE') AS attestor, "+
    "pg_catalog.pg_has_role(current_user,'paper_atproto_consent_issuer','MEMBER') AS issuer_member, "+
    "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer_member, "+
    "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_revoker','MEMBER') AS revoker_member, "+
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','UPDATE,INSERT,DELETE') AS dml, "+
    "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.attest_owner_consent(text,text,text,uuid,text,bytea)','EXECUTE') AS attest_exec, "+
    "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.begin_owner_consent(text,text,text,uuid,bytea)','EXECUTE') AS begin_exec "+
    "FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"
  ).catch(()=>fail('SAI_ACTIVATION_ATTESTOR_PRIVILEGES_UNSAFE'));
  const role=q.rows?.[0];
  if(q.rowCount!==1||role.self_login!==true||role.restricted!==true||
     role.attestor!==true||role.issuer_member!==false||
     role.importer_member!==false||role.revoker_member!==false||
     role.dml!==false||role.attest_exec!==true||role.begin_exec!==false) {
    fail('SAI_ACTIVATION_ATTESTOR_PRIVILEGES_UNSAFE');
  }
  const inspect=async()=>{
    const evidence=verifyNativeSaiEvidence(await readNativeSai(s),s);
    return evidence;
  };
  return Object.freeze({
    async attest({did,operationId}){
      guard();
      if(typeof did!=='string'||!DID.test(did)||!UUID.test(operationId||''))fail();
      const before=await inspect();
      const result=await pool.query(
        'SELECT paper_atproto_authority.attest_owner_consent('+
        '$1::text,$2::text,$3::text,$4::uuid,$5::text,$6::bytea) AS accepted',
        [s.owner,did,s.app,operationId,before.grant,before.digest]);
      if(result.rowCount!==1||result.rows[0].accepted!==true){
        fail('SAI_ACTIVATION_PENDING_OR_REVOKED');
      }
      // The first Jena read and SQL update cannot share an atomic transaction.
      // Repeat the independent check to catch in-flight changes before return.
      const after=await inspect();
      if(after.grant!==before.grant||
         !crypto.timingSafeEqual(after.digest,before.digest)){
        fail('SAI_ACTIVATION_NATIVE_EVIDENCE_CHANGED');
      }
      return Object.freeze({attested:true,grantUri:after.grant,
        digest:after.digest.toString('hex')});
    },
    inspect
  });
}

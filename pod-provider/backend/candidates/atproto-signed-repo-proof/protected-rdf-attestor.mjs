/**
 * NONACTIVATED protected-RDF readback + SQL receipt, in a distinct process
 * from both the Jena projection writer and PostgreSQL projection/ACK login.
 *
 * The reader uses an independently configured read-only Fuseki principal
 * and a fixed dataset/subject. A generic SPARQL endpoint, Pod URL or graph
 * cannot be selected by a request. No production activation.
 */
import crypto from 'node:crypto';
import {assertRestrictedRdfAttestorLogin} from './pg-protected-rdf-attestor-role.mjs';

const NS='http://activitypods.org/ns/core#';
const XSD='http://www.w3.org/2001/XMLSchema#';
const RDF_TYPE='http://www.w3.org/1999/02/22-rdf-syntax-ns#type';
const BINDING_TYPE=NS+'AtprotoIdentityBinding';
const FIELDS=Object.freeze([
  'canonicalAccountId','webId','activityPubActorId','atprotoDid',
  'atprotoManaged','atprotoSource','status','repoInitialized',
  'repoRootCid','repoRev','repoProjectionFence'
]);
const PREDICATES=Object.freeze([...FIELDS.map(x=>NS+x),RDF_TYPE]);
const FIELD_SET=new Set(PREDICATES);
const URI_FIELDS=new Set(['webId','activityPubActorId']);
const BOOLEAN_FIELDS=new Set(['atprotoManaged','repoInitialized']);
const STRING_FIELDS=new Set(FIELDS.filter(field=>
  !URI_FIELDS.has(field)&&!BOOLEAN_FIELDS.has(field)&&
  field!=='repoProjectionFence'
));
const DID=/^did:plc:[a-z2-7]{24}$/u;
const CID=/^bafyre[a-z2-7]{53}$/u;
const TID=/^[234567abcdefghij][234567abcdefghijklmnopqrstuvwxyz]{12}$/u;
const INT=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const SUBJECT='urn:paper:atproto:proof:attested-binding';
function deny(code='PROTECTED_RDF_ATTESTATION_INVALID'){
  const e=new Error('Independent protected RDF attestation refused');
  e.code=code;throw e;
}
function canonical(value){
  if(typeof value!=='string'||value.length>2048)return false;
  try{const u=new URL(value);return u.protocol==='https:'&&
    u.href===value&&!u.search&&!u.hash&&!u.username&&!u.password;}
  catch{return false;}
}
function enabled(){
  return process.env.NODE_ENV==='test'&&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_PROJECTION_ROLE_TEST_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE==='confirmed';
}
function scope(p,{requireLeaseOwner=true}={}){
  if(!p||!canonical(p.accountId)||!canonical(p.appUri)||
     !canonical(p.grantUri)||!DID.test(p.did||'')||
     !CID.test(p.commitCid||'')||!CID.test(p.rootCid||'')||
     !TID.test(p.rev||'')||!INT.test(p.leaseEpoch||'')||
     !INT.test(p.consentRevision||'')||
     BigInt(p.leaseEpoch)>MAX||BigInt(p.consentRevision)>MAX||
     (requireLeaseOwner &&
       (typeof p.leaseOwner!=='string' ||
        !/^\{?[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\}?$/iu.test(p.leaseOwner)))||
     !Number.isSafeInteger(p.generation)||p.generation<1){
    deny();
  }
  return p;
}
function one(rows,p){
  if(!Array.isArray(rows)||rows.length!==PREDICATES.length)deny('PROTECTED_RDF_CARDINALITY_INVALID');
  const values=new Map();
  for(const row of rows){
    const predicate=row?.p?.value,object=row?.o;
    if(!FIELD_SET.has(predicate)||!object||typeof object.value!=='string'||
       values.has(predicate)||!['uri','literal','typed-literal'].includes(object.type)){
      deny('PROTECTED_RDF_CARDINALITY_INVALID');
    }
    values.set(predicate,object);
  }
  // A correct-looking field set is not a binding without the same RDF
  // class that the atomic projection CAS requires. Other rdf:types on the
  // resource are allowed; the fixed query selects this class specifically.
  const type=values.get(RDF_TYPE);
  if(!type||type.type!=='uri'||type.value!==BINDING_TYPE||
     type.datatype!==undefined||type['xml:lang']!==undefined){
    deny('PROTECTED_RDF_BINDING_TYPE_INVALID');
  }
  const expected={
    canonicalAccountId:p.accountId,webId:p.accountId,
    activityPubActorId:p.accountId,atprotoDid:p.did,
    atprotoManaged:'true',atprotoSource:'local',status:'active',
    repoInitialized:'true',repoRootCid:p.rootCid,
    repoRev:p.rev,repoProjectionFence:p.leaseEpoch
  };
  for(const [field,want] of Object.entries(expected)){
    const val=values.get(NS+field);
    if(!val||val.value!==want)deny('PROTECTED_RDF_READBACK_MISMATCH');
    if(val['xml:lang']!==undefined||val.lang!==undefined){
      deny('PROTECTED_RDF_READBACK_MISMATCH');
    }
    if(URI_FIELDS.has(field)){
      if(val.type!=='uri'||val.datatype!==undefined){
        deny('PROTECTED_RDF_READBACK_MISMATCH');
      }
    }else{
      if(!['literal','typed-literal'].includes(val.type)){
        deny('PROTECTED_RDF_READBACK_MISMATCH');
      }
      if(STRING_FIELDS.has(field) &&
         val.datatype!==undefined && val.datatype!==XSD+'string'){
        deny('PROTECTED_RDF_READBACK_MISMATCH');
      }
      if(BOOLEAN_FIELDS.has(field)&&val.datatype!==XSD+'boolean'){
        deny('PROTECTED_RDF_READBACK_MISMATCH');
      }
      if(field==='repoProjectionFence'&&val.datatype!==XSD+'integer'){
        deny('PROTECTED_RDF_READBACK_MISMATCH');
      }
    }
  }
  // One deterministic digest of the observed *typed* RDF terms (not a
  // hash of client assertions). SQL stores only the bounded 32-byte receipt.
  return crypto.createHash('sha256').update(JSON.stringify(PREDICATES.map(predicate=>{
    const v=values.get(predicate);
    return [predicate,v.type,v.value,v.datatype??null,v['xml:lang']??null];
  }))).digest();
}
async function boundedRead(response){
  if(!response.body)deny('PROTECTED_RDF_HTTP_INVALID');
  const reader=response.body.getReader();
  const chunks=[];let size=0;
  try{
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      size+=value.byteLength;
      if(size>16384)deny('PROTECTED_RDF_HTTP_TOO_LARGE');
      chunks.push(Buffer.from(value));
    }
  }catch(error){
    // A malformed or oversized SPARQL response must not leave an unread
    // streaming socket parked in the dedicated attestor connection pool.
    try{await reader.cancel();}catch{/* preserve original failure */}
    throw error;
  }finally{reader.releaseLock();}
  try{return JSON.parse(Buffer.concat(chunks,size).toString('utf8'));}
  catch{deny('PROTECTED_RDF_HTTP_INVALID');}
}
export function makeDisposableProtectedFusekiReader({
  origin,password,username='fixture-attestor'
}={}){
  if(!enabled()||origin!=='http://127.0.0.1:3041'||
     username!=='fixture-attestor'||password!=='fixture-attestor-only'){
    deny('PROTECTED_RDF_READER_NOT_RELEASED');
  }
  // Explicit class filter prevents extra legitimate rdf:types from
  // affecting the bounded cardinality test. Missing or mismatched binding
  // class still results in one absent required row, and fails closed.
  const query='SELECT ?p ?o WHERE { VALUES ?p { '+
    PREDICATES.map(p=>'<'+p+'>').join(' ')+' } <'+SUBJECT+
    '> ?p ?o . FILTER(?p != <'+RDF_TYPE+'> || ?o = <'+BINDING_TYPE+
    '>) } LIMIT 16';
  const credential='Basic '+Buffer.from(username+':'+password).toString('base64');
  return async function readProtectedRdf(){
    if(!enabled())deny('PROTECTED_RDF_READER_NOT_RELEASED');
    const controller=new AbortController();
    const deadline=setTimeout(()=>controller.abort(),8000);
    try{
      const response=await fetch(origin+'/protected-proof/query',{
        method:'POST',headers:{
          authorization:credential,
          'content-type':'application/sparql-query',
          accept:'application/sparql-results+json'
        },body:query,signal:controller.signal,redirect:'manual'
      });
      if(response.status!==200)deny('PROTECTED_RDF_HTTP_INVALID');
      const parsed=await boundedRead(response);
      if(!Array.isArray(parsed?.results?.bindings)){
        deny('PROTECTED_RDF_HTTP_INVALID');
      }
      return parsed.results.bindings;
    }finally{clearTimeout(deadline);}
  };
}
export async function createIndependentProtectedRdfAttestor({
  pool,readProtectedRdf,appUri,grantUri,consentRevision,fixtureOnly=false
}={}){
  if(fixtureOnly!==true||!enabled()||
     typeof readProtectedRdf!=='function'||
     !canonical(appUri)||!canonical(grantUri)||
     typeof consentRevision!=='string'||!INT.test(consentRevision)||
     BigInt(consentRevision)>MAX)deny('PROTECTED_RDF_READER_NOT_RELEASED');
  await assertRestrictedRdfAttestorLogin(pool);
  return Object.freeze({
    async verifyReadback(payload){
      if(!enabled())deny('PROTECTED_RDF_READER_NOT_RELEASED');
      const p=scope({...payload,appUri,grantUri,consentRevision},
        {requireLeaseOwner:false});
      return one(await readProtectedRdf(),p);
    },
    async attest(payload){
      if(!enabled())deny('PROTECTED_RDF_READER_NOT_RELEASED');
      const p=scope({...payload,appUri,grantUri,consentRevision});
      const hash=one(await readProtectedRdf(),p);
      const r=await pool.query(
        'SELECT paper_atproto_repo_proof.attest_protected_rdf('+
        '$1,$2,$3::uuid,$4::bigint,$5,$6,$7,$8::bigint,$9,$10,$11::bigint,$12::bytea) AS accepted',
        [p.accountId,p.did,p.leaseOwner,p.leaseEpoch,p.commitCid,
          p.rootCid,p.rev,p.generation,appUri,grantUri,
          consentRevision,hash]
      );
      if(r.rowCount!==1||r.rows[0].accepted!==true){
        deny('PROTECTED_RDF_SQL_ATTESTATION_REJECTED');
      }
      return Object.freeze({attested:true,accountId:p.accountId,did:p.did,
        leaseEpoch:p.leaseEpoch,headCid:p.commitCid,rdfSha256:hash.toString('hex')});
    }
  });
}

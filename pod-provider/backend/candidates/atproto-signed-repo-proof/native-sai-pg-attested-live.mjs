/**
 * Cross-store, NON-ACTIVATED native SAI -> PG attestation rehearsal.
 * Runs against real PG18 plus independently authenticated Jena/TDB2 via
 * the existing disposable protected Fuseki isolation workflow.
 *
 * prepare: create pending consent under separately credentialed coordinator,
 *          write actual native SAI RDF, independently read it, then exit.
 * verify:  after Jena/process restart, two attestors attest fresh readback;
 *          canonical owner revokes; old valid RDF cannot revive the grant.
 * cleanup: delete only this fixture, passwords, logins and v2 roles.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import {Client} from 'pg';
import {createRequire} from 'node:module';
import {createDisposableNativeSaiReader,createDisposableNativeSaiPgAttestor,
  verifyNativeSaiEvidence} from './native-sai-pg-consent-attestor.mjs';

const require=createRequire(import.meta.url);
const {createCanonicalAtprotoPgAuthority}=require('../../utils/atproto-canonical-pg-authority.js');
const ORIGIN='http://127.0.0.1:3041';
const DSN='postgres://paper_probe:probe_local_only@127.0.0.1:5548/atproto_signed_repo_proof_test';
const stage=process.argv[2];
if(!['prepare','verify','cleanup'].includes(stage)||
   process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_SAI_ACTIVATION_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'||
   process.env.FUSEKI_ISOLATION_URL!==ORIGIN||
   process.env.ATPROTO_REPO_PROOF_DSN!==DSN||
   !process.env.RUNNER_TEMP?.startsWith('/')){
  throw new Error('Refusing non-disposable native SAI cross-store proof');
}
const METAFILE=process.env.RUNNER_TEMP+'/paper-native-sai-consent-activation.json';
const owner='https://paper.example.org/new-native-sai';
const did='did:plc:'+'j'.repeat(24);
const app='https://app-e2e.test:3443/app';
const group='https://app-e2e.test:3443/access-need';
const rights=['CreateGroup','ReadGroups','ManageMembers'].map(x=>
  'http://activitypods.org/ns/core#'+x);
const scope=Object.freeze({owner,app,needGroup:group,requiredRights:rights});
const registration=owner+'/data/app-registrations/app';
const grant=owner+'/data/access-grants/read-signed-repo';
const registrySet=owner+'/data/registry-set';
const registry=owner+'/data/agent-registry';
const I='http://www.w3.org/ns/solid/interop#';
const A='http://activitypods.org/ns/core#';
const subject=s=>'<'+s+'>';
const ownerGraph=[
  subject(owner)+' <'+I+'hasRegistrySet> '+subject(registrySet)+' .',
  subject(registrySet)+' <'+I+'hasAgentRegistry> '+subject(registry)+' .',
  subject(registry)+' <'+I+'hasApplicationRegistration> '+subject(registration)+' .',
  subject(registration)+' a <'+I+'ApplicationRegistration> ;',
  ' <'+I+'registeredBy> '+subject(owner)+' ;',
  ' <'+I+'registeredAgent> '+subject(app)+' ;',
  ' <'+I+'hasAccessGrant> '+subject(grant)+' .',
  subject(grant)+' a <'+I+'AccessGrant> ;',
  ' <'+I+'grantedBy> '+subject(owner)+' ;',
  ' <'+I+'grantee> '+subject(app)+' ;',
  ' <'+I+'hasAccessNeedGroup> '+subject(group)+' ;',
  ' <'+A+'hasSpecialRights> '+rights.map(subject).join(', ')+' .'
].join('\n');
const sha=data=>crypto.createHash('sha256').update(data).digest();
const role=(kind,meta)=>meta.login[kind];
const safeName=name=>{assert.match(name,/^[a-z_][a-z0-9_]{0,62}$/u);return '"'+name+'"';};
const admin=new Client({connectionString:DSN,connectionTimeoutMillis:3000,query_timeout:6000});
const clients=[];
async function connect(kind,meta){
  const uri=new URL(DSN);
  uri.username=role(kind,meta);uri.password=meta.passwords[kind];
  const client=new Client({connectionString:uri.toString(),connectionTimeoutMillis:3000,
    query_timeout:6500});
  await client.connect();
  clients.push(client);
  assert.equal((await client.query('SELECT current_user AS name')).rows[0].name,role(kind,meta));
  return client;
}
async function project(statement){
  const response=await fetch(ORIGIN+'/protected-proof/update',{
    method:'POST',redirect:'error',signal:AbortSignal.timeout(7000),
    headers:{authorization:'Basic '+Buffer.from('fixture-projector:fixture-projector-only').toString('base64'),
      'content-type':'application/sparql-update'},
    body:statement
  });
  if(![200,204].includes(response.status))throw Error('Protected RDF projection unavailable');
  await response.body?.cancel().catch(()=>{});
}
const read=createDisposableNativeSaiReader({origin:ORIGIN,
  username:'fixture-attestor',password:'fixture-attestor-only',fixtureOnly:true});
async function metadata(){
  const data=JSON.parse(await fs.readFile(METAFILE,'utf8'));
  if(data.owner!==owner||data.did!==did||data.app!==app||
    !/^[0-9a-f-]{36}$/u.test(data.operation)||!data.login||!data.passwords){
    throw Error('Invalid disposable owner consent metadata');
  }
  return data;
}
async function createLogin(kind,base,meta){
  const name=role(kind,meta);
  await admin.query('CREATE ROLE '+safeName(name)+
    " LOGIN PASSWORD '"+meta.passwords[kind]+"' "+
    'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS');
  await admin.query('GRANT '+safeName(base)+' TO '+safeName(name)+
    ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
}
async function begin(client,meta){
  const r=await client.query('SELECT paper_atproto_authority.begin_owner_consent('+
    '$1,$2,$3,$4::uuid,$5::bytea) AS ok',
    [owner,did,app,meta.operation,Buffer.from(meta.receipt,'hex')]);
  assert.equal(r.rowCount,1);return r.rows[0].ok;
}
async function prepare(){
  const id=crypto.randomBytes(6).toString('hex');
  const kinds=['issuer','attestor','attestor2','revoker'];
  const meta={fixture:true,owner,app,did,operation:crypto.randomUUID(),
    receipt:sha('owner-confirmed signup operation:'+owner).toString('hex'),
    login:Object.fromEntries(kinds.map(k=>[k,'paper_live_consent_'+k+'_'+id])),
    passwords:Object.fromEntries(kinds.map(k=>[k,crypto.randomBytes(32).toString('hex')]))};
  await fs.writeFile(METAFILE,JSON.stringify(meta),{mode:0o600,flag:'wx'});
  // The independent signed projection suite already prepared this v1
  // authority schema. Only the additive v2 transition is applied here.
  const existing=await admin.query("SELECT to_regnamespace('paper_atproto_authority') AS ns");
  assert.equal(existing.rows[0].ns,'paper_atproto_authority');
  await admin.query(await fs.readFile(
    new URL('../../sql/paper-atproto-canonical-authority-v2-owner-consent.sql',import.meta.url),'utf8'));
  await createLogin('issuer','paper_atproto_consent_issuer',meta);
  await createLogin('attestor','paper_atproto_consent_attestor',meta);
  await createLogin('attestor2','paper_atproto_consent_attestor',meta);
  await createLogin('revoker','paper_atproto_authority_revoker',meta);
  await admin.query('INSERT INTO paper_atproto_authority.identities '+
    '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
    "VALUES($1,$2,'active',true,1,$3)",
    [owner,did,sha('verified managed owner:'+owner)]);
  const issuer=await connect('issuer',meta);
  assert.equal(await begin(issuer,meta),true);
  const revoker=await connect('revoker',meta);
  const pg=createCanonicalAtprotoPgAuthority({pool:revoker});
  assert.equal((await pg.getConsent({owner,app})).state,'pending');
  await assert.rejects(pg.verifyActiveGrant({owner,app,did,grantUri:grant,consentRevision:'1'}),
    e=>e?.code==='ATPROTO_PG_PERMISSION_DENIED');
  // Real protected Jena write, but no attestation yet. Killing this process
  // simulates an ambiguous ACK after native SAI mutation.
  await project('INSERT DATA { '+ownerGraph+' }');
  const rows=await read(scope);
  const evidence=verifyNativeSaiEvidence(rows,scope);
  assert.equal(evidence.grant,grant);
  assert.equal(evidence.rights.length,rights.length);
  const attestor=await connect('attestor',meta);
  await createDisposableNativeSaiPgAttestor({pool:attestor,readNativeSai:read,
    config:scope,fixtureOnly:true});
  assert.equal((await pg.getConsent({owner,app})).state,'pending');
  console.log('PASS: native owner SAI written and independently read in protected Jena; PG still pending');
}
async function verify(){
  const meta=await metadata();
  const [revoker,attestor1,attestor2]=await Promise.all(
    ['revoker','attestor','attestor2'].map(k=>connect(k,meta)));
  const pg=createCanonicalAtprotoPgAuthority({pool:revoker});
  const first=await createDisposableNativeSaiPgAttestor({
    pool:attestor1,readNativeSai:read,config:scope,fixtureOnly:true
  });
  const second=await createDisposableNativeSaiPgAttestor({
    pool:attestor2,readNativeSai:read,config:scope,fixtureOnly:true
  });
  assert.equal((await pg.getConsent({owner,app})).state,'pending',
    'No process restart may auto-activate owner consent');
  // Separate PG LOGINs and fresh independent Jena reads. If the initial
  // attestor died after native Jena write, no SAI mutation is replayed.
  const accepted=await Promise.all([
    first.attest({did,operationId:meta.operation}),
    second.attest({did,operationId:meta.operation})
  ]);
  assert.equal(accepted.length,2);
  assert(accepted.every(x=>x.attested===true&&x.grantUri===grant));
  assert.equal((await pg.getConsent({owner,app})).state,'active');
  assert.equal(await pg.verifyActiveGrant({owner,app,did,grantUri:grant,consentRevision:'1'}),true);
  // Owner revokes despite still-valid native RDF; old attest/replay can
  // never reactivate the canonical row or a stale signed operation ticket.
  assert.deepEqual(await pg.revoke({owner,app,grantUri:grant,expectedRevision:'1'}),
    {state:'blocked',revision:'2'});
  await assert.rejects(first.attest({did,operationId:meta.operation}),
    e=>e?.code==='SAI_ACTIVATION_PENDING_OR_REVOKED');
  assert.equal((await pg.getConsent({owner,app})).state,'blocked');
  await assert.rejects(pg.verifyActiveGrant({owner,app,did,grantUri:grant,consentRevision:'1'}),
    e=>e?.code==='ATPROTO_PG_PERMISSION_DENIED');
  // Actual projector tampering cannot bypass canonical SQL. The independent
  // reader rejects malformed/partial grant rights rather than caching true.
  await project('DELETE DATA { '+subject(grant)+' <'+A+'hasSpecialRights> '+subject(rights[1])+' . }');
  await assert.rejects(second.inspect(),e=>e?.code==='SAI_ACTIVATION_EVIDENCE_INVALID');
  await project('INSERT DATA { '+subject(grant)+' <'+A+'hasSpecialRights> '+subject(rights[1])+' . }');
  assert.equal((await second.inspect()).grant,grant);
  assert.equal((await pg.getConsent({owner,app})).state,'blocked');
  console.log('PASS: cross-process PG/Jena pending->attested, two worker reads, monotonic revocation, Jena tamper denial');
}
async function cleanup(){
  let data;
  try{data=await metadata();}catch(e){
    if(e?.code==='ENOENT')return;
    throw e;
  }
  // Cleanup is only scoped to these synthetic owner/grant rows. Leave
  // the other signed-RDF test's canonical records and SQL schemas intact.
  try{await project('DELETE DATA { '+ownerGraph+' }');}catch{}
  await admin.query('DELETE FROM paper_atproto_authority.consents WHERE owner_webid=$1',[owner]);
  await admin.query('DELETE FROM paper_atproto_authority.identities WHERE owner_webid=$1',[owner]);
  for(const kind of ['issuer','attestor','attestor2','revoker']){
    await admin.query('DROP ROLE IF EXISTS '+safeName(role(kind,data)));
  }
  for(const [name,args] of [
    ['begin_owner_consent','text,text,text,uuid,bytea'],
    ['attest_owner_consent','text,text,text,uuid,text,bytea'],
    ['confirm_owner_consent','text,text,text,uuid,text,bytea']
  ]){
    await admin.query('DROP FUNCTION IF EXISTS paper_atproto_authority.'+name+'('+args+')');
  }
  for(const name of ['paper_atproto_consent_issuer','paper_atproto_consent_attestor']){
    await admin.query('REVOKE USAGE ON SCHEMA paper_atproto_authority FROM '+safeName(name));
    await admin.query('DROP ROLE '+safeName(name));
  }
  await fs.unlink(METAFILE);
  console.log('PASS: disposed isolated owner grant and independent PG logins');
}
await admin.connect();
try{
  if(stage==='prepare')await prepare();
  else if(stage==='verify')await verify();
  else await cleanup();
}finally{
  await Promise.allSettled(clients.map(client=>client.end()));
  await admin.end();
}

/**
 * NONACTIVATED independent PG18 PRE-DENY reservation and signed-write fence.
 * Two physically distinct real PostgreSQL 18 clusters. S3 Object Lock
 * retention, externally administered signer and native owner are TEST DOUBLES.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import pg from 'pg';
import {assertReceipt} from '../candidates/oauth-s3-compliance-archive.mjs';
import {subjectHash} from '../candidates/oauth-pre-deny-intent-coordinator.mjs';

const PRIMARY='postgres://paper_probe:probe_local_only@127.0.0.1:5549/atproto_signed_repo_proof_test';
const WITNESS='postgres://witness_probe:fixture_witness_only@127.0.0.1:5550/oauth_witness_disposable';
if(process.env.NODE_ENV!=='test'||
 process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PRE_DENY_WITNESS_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PG_RESTORE_DSN!==PRIMARY||
 process.env.PAPER_OAUTH_WITNESS_DSN!==WITNESS)
 throw Error('Refusing non-disposable independent PG18 pre-denial proof');
const secret=crypto.randomBytes(5).toString('hex');
const cli='https://paper-client.example.org/oauth';
const ownerA='https://paper.example.org/users/deny-a-'+secret;
const ownerB='https://paper.example.org/users/deny-b-'+secret;
const ownerC='https://paper.example.org/users/deny-c-'+secret;
const grant=crypto.randomBytes(32);
const grantHash=crypto.createHash('sha256').update(grant).digest();
const scopeHash=crypto.createHash('sha256')
 .update('atproto repo:app.bsky.feed.post?action=create').digest();
const cid1='bafyre'+'a'.repeat(53),cid2='bafyre'+'b'.repeat(53);
const loginName=kind=>'paper_pre_deny_'+kind+'_'+secret;
const quoted=value=>'"'+value.replaceAll('"','""')+'"';
const roles={
 issuer:'paper_oauth_witness_issuer',
 revoker:'paper_oauth_witness_revoker',
 reader:'paper_oauth_witness_reader',
 writer:'paper_oauth_witness_writer',
 reconciler:'paper_oauth_witness_reconciler',
 attestor:'paper_oauth_witness_attestor',
 preparer:'paper_oauth_witness_pre_deny_preparer',
 denyAttestor:'paper_oauth_witness_pre_deny_attestor'
};
const root=new pg.Client({connectionString:WITNESS,
 connectionTimeoutMillis:3000,query_timeout:8500});
const primary=new pg.Client({connectionString:PRIMARY,
 connectionTimeoutMillis:3000,query_timeout:8500});
const connections=[],loginNames=[],objects=new Map();
let schema=false,failed=false;
const sql=relative=>fs.readFile(new URL(relative,import.meta.url),'utf8');
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest();
const denied=(fn,code)=>assert.rejects(fn,e=>e?.code===code,
 'Expected PostgreSQL error '+code);
const fun=(method,params)=>
 'SELECT paper_oauth_restore_witness.'+method+'('+params+') AS value';
async function role(kind){
 const name=loginName(kind),pass=crypto.randomBytes(20).toString('hex');
 await root.query('CREATE ROLE '+quoted(name)+
  " LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE "+
  "NOREPLICATION NOBYPASSRLS PASSWORD '"+pass+"'");
 loginNames.push(name);
 await root.query('GRANT '+roles[kind]+' TO '+quoted(name)+
  ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
 const u=new URL(WITNESS);u.username=name;u.password=pass;
 const c=new pg.Client({connectionString:u.toString(),
  connectionTimeoutMillis:3000,query_timeout:8500});
 await c.connect();connections.push(c);return c;
}
async function issue(actor,owner,expected,op=crypto.randomUUID(),
 grantDigest=grantHash){
 const r=await actor.query(fun('issue','$1,$2,$3,$4::bigint,$5::uuid'),
  [owner,cli,grantDigest,expected,op]);
 return String(r.rows[0]?.value);
}
async function sealEpoch(attestor,owner,op){
 const digest=(await attestor.query(fun('get_unsealed_receipt',
  '$1,$2,$3::bigint,$4::uuid'),[owner,cli,1,op])).rows[0]?.value;
 assert.ok(Buffer.isBuffer(digest)&&digest.length===32);
 // Existing v1 test fixture already simulates independent WORM GET here.
 return (await attestor.query(fun('seal',
  '$1,$2,$3::bigint,$4::uuid,$5'),
  [owner,cli,1,op,digest])).rows[0].value===true;
}
async function prepare(actor,owner,op,epoch=11,sai=3,
 grantDigest=grantHash){
 const r=await actor.query(fun('prepare_pre_deny',
  '$1,$2,$3,$4::bigint,$5::uuid,$6::bigint,$7::bigint,$8'),
  [owner,cli,grantDigest,1,op,epoch,sai,scopeHash]);
 return r.rows[0]?.value===true;
}
async function block(actor,owner,op){
 const r=await actor.query(fun('block','$1,$2,$3,$4::bigint,$5::uuid'),
  [owner,cli,grantHash,1,op]);
 return String(r.rows[0]?.value);
}
async function verify(actor,owner){
 const r=await actor.query(fun('verify','$1,$2,$3,$4::bigint'),
  [owner,cli,grantHash,1]);
 return r.rows[0]?.value===true;
}
async function reserve(actor,owner,op=crypto.randomUUID()){
 const r=await actor.query(fun('reserve_signed_write',
  '$1,$2,$3,$4::bigint,$5::uuid,$6,$7'),
  [owner,cli,grantHash,1,op,cid1,cid2]);
 return r.rows[0]?.value===true;
}
function deterministicOperation(owner){
 const subject=subjectHash(owner,cli);
 const raw=crypto.createHash('sha256')
  .update('paper:oauth:pre-deny:operation:v1\0')
  .update(subject).update('\0').update(grantHash.toString('hex'))
  .update('\0').update('1').digest().subarray(0,16);
 const b=Buffer.from(raw);
 b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;
 const h=b.toString('hex');
 return [h.slice(0,8),h.slice(8,12),h.slice(12,16),
  h.slice(16,20),h.slice(20)].join('-');
}
async function archivePreDeny(attestor,owner,op,{bad=false}={}){
 const r=await attestor.query(fun('pre_deny_receipt',
  '$1,$2,$3::uuid'),[owner,cli,op]);
 const bytes=r.rows[0]?.value;
 assert.ok(Buffer.isBuffer(bytes)&&bytes.length<1024);
 const key='paper/oauth-witness/pre-deny/v1/'+subjectHash(owner,cli)+
  '/0000000000000000001/'+op;
 assertReceipt(key,bytes);
 const expected=Buffer.from(JSON.stringify({
  kind:'paper.oauth.pre-deny.v1',subject:subjectHash(owner,cli),
  revision:'1',operationId:op,grantSha256:grantHash.toString('hex'),
  credentialEpoch:'11',saiRevision:'3',
  scopeSha256:scopeHash.toString('hex')
 }));
 assert.deepEqual(bytes,expected,'PG18 WORM bytes must match JS/S3 contract');
 if(objects.has(key))throw Error('Duplicate WORM object not permitted');
 objects.set(key,Buffer.from(bad?'tampered':bytes));
 const retrieved=objects.get(key); // Explicit disposable S3 readback mock.
 if(!retrieved.equals(bytes))return false;
 return (await attestor.query(fun('seal_pre_deny',
  '$1,$2,$3::uuid,$4'),[owner,cli,op,hash(retrieved)]))
  .rows[0]?.value===true;
}
async function archiveWriteIntent(attestor,op,phase){
 const bytes=(await attestor.query(fun('signed_intent_receipt',
  '$1::uuid,$2'),[op,phase])).rows[0]?.value;
 assert.ok(Buffer.isBuffer(bytes)&&bytes.length>70);
 const key='paper/oauth-witness/signed-intents/v1/'+op+'/'+phase;
 assertReceipt(key,bytes);
 if(objects.has(key))throw Error('Duplicate signed-write receipt');
 objects.set(key,Buffer.from(bytes));
 return (await attestor.query(fun('seal_signed_intent_receipt',
  '$1::uuid,$2,$3'),[op,phase,hash(bytes)])).rows[0]?.value===true;
}
async function run(){
 await root.connect();await primary.connect();
 const [w,p]=await Promise.all([
  root.query('SELECT system_identifier::text AS id FROM pg_control_system()'),
  primary.query('SELECT system_identifier::text AS id FROM pg_control_system()')
 ]);
 assert.notEqual(w.rows[0].id,p.rows[0].id,
  'Both PG18 servers must have independent physical identities');
 for(const part of [
  'v1','v2-writer-intents','v3-bound-commit-intents',
  'v4-commit-only-reconciliation','v5-immutable-signed-intent-receipts',
  'v6-immutable-highwater-read'
 ]){
  const file=part==='v1'?
   'paper-oauth-external-restore-witness-v1.sql':
   'paper-oauth-external-restore-witness-'+part+'.sql';
  await root.query(await sql('../sql/'+file));schema=true;
 }
 const issuer=await role('issuer'),revoker=await role('revoker'),
  reader=await role('reader'),writer=await role('writer'),
  reconciler=await role('reconciler'),attestor=await role('attestor');
 const issuances=[
  [ownerA,crypto.randomUUID()],[ownerB,crypto.randomUUID()],
  [ownerC,crypto.randomUUID()]
 ];
 for(const [owner,op] of issuances){
  assert.equal(await issue(issuer,owner,0,op),'1');
  assert.equal(await sealEpoch(attestor,owner,op),true);
  assert.equal(await verify(reader,owner),true);
 }
 // Migration guard: do not silently import/revoke against historical
 // signed-write state not yet archived under the v7 pre-denial protocol.
 const historical=crypto.randomUUID();
 assert.equal(await reserve(writer,ownerA,historical),true);
 const migration=await sql('../sql/paper-oauth-external-restore-witness-v7-pre-deny-writer-fence.sql');
 await denied(()=>root.query(migration),'P0001');
 await root.query('ROLLBACK');
 assert.equal((await root.query(
  'SELECT count(*)::int AS n FROM paper_oauth_restore_witness.signed_write_intents'
 )).rows[0].n,1);
 // Safe only in this disposable, pre-release fixture.
 await root.query('DELETE FROM paper_oauth_restore_witness.signed_write_intents');
 await root.query(migration);
 const preparer=await role('preparer');
 const denyAttestor=await role('denyAttestor');

 await denied(()=>preparer.query(
  'SELECT * FROM paper_oauth_restore_witness.current_epochs'), '42501');
 await denied(()=>writer.query(fun('prepare_pre_deny',
  '$1,$2,$3,$4::bigint,$5::uuid,$6::bigint,$7::bigint,$8'),
  [ownerA,cli,grantHash,1,deterministicOperation(ownerA),11,3,scopeHash]),
 '42501');
 await denied(()=>preparer.query(fun('seal_pre_deny',
  '$1,$2,$3::uuid,$4'),
  [ownerA,cli,deterministicOperation(ownerA),Buffer.alloc(32)]),'42501');

 // No pending writes: PREPARE stops the independent witness immediately.
 const opA=deterministicOperation(ownerA);
 assert.equal(await prepare(preparer,ownerA,opA),true);
 assert.equal(await prepare(preparer,ownerA,opA),true,
  'Exact same operation can be reconciled after lost prepare ACK');
 assert.equal(await prepare(preparer,ownerA,crypto.randomUUID()),false);
 assert.equal(await prepare(preparer,ownerA,opA,12),false);
 await denied(()=>root.query(
  'UPDATE paper_oauth_restore_witness.current_epochs '+
  'SET deny_sealed_at=clock_timestamp() WHERE owner_webid=$1',
  [ownerA]),'23514');
 assert.equal(await verify(reader,ownerA),false);
 const active=await reader.query(
  'SELECT * FROM paper_oauth_restore_witness.active_checkpoint('+
  '$1,$2,$3,$4::bigint)',[ownerA,cli,grantHash,1]);
 assert.equal(active.rowCount,0);
 await denied(()=>reserve(writer,ownerA),'P0001');
 assert.equal(await block(revoker,ownerA,opA),'0',
  'No owner-visible revoke ACK before independent WORM sealing');
 const wrongSeal=await denyAttestor.query(fun('seal_pre_deny',
  '$1,$2,$3::uuid,$4'),
  [ownerA,cli,opA,Buffer.alloc(32)]);
 assert.equal(wrongSeal.rows[0]?.value,false,
  'Correct attestor role MUST reject a forged/unarchived receipt digest');
 // Unretained or corrupted object must strand denial, never reopen grant.
 assert.equal(await archivePreDeny(denyAttestor,ownerA,opA),true);
 assert.equal(await block(revoker,ownerA,crypto.randomUUID()),'0');
 assert.equal(await block(revoker,ownerA,opA),'2');
 assert.equal(await verify(reader,ownerA),false);
 assert.equal(await issue(issuer,ownerA,2,crypto.randomUUID()),'0',
  'Old grant cannot revive by reapproval after prepared denial');
 await denied(()=>root.query(
  'UPDATE paper_oauth_restore_witness.current_epochs '+
  'SET deny_operation_id=NULL WHERE owner_webid=$1',[ownerA]),'P0001');
 await denied(()=>root.query(
  'UPDATE paper_oauth_restore_witness.current_epochs '+
  'SET deny_sealed_at=NULL WHERE owner_webid=$1',[ownerA]),'P0001');

 // A prior signed-PDS reservation remains PENDING after preparation.
 const pendingOp=crypto.randomUUID();
 assert.equal(await reserve(writer,ownerB,pendingOp),true);
 const opB=deterministicOperation(ownerB);
 assert.equal(await prepare(preparer,ownerB,opB),true);
 await denied(()=>reserve(writer,ownerB),'P0001');
 assert.equal(await archivePreDeny(denyAttestor,ownerB,opB),true);
 await denied(()=>block(revoker,ownerB,opB),'P0001');
 // Separate attestor settles exact immutable PENDING and RESOLVED bytes.
 assert.equal(await archiveWriteIntent(attestor,pendingOp,'pending'),true);
 const settled=await reconciler.query(fun('settle_verified_committed',
  '$1::uuid,$2,$3,$4::bigint,$5'),
  [pendingOp,ownerB,cli,1,cid2]);
 assert.equal(settled.rows[0]?.value,true);
 await denied(()=>block(revoker,ownerB,opB),'P0001');
 assert.equal(await archiveWriteIntent(attestor,pendingOp,'resolved'),true);
 assert.equal(await block(revoker,ownerB,opB),'2');
 assert.equal(await verify(reader,ownerB),false);

 // Serialize PREPARE with an in-flight genuine restricted signed-intent
 // reservation. Whichever transaction first locks the same witness epoch
 // establishes an unambiguous ordering, never a timeout-based abort.
 const preWrite=crypto.randomUUID(),opC=deterministicOperation(ownerC);
 await writer.query('BEGIN');
 try{
  assert.equal(await reserve(writer,ownerC,preWrite),true);
  let finished=false;
  const preparing=prepare(preparer,ownerC,opC).then(x=>{
   finished=true;return x;
  });
  await new Promise(resolve=>setTimeout(resolve,125));
  assert.equal(finished,false,
   'PRE-DENY cannot overtake writer lock held through commit');
  await writer.query('COMMIT');
  assert.equal(await preparing,true);
 }catch(e){
  await writer.query('ROLLBACK').catch(()=>{});
  throw e;
 }
 assert.equal(await verify(reader,ownerC),false);
 await denied(()=>reserve(writer,ownerC),'P0001');
 assert.equal(await archivePreDeny(denyAttestor,ownerC,opC),true);
 await denied(()=>block(revoker,ownerC,opC),'P0001',
  'Earlier pending signed intent must survive for manual recovery');
 console.log('PASS: two physical PG18 clusters; v7 denies new PDS write intent on prepared denial; exact retained receipt before revoke, pending WORM outcomes gate block; no live Object Lock, issuer or PDS activation');
}
const watchdog=setTimeout(()=>{console.error('v7 PG18 proof hung');process.exit(1)},90000);
try{await run()}catch(e){failed=true;process.exitCode=1;console.error(e?.stack||String(e))}
finally{
 for(const c of connections.reverse())try{await c.end()}catch(e){
  failed=true;console.error(e)
 }
 if(schema)try{
  await root.query('DROP SCHEMA IF EXISTS paper_oauth_restore_witness CASCADE');
 }catch(e){failed=true;console.error(e)}
 for(const name of loginNames.reverse())try{
  await root.query('DROP ROLE IF EXISTS '+quoted(name));
 }catch(e){failed=true;console.error(e)}
 if(schema)for(const kind of Object.keys(roles))try{
  await root.query('DROP ROLE IF EXISTS '+quoted(roles[kind]));
 }catch(e){failed=true;console.error(e)}
 for(const c of [primary,root])try{await c.end()}catch(e){
  failed=true;console.error(e)
 }
 clearTimeout(watchdog);
 if(failed)process.exitCode=1;
}

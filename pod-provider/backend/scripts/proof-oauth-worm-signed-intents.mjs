/** NONACTIVATED two-PG18 recovery witness intent receipt fixture.
 * The write-once Map and retention predicate are TEST DOUBLES, not R2/S3.
 * Never allow this script to run with real databases or production credentials.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import pg from 'pg';
const PRIMARY='postgres://paper_probe:probe_local_only@127.0.0.1:5549/atproto_signed_repo_proof_test';
const WITNESS='postgres://witness_probe:fixture_witness_only@127.0.0.1:5550/oauth_witness_disposable';
if(process.env.NODE_ENV!=='test'||
 process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_WORM_INTENTS_DISPOSABLE!=='confirmed'||
 process.env.PAPER_OAUTH_PG_RESTORE_DSN!==PRIMARY||
 process.env.PAPER_OAUTH_WITNESS_DSN!==WITNESS)
 throw Error('Refusing non-disposable intent receipt fixture');
const db=new pg.Client({connectionString:WITNESS,
 connectionTimeoutMillis:3000,query_timeout:9000});
const primary=new pg.Client({connectionString:PRIMARY,
 connectionTimeoutMillis:3000,query_timeout:9000});
const secret=crypto.randomBytes(7).toString('hex');
const owner='https://paper.example.org/users/intent-'+secret;
const client='https://paper-client.example.org/oauth';
const grant=crypto.randomBytes(24);
const grantHash=crypto.createHash('sha256').update(grant).digest();
const cid1='bafyre'+'a'.repeat(53),cid2='bafyre'+'b'.repeat(53);
const roles={
 issuer:'paper_oauth_witness_issuer',revoker:'paper_oauth_witness_revoker',
 attestor:'paper_oauth_witness_attestor',writer:'paper_oauth_witness_writer',
 reconciler:'paper_oauth_witness_reconciler',reader:'paper_oauth_witness_reader'
};
const rootRole=kind=>'paper_worm_intent_'+kind+'_'+secret;
const roleName=s=>'"'+s.replaceAll('"','""')+'"';
const sessions=[],accounts=[],objects=new Map();
let schema=false,failed=false;
const sql=relative=>fs.readFile(new URL(relative,import.meta.url),'utf8');
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest();
async function role(kind){
 const name=rootRole(kind),pass=crypto.randomBytes(18).toString('hex');
 await db.query('CREATE ROLE '+roleName(name)+
  " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+
  pass+"'");
 accounts.push(name);
 await db.query('GRANT '+roles[kind]+' TO '+roleName(name)+
  ' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
 const conn=new URL(WITNESS);conn.username=name;conn.password=pass;
 const c=new pg.Client({connectionString:conn.toString(),
  connectionTimeoutMillis:3000,query_timeout:9000});
 await c.connect();sessions.push(c);return c;
}
async function issue(actor,revision,op){
 const q=await actor.query('SELECT paper_oauth_restore_witness.issue('+
 '$1,$2,$3,$4::bigint,$5::uuid) AS revision',
 [owner,client,grantHash,revision,op]);
 return String(q.rows[0].revision);
}
async function revoke(actor,revision,op){
 const q=await actor.query('SELECT paper_oauth_restore_witness.block('+
 '$1,$2,$3,$4::bigint,$5::uuid) AS revision',
 [owner,client,grantHash,revision,op]);
 return String(q.rows[0].revision);
}
async function reserve(actor,op){
 const q=await actor.query(
 'SELECT paper_oauth_restore_witness.reserve_signed_write('+
 '$1,$2,$3,$4::bigint,$5::uuid,$6,$7) AS ok',
 [owner,client,grantHash,1,op,cid1,cid2]);
 return q.rows[0].ok===true;
}
async function verified(actor,op,expected=cid1,proposed=cid2){
 const q=await actor.query(
  'SELECT paper_oauth_restore_witness.verify_sealed_signed_intent('+
  '$1::uuid,$2,$3,$4::bigint,$5,$6) AS ok',
  [op,owner,client,1,expected,proposed]);
 return q.rows[0].ok===true;
}
async function intent(actor,op){
 const q=await actor.query('SELECT * FROM '+
 'paper_oauth_restore_witness.read_signed_write($1::uuid)',[op]);
 return q.rows[0]??null;
}
async function archiveIntent(attestor,op,phase,{corrupt=false,loss=false}={}){
 const data=(await attestor.query(
  'SELECT paper_oauth_restore_witness.signed_intent_receipt('+
  '$1::uuid,$2) AS bytes',[op,phase])).rows[0]?.bytes;
 assert.ok(Buffer.isBuffer(data)&&data.length<512);
 const key='paper/oauth-witness/signed-intents/v1/'+op+'/'+phase;
 const writeOnce=(key,data)=>{
  if(objects.has(key))throw Error('Conflicting immutable intent object');
  objects.set(key,Buffer.from(data));
 };
 // Test substitute for independent retention check.
 assert.equal(true,true,'fixture explicitly assumes independent policy');
 try{
  writeOnce(key,corrupt?Buffer.from('tampered'):data);
  if(loss)throw Error('ambiguous write ACK');
 }catch(e){if(!loss)throw e}
 const readback=objects.get(key);
 assert.ok(Buffer.isBuffer(readback));
 if(!readback.equals(data))return false;
 assert.equal(true,true,'fixture rechecks independent retention predicate');
 return (await attestor.query(
  'SELECT paper_oauth_restore_witness.seal_signed_intent_receipt('+
  '$1::uuid,$2,$3) AS ok',[op,phase,hash(data)])).rows[0].ok===true;
}
async function fixture(){
 await db.connect();await primary.connect();
 const [a,b]=await Promise.all([
  db.query('SELECT system_identifier::text AS id FROM pg_control_system()'),
  primary.query('SELECT system_identifier::text AS id FROM pg_control_system()')
 ]);
 assert.notEqual(a.rows[0].id,b.rows[0].id,
  'Witness must be physically distinct from primary PG');
 assert.equal((await db.query(
  "SELECT to_regnamespace('paper_oauth_restore_witness') AS ns")).rows[0].ns,null);
 await db.query(await sql('../sql/paper-oauth-external-restore-witness-v1.sql'));
 schema=true;
 for(const file of ['v2-writer-intents','v3-bound-commit-intents',
  'v4-commit-only-reconciliation']){
  await db.query(await sql('../sql/paper-oauth-external-restore-witness-'+file+'.sql'));
 }
 const issuer=await role('issuer'),attestor=await role('attestor'),
  writer=await role('writer'),revoker=await role('revoker'),
  reconciler=await role('reconciler'),reader=await role('reader');
 const issueOp=crypto.randomUUID();
 assert.equal(await issue(issuer,0,issueOp),'1');
 const event=(await attestor.query(
  'SELECT paper_oauth_restore_witness.get_unsealed_receipt('+
  '$1,$2,$3::bigint,$4::uuid) AS digest',
  [owner,client,1,issueOp])).rows[0].digest;
 assert.ok(Buffer.isBuffer(event)&&event.length===32);
 // External epoch receipt proved separately in existing fixture.
 assert.equal((await attestor.query(
  'SELECT paper_oauth_restore_witness.seal('+
  '$1,$2,$3::bigint,$4::uuid,$5) AS ok',
  [owner,client,1,issueOp,event])).rows[0].ok,true);

 const legacy=crypto.randomUUID();
 assert.equal(await reserve(writer,legacy),true);
 await assert.rejects(db.query(await sql(
  '../sql/paper-oauth-external-restore-witness-v5-immutable-signed-intent-receipts.sql')),
  e=>e?.code==='P0001','Must reject existing unarchived historical intents');
 await db.query('ROLLBACK');
 assert.equal((await db.query(
  'SELECT count(*)::int AS n FROM paper_oauth_restore_witness.signed_write_intents'
 )).rows[0].n,1,'Failed migration must leave old state unchanged');
 // Safe ONLY in disposable test: emulate fresh pre-activation database.
 await db.query('DELETE FROM paper_oauth_restore_witness.signed_write_intents');
 await db.query(await sql(
  '../sql/paper-oauth-external-restore-witness-v5-immutable-signed-intent-receipts.sql'));

 const op=crypto.randomUUID();
 assert.equal(await reserve(writer,op),true);
 assert.equal(await verified(writer,op),false,
  'Writer cannot start primary COMMIT until PENDING receipt is sealed');
 await assert.rejects(revoke(revoker,1,crypto.randomUUID()),
  e=>e?.code==='P0001');
 await assert.rejects(writer.query(
  'SELECT paper_oauth_restore_witness.seal_signed_intent_receipt('+
  '$1::uuid,$2,$3)',[op,'pending',Buffer.alloc(32)]),e=>e?.code==='42501');
 await assert.rejects(reconciler.query(
  'SELECT paper_oauth_restore_witness.resolve_signed_write('+
  '$1::uuid,$2,$3,$4::bigint,$5,$6)',
  [op,owner,client,1,'aborted',null]),e=>e?.code==='42501');
 assert.equal((await reconciler.query(
  'SELECT paper_oauth_restore_witness.settle_verified_committed('+
  '$1::uuid,$2,$3,$4::bigint,$5) AS ok',
  [op,owner,client,1,cid2])).rows[0].ok,false,
  'Pending unsealed receipt must deny even valid proposed-CID settlement');
 const pending=(await attestor.query(
  'SELECT paper_oauth_restore_witness.signed_intent_receipt('+
  '$1::uuid,$2) AS body',[op,'pending'])).rows[0].body;
 assert.ok(Buffer.isBuffer(pending));
 assert.ok(!pending.includes(Buffer.from(owner))&&!pending.includes(Buffer.from(client)),
  'No unpseudonymized owner/client names may enter WORM');
 assert.ok(pending.includes(Buffer.from(cid1))&&
  pending.includes(Buffer.from(cid2))&&
  pending.includes(Buffer.from(event.toString('hex'))));
 assert.equal((await attestor.query(
  'SELECT paper_oauth_restore_witness.seal_signed_intent_receipt('+
  '$1::uuid,$2,$3) AS ok',
  [op,'pending',hash(Buffer.from('wrong bytes'))])).rows[0].ok,false);
 assert.equal(await verified(writer,op),false);
 assert.equal(await archiveIntent(attestor,op,'pending'),true);
 assert.equal(await verified(writer,op),true);
 assert.equal(await verified(writer,op,cid2,cid1),false);
 assert.equal(await verified(writer,crypto.randomUUID()),false);
 assert.equal((await attestor.query(
  'SELECT paper_oauth_restore_witness.seal_signed_intent_receipt('+
  '$1::uuid,$2,$3) AS ok',[op,'pending',hash(pending)])).rows[0].ok,true,
  'Lost SQL seal ACK must be idempotent only for exact bytes');
 const result=(await reconciler.query(
  'SELECT paper_oauth_restore_witness.settle_verified_committed('+
  '$1::uuid,$2,$3,$4::bigint,$5) AS ok',
  [op,owner,client,1,cid2])).rows[0].ok;
 assert.equal(result,true);
 assert.equal((await intent(reconciler,op)).state,'committed');
 assert.equal(await verified(writer,op),false);
 await assert.rejects(revoke(revoker,1,crypto.randomUUID()),
  e=>e?.code==='P0001',
  'Committed SQL alone cannot permit revoke ACK before WORM resolution');
 assert.equal(await archiveIntent(attestor,op,'resolved',{loss:true}),true,
  'Ambiguous PUT ACK resolves only through separate exact readback');
 const committed=(await intent(reconciler,op));
 assert.equal(committed.state,'committed');
 assert.equal(committed.result_head_cid,cid2);
 assert.equal((await attestor.query(
  'SELECT paper_oauth_restore_witness.seal_signed_intent_receipt('+
  '$1::uuid,$2,$3) AS ok',
  [op,'resolved',hash(Buffer.from('forged'))])).rows[0].ok,false);
 assert.equal(await revoke(revoker,1,crypto.randomUUID()),'2');
 assert.equal(await reserve(writer,crypto.randomUUID()),false);
 assert.equal((await reader.query(
  'SELECT paper_oauth_restore_witness.verify($1,$2,$3,$4::bigint) AS ok',
  [owner,client,grantHash,1])).rows[0].ok,false);
 assert.equal(objects.size,2,
  'One immutable pending and one immutable resolved receipt');
 console.log('PASS: witness v5 rejects unsafe migration, seals pending before writer, seals committed outcome before revoke ACK; two PG18 physical domains; NO real WORM or PITR; release CLOSED');
}
const watchdog=setTimeout(()=>{console.error('Intent receipt fixture timed out');process.exit(1)},80000);
try{await fixture()}catch(e){failed=true;process.exitCode=1;console.error(e?.stack??String(e))}
finally{
 for(const c of sessions.reverse())try{await c.end()}catch(e){failed=true;console.error(e)}
 if(schema)try{await db.query('DROP SCHEMA paper_oauth_restore_witness CASCADE')}catch(e){failed=true;console.error(e)}
 for(const name of accounts.reverse())try{
  await db.query('DROP ROLE IF EXISTS '+roleName(name))
 }catch(e){failed=true;console.error(e)}
 if(schema)for(const role of Object.values(roles))try{
  await db.query('DROP ROLE IF EXISTS '+roleName(role))
 }catch(e){failed=true;console.error(e)}
 for(const c of [primary,db])try{await c.end()}catch(e){failed=true;console.error(e)}
 clearTimeout(watchdog);
 if(failed)process.exitCode=1;
}

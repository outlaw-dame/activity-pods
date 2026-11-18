/**
 * NONACTIVATED provider-owned pre-account dataset administration.
 *
 * New ActivityPods signup creates a dataset BEFORE committing a WebID.
 * Accordingly, a future dataset administrator must require a trusted,
 * independently signed one-time provisioning claim, not a query for an
 * account that does not exist yet. The ordinary SemApps provider MUST NOT
 * hold the Fuseki administrator password or the claim-signing key.
 *
 * This candidate uses real PostgreSQL 18 and real Fuseki HTTP only in a
 * strictly disposable local CI fixture. No production service registration.
 */
import { ownerWebId } from '../../services/utils/disposable-provider-identity.js';
import crypto from 'node:crypto';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);

const ORIGIN='http://127.0.0.1:3041';
const ISSUER='https://paper.example.org/provider';
const AUDIENCE='urn:activitypods:dataset-admin:v1';
const DOMAIN=Buffer.from('activitypods:dataset-admin:claim:v1\0','utf8');
const DATASET=/^claimtest-[a-z0-9]{8,24}$/u;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const KEYS=Object.freeze([
  'version','issuer','audience','dataset','ownerWebid',
  'reservationId','nonce','issuedAtMs','expiresAtMs'
]);
function fail(code='DATASET_ADMIN_CLAIM_REFUSED',httpStatus=403){
  const error=new Error('Pre-account dataset provisioning refused');
  error.code=code;error.httpStatus=httpStatus;throw error;
}
function disposable(){
  return process.env.NODE_ENV==='test'&&
    process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE==='confirmed'&&
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE==='confirmed'&&
    process.env.FUSEKI_ISOLATION_URL===ORIGIN;
}
function object(x,keys){
  if(!x||typeof x!=='object'||Array.isArray(x)||
     Object.getPrototypeOf(x)!==Object.prototype||
     Object.keys(x).length!==keys.length||
     keys.some(k=>!Object.hasOwn(x,k)))fail();
}
function canonical(c,now){
  object(c,KEYS);
  if(c.version!==1||c.issuer!==ISSUER||c.audience!==AUDIENCE||
     typeof c.dataset!=='string'||!DATASET.test(c.dataset)||
     c.ownerWebid!==ownerWebId(c.dataset)||
     typeof c.reservationId!=='string'||!UUID.test(c.reservationId)||
     typeof c.nonce!=='string'||!UUID.test(c.nonce)||
     !Number.isSafeInteger(c.issuedAtMs)||
     !Number.isSafeInteger(c.expiresAtMs)||
     c.expiresAtMs-c.issuedAtMs<1000||
     c.expiresAtMs-c.issuedAtMs>120000||
     c.issuedAtMs-now>30000||now-c.issuedAtMs>120000||
     now>=c.expiresAtMs)fail();
  // Deterministic field ordering; signed bytes do not depend on JSON
  // property order, whitespace, escaping choices or duplicate JSON keys.
  return Buffer.concat([DOMAIN,Buffer.from(
    JSON.stringify(KEYS.map(k=>c[k])),'utf8')]);
}
export function signDisposableDatasetClaim(claim,privateKey,now=Date.now()){
  if(!disposable()||!privateKey)fail('DATASET_ADMIN_SIGNER_NOT_RELEASED');
  const bytes=canonical(claim,now);
  const signature=crypto.sign(null,bytes,privateKey).toString('base64url');
  return Object.freeze({claim,signature});
}
export function verifyDisposableDatasetClaim(ticket,publicKey,now=Date.now()){
  if(!disposable())fail('DATASET_ADMIN_NOT_RELEASED');
  object(ticket,['claim','signature']);
  const bytes=canonical(ticket.claim,now);
  if(typeof ticket.signature!=='string'||
     !/^[A-Za-z0-9_-]{86}$/u.test(ticket.signature))fail();
  const sig=Buffer.from(ticket.signature,'base64url');
  if(sig.length!==64||sig.toString('base64url')!==ticket.signature||
     !crypto.verify(null,bytes,publicKey,sig))fail('DATASET_ADMIN_SIGNATURE_INVALID');
  return Object.freeze({
    dataset:ticket.claim.dataset,ownerWebid:ticket.claim.ownerWebid,
    reservationId:ticket.claim.reservationId,
    sha256:crypto.createHash('sha256').update(bytes).update(sig).digest()
  });
}
export async function assertRestrictedDatasetAdminLogin(pool){
  if(!disposable()||typeof pool?.query!=='function')fail('DATASET_ADMIN_SQL_NOT_RELEASED');
  let r;
  try{
    r=await pool.query(
      "SELECT current_user AS login,current_setting('server_version_num')::int AS version,"+
      "x.rolcanlogin,x.rolsuper,x.rolcreatedb,x.rolcreaterole,"+
      "x.rolreplication,x.rolbypassrls,"+
      "pg_catalog.pg_has_role(current_user,'paper_dataset_admin_agent','USAGE') AS allowed,"+
      "pg_catalog.pg_has_role(current_user,'paper_dataset_admin_agent','SET') AS role_switch,"+
      "pg_catalog.has_schema_privilege(current_user,'paper_dataset_admin_proof','CREATE') AS create_schema,"+
      "pg_catalog.has_table_privilege(current_user,'paper_dataset_admin_proof.claims','DELETE') AS can_delete,"+
      "pg_catalog.has_table_privilege(current_user,'paper_dataset_admin_proof.claims','TRUNCATE') AS can_truncate,"+
      "pg_catalog.has_column_privilege(current_user,'paper_dataset_admin_proof.claims','dataset','INSERT') AS can_claim,"+
      "pg_catalog.has_column_privilege(current_user,'paper_dataset_admin_proof.claims','state','UPDATE') AS can_complete,"+
      "pg_catalog.has_table_privilege(current_user,'paper_dataset_admin_proof.claims','SELECT') AS can_read_all,"+
      "pg_catalog.has_column_privilege(current_user,'paper_dataset_admin_proof.claims','dataset','UPDATE') AS can_change_dataset,"+
      "pg_catalog.has_column_privilege(current_user,'paper_dataset_admin_proof.claims','owner_webid','UPDATE') AS can_change_owner,"+
      "pg_catalog.has_column_privilege(current_user,'paper_dataset_admin_proof.claims','reservation_id','UPDATE') AS can_change_reservation,"+
      "pg_catalog.has_column_privilege(current_user,'paper_dataset_admin_proof.claims','signed_ticket_sha256','UPDATE') AS can_change_ticket,"+
      "pg_catalog.has_column_privilege(current_user,'paper_dataset_admin_proof.claims','state','INSERT') AS can_forge_state,"+
      "pg_catalog.has_column_privilege(current_user,'paper_dataset_admin_proof.claims','completed_at','INSERT') AS can_forge_completion,"+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace "+
        "WHERE nspname='paper_dataset_admin_proof'),'MEMBER') AS owner_member,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_auth_members am "+
      "JOIN pg_catalog.pg_roles member_role ON member_role.oid=am.member "+
      "JOIN pg_catalog.pg_roles target_role ON target_role.oid=am.roleid "+
      "WHERE member_role.rolname=current_user "+
      "AND target_role.rolname<>'paper_dataset_admin_agent') AS extra_roles,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_auth_members am "+
      "JOIN pg_catalog.pg_roles member_role ON member_role.oid=am.member "+
      "JOIN pg_catalog.pg_roles target_role ON target_role.oid=am.roleid "+
      "WHERE member_role.rolname=current_user "+
      "AND target_role.rolname='paper_dataset_admin_agent' "+
      "AND (am.set_option OR am.admin_option OR NOT am.inherit_option)) AS bad_role_options,"+
      "(SELECT count(*)::int FROM pg_catalog.pg_auth_members am "+
      "JOIN pg_catalog.pg_roles member_role ON member_role.oid=am.member "+
      "WHERE member_role.rolname='paper_dataset_admin_agent') AS inherited_extra_roles "+
      "FROM pg_catalog.pg_roles x WHERE x.rolname=current_user"
    );
  }catch{fail('DATASET_ADMIN_SQL_PRIVILEGES_UNSAFE');}
  const x=r.rows?.[0];
  if(r.rowCount!==1||x.version<180000||x.login==='paper_dataset_admin_agent'||
     !x.rolcanlogin||x.rolsuper||x.rolcreatedb||x.rolcreaterole||
     x.rolreplication||x.rolbypassrls||!x.allowed||x.role_switch||
     x.create_schema||x.can_delete||x.can_truncate||
     !x.can_claim||!x.can_complete||x.can_read_all||x.owner_member||
     x.extra_roles!==0||x.bad_role_options!==0||
     x.inherited_extra_roles!==0||
     x.can_change_dataset||x.can_change_owner||x.can_change_reservation||
     x.can_change_ticket||x.can_forge_state||x.can_forge_completion){
    fail('DATASET_ADMIN_SQL_PRIVILEGES_UNSAFE');
  }
  return true;
}
async function bounded(response){
  if(!response.body)return '';
  const reader=response.body.getReader();
  const pieces=[];let total=0;
  try{
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      total+=value.byteLength;
      if(total>2048)fail('DATASET_ADMIN_FUSEKI_UNAVAILABLE',503);
      pieces.push(Buffer.from(value));
    }
  }catch(error){
    try{await reader.cancel();}catch  { /* Best-effort cleanup or optional parsing; caller handles the fallback. */ }
    throw error;
  }finally{reader.releaseLock();}
  return Buffer.concat(pieces,total).toString('utf8');
}
export async function createDisposableDatasetAdmin({
  pool,origin=ORIGIN,adminUsername,adminPassword,publicKeyPem
}={}){
  if(!disposable()||origin!==ORIGIN||
     adminUsername!=='admin'||adminPassword!=='fixture-admin-only'||
     typeof publicKeyPem!=='string'||!publicKeyPem||
     typeof pool?.connect!=='function')fail('DATASET_ADMIN_CONFIG_UNSAFE');
  await assertRestrictedDatasetAdminLogin(pool);
  let key;
  try{
    key=crypto.createPublicKey(publicKeyPem);
    if(key.asymmetricKeyType!=='ed25519')fail();
  }catch{fail('DATASET_ADMIN_ISSUER_INVALID');}
  const basic='Basic '+Buffer.from(adminUsername+':'+adminPassword).toString('base64');
  const template = await readFile(require.resolve('@semapps/triplestore/templates/secure-dataset.ttl'), 'utf8');
  async function fuseki(endpoint,method,body=null,type=null,principal='system'){
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),6000);
    try{
      const response=await fetch(origin+endpoint,{
        method,headers:{authorization:basic,'X-SemappsUser':principal,
          ...(type?{'content-type':type}:{}),
          accept:'application/sparql-results+json'},
        body,redirect:'manual',signal:controller.signal
      });
      const status=response.status;
      const bodyText=await bounded(response);
      return {status,body:bodyText};
    }catch{fail('DATASET_ADMIN_FUSEKI_UNAVAILABLE',503);}
    finally{clearTimeout(timer);}
  }
  async function claimRow(p){
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      await client.query(
        'INSERT INTO paper_dataset_admin_proof.claims '+
        '(dataset,owner_webid,reservation_id,signed_ticket_sha256) '+
        'VALUES($1,$2,$3::uuid,$4) ON CONFLICT DO NOTHING',
        [p.dataset,p.ownerWebid,p.reservationId,p.sha256]
      );
      const r=await client.query(
        'SELECT dataset,owner_webid,reservation_id,signed_ticket_sha256,state '+
        'FROM paper_dataset_admin_proof.claims WHERE dataset=$1 FOR UPDATE',
        [p.dataset]
      );
      if(r.rowCount!==1||r.rows[0].owner_webid!==p.ownerWebid||
         r.rows[0].reservation_id!==p.reservationId||
         !Buffer.isBuffer(r.rows[0].signed_ticket_sha256)||
         !crypto.timingSafeEqual(r.rows[0].signed_ticket_sha256,p.sha256)){
        fail('DATASET_ADMIN_CLAIM_CONFLICT',409);
      }
      await client.query('COMMIT');
      return r.rows[0].state;
    }catch(e){
      await client.query('ROLLBACK').catch(()=>{});
      if(e.httpStatus)throw e;
      fail('DATASET_ADMIN_SQL_UNAVAILABLE',503);
    }finally{client.release();}
  }
  async function ask(dataset, pattern, principal = 'system') {
    const result = await fuseki('/'+dataset+'/query', 'POST', 'ASK WHERE { '+pattern+' }',
      'application/sparql-query', principal);
    if (result.status === 404) return null;
    if (result.status !== 200) fail('DATASET_ADMIN_DATASET_UNVERIFIED',503);
    let value;
    try { value = JSON.parse(result.body).boolean; } catch { /* Refuse malformed readback below. */ }
    if (typeof value !== 'boolean') fail('DATASET_ADMIN_DATASET_UNVERIFIED',503);
    return value;
  }
  async function provisionOnce(p) {
    const state = await claimRow(p);
    // Only the admin writes this private witness, and only following a
    // successful assembler creation. Never adopt a pre-existing empty Pod.
    const marker = '<urn:paper:dataset:' + p.sha256.toString('hex') + '> <urn:paper:secured> true';
    const visible = await ask(p.dataset, marker);
    if (visible !== true) {
      if (state !== 'pending' || visible !== null) fail('DATASET_ADMIN_DATASET_UNVERIFIED',503);
      const created = await fuseki('/$/datasets','POST',template.replaceAll('{dataset}',p.dataset),'text/turtle');
      if (![200,201,204].includes(created.status)) fail('DATASET_ADMIN_CREATE_REJECTED',503);
      const written = await fuseki('/'+p.dataset+'/update','POST','INSERT DATA { '+marker+' }','application/sparql-update');
      if (![200,204].includes(written.status) || await ask(p.dataset,marker) !== true) {
        fail('DATASET_ADMIN_CREATE_UNVERIFIED',503);
      }
    }
    if (await ask(p.dataset,marker,'anon') !== false) fail('DATASET_ADMIN_WEBACL_UNVERIFIED',503);
    if (state === 'pending') {
      const r=await pool.query(
        'UPDATE paper_dataset_admin_proof.claims '+
        "SET state='created',completed_at=clock_timestamp() "+
        "WHERE dataset=$1 AND owner_webid=$2 AND reservation_id=$3::uuid "+
        "AND signed_ticket_sha256=$4 AND state='pending'",
        [p.dataset,p.ownerWebid,p.reservationId,p.sha256]
      );
      if(r.rowCount!==1){
        // Another same-proof worker may have completed, but do not
        // trust it without a matching ledger read and dataset proof.
        const found=await pool.query(
          'SELECT state,signed_ticket_sha256 FROM paper_dataset_admin_proof.claims '+
          'WHERE dataset=$1 AND owner_webid=$2 AND reservation_id=$3::uuid',
          [p.dataset,p.ownerWebid,p.reservationId]
        );
        if(found.rowCount!==1||found.rows[0].state!=='created'||
           !crypto.timingSafeEqual(found.rows[0].signed_ticket_sha256,p.sha256)){
          fail('DATASET_ADMIN_CONCURRENT_STATE_UNSAFE',503);
        }
      }
    }
    return Object.freeze({created:true,dataset:p.dataset,ownerWebid:p.ownerWebid,
      idempotent:state==='created'});
  }
  const running = new Map();
  function provision(ticket,{now=Date.now()}={}) {
    const claim = verifyDisposableDatasetClaim(ticket,key,now);
    const digest = claim.sha256.toString('hex');
    if (running.has(digest)) return running.get(digest);
    if (running.size >= 16) fail('DATASET_ADMIN_BUSY',503);
    const pending = provisionOnce(claim).finally(() => running.delete(digest));
    running.set(digest,pending);
    return pending;
  }
  return Object.freeze({provision});
}
export function makeDisposableDatasetAdminHttpServer({admin,port=3042}={}){
  if(!disposable()||typeof admin?.provision!=='function'||
     port!==3042)fail('DATASET_ADMIN_SERVER_NOT_RELEASED');
  const server=http.createServer(async(req,res)=>{
    const answer=(status,body)=>{
      const value=JSON.stringify(body);
      res.writeHead(status,{'content-type':'application/json; charset=utf-8',
        'cache-control':'no-store','content-length':Buffer.byteLength(value)});
      res.end(value);
    };
    if(req.url!=='/v1/provision'||req.method!=='POST'){
      answer(404,{error:'NotFound'});return;
    }
    if((req.headers['content-type']||'').split(';')[0]!=='application/json'){
      answer(415,{error:'UnsupportedMediaType'});return;
    }
    const length=Number(req.headers['content-length']);
    if(Number.isFinite(length)&&length>4096){
      answer(413,{error:'PayloadTooLarge'});req.resume();return;
    }
    let chunks=[],total=0;
    try{
      for await(const chunk of req){
        total+=chunk.length;
        if(total>4096)fail('DATASET_ADMIN_BODY_TOO_LARGE',413);
        chunks.push(chunk);
      }
      const body=JSON.parse(Buffer.concat(chunks,total).toString('utf8'));
      object(body,['ticket']);
      const result=await admin.provision(body.ticket);
      answer(200,{created:result.created,idempotent:result.idempotent});
    }catch(error){
      const code=Number(error.httpStatus);
      answer([403,409,413,503].includes(code)?code:403,
        {error:code===409?'Conflict':code===503?'Unavailable':'Forbidden'});
    }
  });
  server.maxConnections=16;
  server.maxRequestsPerSocket=8;
  server.requestTimeout=10000;
  server.headersTimeout=8000;
  server.keepAliveTimeout=2000;
  return server;
}

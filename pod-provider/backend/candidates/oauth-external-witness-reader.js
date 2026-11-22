'use strict';

// NONACTIVATED external OAuth epoch witness. Distinct PG18 failure-domain
// LOGIN, no authority to issue/revoke/seal or read witness data tables.
// Requires a separate independently backed WORM receipt policy in production.
const crypto=require('node:crypto');
const EPOCH=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const GRANT=/^[A-Za-z0-9_-]{32}$/u;
const HASH=/^[0-9a-f]{64}$/u;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
function fail(code) {
  const e=new Error('Independent OAuth recovery witness unavailable');
  e.code=code;
  throw e;
}
function https(value) {
  if(typeof value!=='string'||value.length<8||value.length>2048)return false;
  try{
    const u=new URL(value);
    return u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&
      !u.hash&&u.href===value;
  }catch{return false}
}
function gate() {
  if(process.env.NODE_ENV!=='test'||
     process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed')
    fail('PG_OAUTH_WITNESS_NOT_RELEASED');
}
function createDisposableOauthWitnessReader({
  pool,clientIds,readImmutableHeadReceipt=null,fixtureOnly=false
}={}) {
  gate();
  if(fixtureOnly!==true||typeof pool?.connect!=='function'||
     !Array.isArray(clientIds)||clientIds.length<1||clientIds.length>16)
    fail('PG_OAUTH_WITNESS_CONFIGURATION_INVALID');
  // NONACTIVATED external immutable authority. The callback is private
  // configuration, not a query/body argument or cached replica. It must
  // return the latest retained epoch after independently verifying Object
  // Lock policy, high-water enumeration, and exact uncached object readback.
  const flag=process.env.PAPER_OAUTH_WORM_HIGHWATER_DISPOSABLE;
  if((flag!==undefined || readImmutableHeadReceipt!==null) &&
     (flag!=='confirmed' || typeof readImmutableHeadReceipt!=='function'))
    fail('PG_OAUTH_HIGHWATER_NOT_RELEASED');
  const requireHead=flag==='confirmed';
  const clients=new Set();
  for(const value of clientIds){
    if(!https(value)||clients.has(value))
      fail('PG_OAUTH_WITNESS_CONFIGURATION_INVALID');
    clients.add(value);
  }
  async function borrow(){
    let expired=false,timer;
    const pending=Promise.resolve().then(()=>pool.connect()).then(c=>{
      if(expired){c?.release?.(true);fail('PG_OAUTH_WITNESS_UNAVAILABLE')}
      if(typeof c?.query!=='function'||typeof c?.release!=='function')
        fail('PG_OAUTH_WITNESS_UNAVAILABLE');
      return c;
    });
    try{return await Promise.race([pending,new Promise((_,reject)=>{
      timer=setTimeout(()=>{expired=true;reject(Error('Witness acquire timeout'))},3500);
    })])}finally{clearTimeout(timer)}
  }
  async function admission(c){
    let result;
    try {
      result=await c.query({
        text:"SELECT current_setting('server_version_num')::integer AS version,"+
          "current_user=session_user AS own_login,"+
          "NOT pg_catalog.pg_is_in_recovery() AS primary_host,"+
          "r.rolcanlogin AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole"+
          " OR r.rolreplication OR r.rolbypassrls) AS restricted,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_witness_reader','USAGE') AS reader,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_witness_reader','SET') AS can_switch,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_witness_issuer','MEMBER') AS issuer,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_witness_revoker','MEMBER') AS revoker,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_witness_attestor','MEMBER') AS attestor,"+
          "pg_catalog.has_schema_privilege(current_user,"+
          "'paper_oauth_restore_witness','CREATE') AS schema_create,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_oauth_restore_witness.current_epochs',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS direct_current,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_oauth_restore_witness.events',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS direct_events,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_oauth_restore_witness.verify(text,text,bytea,bigint)',"+
          "'EXECUTE') AS can_verify,"+
          (requireHead ?
           "pg_catalog.has_function_privilege(current_user,"+
           "'paper_oauth_restore_witness.active_checkpoint(text,text,bytea,bigint)',"+
           "'EXECUTE') AS can_checkpoint," : "FALSE AS can_checkpoint,")+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_oauth_restore_witness.issue(text,text,bytea,bigint,uuid)',"+
          "'EXECUTE') AS can_issue,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_oauth_restore_witness.block(text,text,bytea,bigint,uuid)',"+
          "'EXECUTE') AS can_block,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_oauth_restore_witness.seal(text,text,bigint,uuid,bytea)',"+
          "'EXECUTE') AS can_seal,"+
          "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members "+
          "WHERE member=r.oid) AS memberships,"+
          "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members am "+
          "WHERE am.member=r.oid AND "+
          "(am.set_option OR am.admin_option OR NOT am.inherit_option)) AS bad_options"+
          " FROM pg_catalog.pg_roles r WHERE r.rolname=current_user",
        query_timeout:3000
      });
    }catch{fail('PG_OAUTH_WITNESS_ROLE_UNSAFE')}
    const x=result?.rows?.[0];
    if(result.rowCount!==1||x.version<180000||x.own_login!==true||
       x.primary_host!==true||
       x.restricted!==true||x.reader!==true||x.can_switch!==false||
       x.issuer!==false||x.revoker!==false||x.attestor!==false||
       x.schema_create!==false||x.direct_current!==false||
       x.direct_events!==false||x.can_verify!==true||
       x.can_issue!==false||x.can_block!==false||x.can_seal!==false||
       (requireHead&&x.can_checkpoint!==true)||
       x.memberships!==1||x.bad_options!==0)
      fail('PG_OAUTH_WITNESS_ROLE_UNSAFE');
  }
  async function verify(p) {
    gate();
    if(!p||!https(p.canonicalAccountId)||!clients.has(p.clientId)||
       !GRANT.test(p.consentGrantId||'')||
       typeof p.oauthPgRevision!=='string'||
       !EPOCH.test(p.oauthPgRevision)||
       BigInt(p.oauthPgRevision)>MAX)
      fail('PG_OAUTH_WITNESS_SCOPE_INVALID');
    let c,discard=false;
    try{
      c=await borrow();
      await admission(c);
      const values=[p.canonicalAccountId,p.clientId,
        crypto.createHash('sha256').update(p.consentGrantId,'utf8').digest(),
        p.oauthPgRevision];
      if(!requireHead){
        const r=await c.query({
          text:'SELECT paper_oauth_restore_witness.verify('+
            '$1::text,$2::text,$3::bytea,$4::bigint) AS allowed',
          values,query_timeout:3000
        });
        return r.rowCount===1&&r.rows[0].allowed===true;
      }
      const sql='SELECT * FROM paper_oauth_restore_witness.active_checkpoint('+
        '$1::text,$2::text,$3::bytea,$4::bigint)';
      const checkpoint=async()=>{
        const q=await c.query({text:sql,values,query_timeout:3000});
        if(q.rowCount!==1)return null;
        const row=q.rows[0];
        if(!EPOCH.test(row.revision||'')||
           BigInt(row.revision)>MAX||!HASH.test(row.event_sha256||'')||
           !UUID.test(row.operation_id||''))return null;
        return row;
      };
      // Check before AND after the archive GET. A revocation/rotation that
      // lands during the independent network read must fail closed rather
      // than authorize a stale snapshot.
      const before=await checkpoint();
      if(!before)return false;
      let raw,timeout;
      const controller=new AbortController();
      try{
        raw=await Promise.race([
          Promise.resolve().then(()=>readImmutableHeadReceipt(Object.freeze({
            owner:p.canonicalAccountId,clientId:p.clientId,
            signal:controller.signal
          }))),
          new Promise((_,reject)=>{
            timeout=setTimeout(()=>reject(Error('Immutable archive timeout')),3000);
          })
        ]);
      }finally{
        clearTimeout(timeout);
        controller.abort();
      }
      if(!Buffer.isBuffer(raw)||raw.length<100||raw.length>512)
        fail('PG_OAUTH_HIGHWATER_INVALID');
      let archive;
      try{archive=JSON.parse(raw.toString('utf8'))}
      catch{fail('PG_OAUTH_HIGHWATER_INVALID')}
      if(!archive||Array.isArray(archive)||
         Object.keys(archive).sort().join(',')!==
          'eventSha256,kind,operationId,revision,subject'||
         archive.kind!=='paper.witness.epoch.v1'||
         !EPOCH.test(archive.revision||'')||BigInt(archive.revision)>MAX||
         !UUID.test(archive.operationId||'')||
         !HASH.test(archive.eventSha256||'')||
         !HASH.test(archive.subject||''))
        fail('PG_OAUTH_HIGHWATER_INVALID');
      // Reject alternate JSON serialization or extra whitespace. The
      // immutable archive must expose exactly the bytes authored by the
      // separate epoch receipt attestor, not an attacker-authored summary.
      const canonical=Buffer.from(JSON.stringify({
        kind:archive.kind,subject:archive.subject,revision:archive.revision,
        operationId:archive.operationId,eventSha256:archive.eventSha256
      }),'utf8');
      if(canonical.length!==raw.length||
         !crypto.timingSafeEqual(raw,canonical))
        fail('PG_OAUTH_HIGHWATER_INVALID');
      const subject=crypto.createHash('sha256')
        .update('paper:witness:subject:v1\0')
        .update(p.canonicalAccountId).update('\0').update(p.clientId)
        .digest('hex');
      if(!crypto.timingSafeEqual(Buffer.from(subject,'hex'),
          Buffer.from(archive.subject,'hex')))
        fail('PG_OAUTH_HIGHWATER_SCOPE_INVALID');
      const after=await checkpoint();
      if(!after)return false;
      if(before.revision!==after.revision||
         before.operation_id!==after.operation_id||
         before.event_sha256!==after.event_sha256)
        return false;
      return archive.revision===after.revision&&
        archive.operationId===after.operation_id&&
        crypto.timingSafeEqual(Buffer.from(archive.eventSha256,'hex'),
         Buffer.from(after.event_sha256,'hex'));
    }catch(e) {
      discard=true;
      throw (e?.code?.startsWith('PG_OAUTH_WITNESS_')||
        e?.code?.startsWith('PG_OAUTH_HIGHWATER_'))?e:
        Object.assign(new Error('Independent OAuth witness unavailable'),
          {code:'PG_OAUTH_WITNESS_UNAVAILABLE'});
    }finally{if(c)c.release(discard)}
  }
  return Object.freeze({verify});
}
module.exports={createDisposableOauthWitnessReader};

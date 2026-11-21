'use strict';

// NONACTIVATED external OAuth epoch witness. Distinct PG18 failure-domain
// LOGIN, no authority to issue/revoke/seal or read witness data tables.
// Requires a separate independently backed WORM receipt policy in production.
const crypto=require('node:crypto');
const EPOCH=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const GRANT=/^[A-Za-z0-9_-]{32}$/u;
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
  pool,clientIds,fixtureOnly=false
}={}) {
  gate();
  if(fixtureOnly!==true||typeof pool?.connect!=='function'||
     !Array.isArray(clientIds)||clientIds.length<1||clientIds.length>16)
    fail('PG_OAUTH_WITNESS_CONFIGURATION_INVALID');
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
       x.restricted!==true||x.reader!==true||x.can_switch!==false||
       x.issuer!==false||x.revoker!==false||x.attestor!==false||
       x.schema_create!==false||x.direct_current!==false||
       x.direct_events!==false||x.can_verify!==true||
       x.can_issue!==false||x.can_block!==false||x.can_seal!==false||
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
      const r=await c.query({
        text:'SELECT paper_oauth_restore_witness.verify('+
          '$1::text,$2::text,$3::bytea,$4::bigint) AS allowed',
        values:[p.canonicalAccountId,p.clientId,
          crypto.createHash('sha256').update(p.consentGrantId,'utf8').digest(),
          p.oauthPgRevision],
        query_timeout:3000
      });
      return r.rowCount===1&&r.rows[0].allowed===true;
    }catch(e) {
      discard=true;
      throw e?.code?.startsWith('PG_OAUTH_WITNESS_')?e:
        Object.assign(new Error('Independent OAuth witness unavailable'),
          {code:'PG_OAUTH_WITNESS_UNAVAILABLE'});
    }finally{if(c)c.release(discard)}
  }
  return Object.freeze({verify});
}
module.exports={createDisposableOauthWitnessReader};

'use strict';

// NONACTIVATED, disposable-only primary PostgreSQL OAuth epoch admission.
// No SQL credentials may be held by browser/app/ordinary provider sessions.
// This reader cannot issue, revoke, sign or directly SELECT consent tables.
const crypto=require('node:crypto');
const MAX=9223372036854775807n;
const EPOCH=/^[1-9][0-9]{0,18}$/u;
const GRANT=/^[A-Za-z0-9_-]{32}$/u;
function refuse(code='PG_OAUTH_EPOCH_UNAVAILABLE'){
  const err=new Error('PostgreSQL OAuth consent authority unavailable');
  err.code=code;
  throw err;
}
function https(value){
  if(typeof value!=='string'||value.length<8||value.length>2048)return false;
  try{
    const u=new URL(value);
    return u.protocol==='https:'&&!u.username&&!u.password&&!u.search&&
      !u.hash&&u.href===value;
  }catch{return false}
}
function acceptedRevision(value){
  return typeof value==='string'&&EPOCH.test(value)&&BigInt(value)<=MAX;
}
function createDisposableOauthPgEpochReader({pool,approvedApps,fixtureOnly=false}={}){
  const gate=()=>{
    if(fixtureOnly!==true||process.env.NODE_ENV!=='test'||
       process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE!=='confirmed'||
       process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
       process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed')
      refuse('PG_OAUTH_EPOCH_NOT_RELEASED');
  };
  gate();
  if(typeof pool?.connect!=='function'||!Array.isArray(approvedApps)||
     approvedApps.length<1||approvedApps.length>16)
    refuse('PG_OAUTH_EPOCH_CONFIGURATION_INVALID');
  const apps=new Map();
  for(const a of approvedApps){
    if(!https(a?.clientId)||!https(a?.appUri)||apps.has(a.clientId))
      refuse('PG_OAUTH_EPOCH_CONFIGURATION_INVALID');
    apps.set(a.clientId,a.appUri);
  }
  async function borrow(){
    let timedOut=false,timer;
    const pending=Promise.resolve().then(()=>pool.connect()).then(client=>{
      if(timedOut){client?.release?.(true);refuse();}
      if(typeof client?.query!=='function'||typeof client?.release!=='function')
        refuse();
      return client;
    });
    try{return await Promise.race([pending,new Promise((_,reject)=>{
      timer=setTimeout(()=>{timedOut=true;reject(Error('PG OAuth reader acquire timeout'));},3500);
    })])}finally{clearTimeout(timer)}
  }
  async function admission(client){
    let row;
    try{
      const result=await client.query({
        text:"SELECT current_setting('server_version_num')::integer AS v,"+
          " current_user=session_user AS own_login,"+
          " r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole"+
          " OR r.rolreplication OR r.rolbypassrls) AS restricted,"+
          " pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_reader','USAGE') AS reader,"+
          " pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_reader','SET') AS can_switch,"+
          " pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_issuer','MEMBER') AS issuer,"+
          " pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_revoker','MEMBER') AS revoker,"+
          " pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_signer','MEMBER') AS signer,"+
          " pg_catalog.has_schema_privilege(current_user,'paper_atproto_authority','CREATE') AS schema_create,"+
          " pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.oauth_generations',"+
          " 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS table_access,"+
          " pg_catalog.has_any_column_privilege(current_user,'paper_atproto_authority.oauth_generations',"+
          " 'SELECT,INSERT,UPDATE,REFERENCES') AS column_access,"+
          " pg_catalog.has_function_privilege(current_user,"+
          " 'paper_atproto_authority.current_oauth_generation(text,text,text,text,bytea)','EXECUTE') AS current_fn,"+
          " pg_catalog.has_function_privilege(current_user,"+
          " 'paper_atproto_authority.verify_oauth_generation(text,text,text,text,bytea,bigint)','EXECUTE') AS verify_fn,"+
          " pg_catalog.has_function_privilege(current_user,"+
          " 'paper_atproto_authority.issue_oauth_generation(text,text,text,text,bytea,bigint,bigint)','EXECUTE') AS issue_fn,"+
          " pg_catalog.has_function_privilege(current_user,"+
          " 'paper_atproto_authority.revoke_oauth_generation(text,text,text,bigint)','EXECUTE') AS revoke_fn,"+
          " pg_catalog.has_function_privilege(current_user,"+
          " 'paper_atproto_authority.lock_oauth_generation_for_write(text,text,text,text,bytea,bigint)','EXECUTE') AS lock_fn,"+
          " (SELECT count(*)::integer FROM pg_catalog.pg_auth_members WHERE member=r.oid) AS memberships,"+
          " (SELECT count(*)::integer FROM pg_catalog.pg_auth_members am WHERE am.member=r.oid"+
          " AND (am.set_option OR am.admin_option OR NOT am.inherit_option)) AS bad_options"+
          " FROM pg_catalog.pg_roles r WHERE r.rolname=current_user",
        query_timeout:3000
      });
      if(result.rowCount!==1)refuse();
      row=result.rows[0];
    }catch{refuse('PG_OAUTH_EPOCH_ROLE_UNSAFE')}
    if(row.v<180000||row.own_login!==true||row.restricted!==true||
       row.reader!==true||row.can_switch!==false||
       row.issuer!==false||row.revoker!==false||row.signer!==false||
       row.schema_create!==false||row.table_access!==false||
       row.column_access!==false||row.current_fn!==true||
       row.verify_fn!==true||row.issue_fn!==false||
       row.revoke_fn!==false||row.lock_fn!==false||
       row.memberships!==1||row.bad_options!==0)
      refuse('PG_OAUTH_EPOCH_ROLE_UNSAFE');
  }
  function params(p){
    gate();
    if(!p||!https(p.canonicalAccountId)||
       !apps.has(p.clientId)||
       !GRANT.test(p.consentGrantId||'')||
       typeof p.scope!=='string'||p.scope.length<1||p.scope.length>8192)
      refuse('PG_OAUTH_EPOCH_SCOPE_INVALID');
    return [
      p.canonicalAccountId,
      apps.get(p.clientId),
      p.clientId,
      p.consentGrantId,
      crypto.createHash('sha256').update(p.scope,'utf8').digest()
    ];
  }
  async function query(p,mode){
    const args=params(p);
    if(mode==='verify'){
      if(!acceptedRevision(p.oauthPgRevision))
        refuse('PG_OAUTH_EPOCH_SCOPE_INVALID');
      args.push(p.oauthPgRevision);
    }
    let client,discard=false;
    try{
      client=await borrow();
      await admission(client);
      const name=mode==='verify'?'verify_oauth_generation':'current_oauth_generation';
      const casts=mode==='verify'?'$1::text,$2::text,$3::text,$4::text,$5::bytea,$6::bigint':
        '$1::text,$2::text,$3::text,$4::text,$5::bytea';
      const sql='SELECT paper_atproto_authority.'+name+'('+casts+') AS result';
      const result=await client.query({text:sql,values:args,query_timeout:3000});
      if(result.rowCount!==1)refuse();
      if(mode==='verify')return result.rows[0].result===true;
      const revision=String(result.rows[0].result);
      return acceptedRevision(revision)?revision:null;
    }catch(e){
      discard=true;
      throw e?.code?.startsWith('PG_OAUTH_EPOCH_')?e:
        Object.assign(new Error('PG OAuth epoch primary admission unavailable'),
          {code:'PG_OAUTH_EPOCH_UNAVAILABLE'});
    }finally{if(client)client.release(discard)}
  }
  return Object.freeze({
    current:p=>query(p,'current'),
    verify:p=>query(p,'verify'),
    assertEnabled:gate
  });
}
module.exports={createDisposableOauthPgEpochReader};

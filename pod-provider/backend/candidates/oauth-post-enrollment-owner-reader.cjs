'use strict';

// NONACTIVATED. Read-only, post-enrollment owner admission for a future
// immutable pre-denial-intent ceremony. It does NOT issue/revoke OAuth,
// authenticate passwords, infer a user from a bearer token, or authorize a
// signed PDS write. A separate canonical writer must revalidate and lock
// the exact owner/credential/SAI/epoch after the immutable deny fence.
const crypto=require('node:crypto');
const EPOCH=/^[1-9][0-9]{0,18}$/u;
const GRANT=/^[A-Za-z0-9_-]{32}$/u;
const SESSION=/^[A-Za-z0-9_-]{43}$/u;
const HEX=/^[0-9a-f]{64}$/u;
const MAX=9223372036854775807n;
function reject(code){
  const e=new Error('Post-enrollment owner authority unavailable');
  e.code=code;
  throw e;
}
function enabled(){
  if(process.env.NODE_ENV!=='test'||
     process.env.PAPER_OAUTH_POST_ENROLLMENT_DISPOSABLE!=='confirmed'||
     process.env.PAPER_CREDENTIAL_PG_DISPOSABLE!=='confirmed'||
     process.env.PAPER_CREDENTIAL_HEAD_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_WITNESS_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_WORM_HIGHWATER_DISPOSABLE!=='confirmed')
    reject('OWNER_POST_ENROLLMENT_NOT_RELEASED');
}
function webid(x){
  if(typeof x!=='string'||x.length<8||x.length>2048)return false;
  try {
    const u=new URL(x);
    return u.protocol==='https:'&&!!u.hostname&&
      !u.username&&!u.password&&!u.search&&!u.hash&&u.href===x;
  }catch{return false}
}
function epoch(s){return typeof s==='string'&&EPOCH.test(s)&&BigInt(s)<=MAX}
function same(a,b){
  if(!a||!b)return false;
  return a.webId===b.webId&&a.sessionId===b.sessionId&&
    a.credentialSeal===b.credentialSeal;
}
function ownerProof(x){
  if(!x||typeof x!=='object'||Array.isArray(x)||
     !webid(x.webId)||typeof x.sessionId!=='string'||
     !SESSION.test(x.sessionId)||typeof x.credentialSeal!=='string'||
     !SESSION.test(x.credentialSeal))
    reject('OWNER_POST_ENROLLMENT_SESSION_INVALID');
  return Object.freeze({
    webId:x.webId,sessionId:x.sessionId,
    credentialSeal:x.credentialSeal
  });
}
async function bounded(task,timeoutMs){
  let timer;
  try{
    return await Promise.race([
      Promise.resolve().then(task),
      new Promise((_,fail)=>{timer=setTimeout(
        ()=>fail(Error('Owner admission read timed out')),timeoutMs)})
    ]);
  }finally{clearTimeout(timer)}
}
function createDisposablePostEnrollmentOwnerReader({
  pool,verifyBrowserSession,certifiedCredentialReader,nativeSaiReader,
  immutableWitnessReader,approvedClients,timeoutMs=3000,fixtureOnly=false
}={}){
  enabled();
  if(fixtureOnly!==true||typeof pool?.connect!=='function'||
     typeof verifyBrowserSession!=='function'||
     typeof certifiedCredentialReader?.readOwnerState!=='function'||
     typeof nativeSaiReader?.verifyFresh!=='function'||
     typeof immutableWitnessReader?.verify!=='function'||
     !Array.isArray(approvedClients)||approvedClients.length<1||
     approvedClients.length>16||
     approvedClients.some(x=>!webid(x))||
     new Set(approvedClients).size!==approvedClients.length||
     !Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>5000)
    reject('OWNER_POST_ENROLLMENT_CONFIG_INVALID');
  const clients=new Set(approvedClients);

  async function borrow(){
    let expired=false,timer;
    const pending=Promise.resolve().then(()=>pool.connect()).then(c=>{
      if(expired){c?.release?.(true);reject('OWNER_POST_ENROLLMENT_PG_UNAVAILABLE')}
      if(typeof c?.query!=='function'||typeof c?.release!=='function')
        reject('OWNER_POST_ENROLLMENT_PG_UNAVAILABLE');
      return c;
    });
    try{
      return await Promise.race([pending,new Promise((_,fail)=>{
        timer=setTimeout(()=>{
          expired=true;fail(Error('Owner reader acquire timed out'));
        },timeoutMs);
      })]);
    }finally{clearTimeout(timer)}
  }
  async function readPrimary(webId,clientId){
    let c,discard=false,tx=false;
    try{
      c=await borrow();
      // Transaction pooling must not move role inspection and canonical
      // snapshot onto different physical PG backend sessions.
      await c.query({text:'BEGIN READ ONLY',query_timeout:timeoutMs});
      tx=true;
      const result=await c.query({
        text:"SELECT current_setting('server_version_num')::integer AS version,"+
          "current_user=session_user AS own_login,"+
          "NOT pg_catalog.pg_is_in_recovery() AS primary_host,"+
          "r.rolcanlogin AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole"+
          " OR r.rolreplication OR r.rolbypassrls) AS restricted,"+
          "pg_catalog.pg_has_role(current_user,"+
          "'paper_oauth_post_enrollment_reader','USAGE') AS reader,"+
          "pg_catalog.pg_has_role(current_user,"+
          "'paper_oauth_post_enrollment_reader','SET') AS can_switch,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_issuer','MEMBER') AS issuer,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_revoker','MEMBER') AS revoker,"+
          "pg_catalog.pg_has_role(current_user,'paper_atproto_consent_attestor','MEMBER') AS sai_attestor,"+
          "pg_catalog.pg_has_role(current_user,'paper_credential_coordinator','MEMBER') AS credential_writer,"+
          "pg_catalog.has_schema_privilege(current_user,'paper_atproto_authority','CREATE') AS schema_create,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_atproto_authority.oauth_generations',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS raw_oauth,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_atproto_authority.consents',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS raw_sai,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_credential_epoch.owners',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS raw_credential,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_atproto_authority.current_post_enrollment_owner_grant(text,text)',"+
          "'EXECUTE') AS can_read,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_atproto_authority.issue_oauth_generation(text,text,text,text,bytea,bigint,bigint)',"+
          "'EXECUTE') AS can_issue_raw,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_atproto_authority.revoke_oauth_generation(text,text,text,bigint)',"+
          "'EXECUTE') AS can_revoke_raw,"+
          "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members WHERE member=r.oid) AS memberships,"+
          "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members am WHERE member=r.oid"+
          " AND (am.set_option OR am.admin_option OR NOT am.inherit_option)) AS bad_options,"+
          "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members am"+
          " WHERE am.member='paper_oauth_post_enrollment_reader'::regrole) AS parent_roles"+
          " FROM pg_catalog.pg_roles r WHERE r.rolname=current_user",
        query_timeout:timeoutMs
      });
      const x=result?.rows?.[0];
      if(result?.rowCount!==1||!Number.isInteger(x?.version)||
         x.version<180000||x.own_login!==true||x.primary_host!==true||
         x.restricted!==true||x.reader!==true||x.can_switch!==false||
         x.issuer!==false||x.revoker!==false||x.sai_attestor!==false||
         x.credential_writer!==false||x.schema_create!==false||
         x.raw_oauth!==false||x.raw_sai!==false||x.raw_credential!==false||
         x.can_read!==true||x.can_issue_raw!==false||x.can_revoke_raw!==false||
         x.memberships!==1||x.bad_options!==0||x.parent_roles!==0)
        reject('OWNER_POST_ENROLLMENT_ROLE_UNSAFE');
      const rowResult=await c.query({
        text:'SELECT * FROM paper_atproto_authority.current_post_enrollment_owner_grant($1::text,$2::text)',
        values:[webId,clientId],query_timeout:timeoutMs
      });
      if(rowResult?.rowCount!==1)
        reject('OWNER_POST_ENROLLMENT_GRANT_NOT_CURRENT');
      const r=rowResult.rows?.[0];
      if(!r||r.owner_webid!==webId||r.client_id!==clientId||
         !webid(r.app_uri)||!GRANT.test(r.grant_id||'')||
         !HEX.test(r.scope_sha256||'')||!epoch(r.oauth_revision)||
         !epoch(r.sai_revision)||!epoch(r.credential_epoch))
        reject('OWNER_POST_ENROLLMENT_GRANT_NOT_CURRENT');
      const committed=await c.query({text:'COMMIT',query_timeout:timeoutMs});
      if(committed?.command!=='COMMIT')reject('OWNER_POST_ENROLLMENT_PG_UNAVAILABLE');
      tx=false;
      return Object.freeze({...r});
    }catch(e){
      discard=true;
      if(tx)await c.query({text:'ROLLBACK',query_timeout:timeoutMs}).catch(()=>{});
      if(e?.code?.startsWith('OWNER_POST_ENROLLMENT_'))throw e;
      reject('OWNER_POST_ENROLLMENT_PG_UNAVAILABLE');
    }finally{if(c)c.release(discard)}
  }
  async function session(context){
    enabled();
    try{return ownerProof(await bounded(()=>verifyBrowserSession(context),timeoutMs))}
    catch{reject('OWNER_POST_ENROLLMENT_SESSION_INVALID')}
  }
  async function credential(webId){
    let c;
    try{c=await bounded(()=>certifiedCredentialReader.readOwnerState(webId),timeoutMs)}
    catch{reject('OWNER_POST_ENROLLMENT_CREDENTIAL_NOT_CURRENT')}
    if(!c||c.webId!==webId||c.mode!=='unified'||c.state!=='active'||
       !epoch(c.epoch))
      reject('OWNER_POST_ENROLLMENT_CREDENTIAL_NOT_CURRENT');
    return c.epoch;
  }
  async function sai(r){
    try{
      const active=await bounded(()=>nativeSaiReader.verifyFresh({
        ownerWebId:r.owner_webid,appUri:r.app_uri,
        saiRevision:r.sai_revision
      }),timeoutMs);
      if(active===true)return;
    }catch{}
    reject('OWNER_POST_ENROLLMENT_SAI_NOT_CURRENT');
  }
  async function witness(r){
    try{
      const active=await bounded(()=>immutableWitnessReader.verify({
        canonicalAccountId:r.owner_webid,clientId:r.client_id,
        consentGrantId:r.grant_id,oauthPgRevision:r.oauth_revision
      }),timeoutMs);
      if(active===true)return;
    }catch{}
    reject('OWNER_POST_ENROLLMENT_WITNESS_NOT_CURRENT');
  }
  return Object.freeze({
    // For a future pre-denial intent only; NEVER treat the returned object
    // as a permission to mutate. Revalidate in the actual canonical commit
    // transaction AFTER the separate immutable denial is archived.
    async inspectForDeny({context,clientId,expectedGrantId}={}){
      enabled();
      if(!clients.has(clientId)||!GRANT.test(expectedGrantId||''))
        reject('OWNER_POST_ENROLLMENT_SCOPE_INVALID');
      const first=await session(context);
      const epochBefore=await credential(first.webId);
      const r=await readPrimary(first.webId,clientId);
      if(r.grant_id!==expectedGrantId||
         r.credential_epoch!==epochBefore)
        reject('OWNER_POST_ENROLLMENT_GRANT_NOT_CURRENT');
      await sai(r);
      await witness(r);
      // No cached positive result. A session logout, password rotation,
      // SAI revoke, PG epoch change or WORM revocation between reads DENIES.
      const after=await readPrimary(first.webId,clientId);
      if(Object.keys(r).some(k=>r[k]!==after[k]))
        reject('OWNER_POST_ENROLLMENT_GRANT_NOT_CURRENT');
      if(await credential(first.webId)!==epochBefore)
        reject('OWNER_POST_ENROLLMENT_CREDENTIAL_NOT_CURRENT');
      await sai(after);
      await witness(after);
      const last=await session(context);
      if(!same(first,last))
        reject('OWNER_POST_ENROLLMENT_SESSION_INVALID');
      return Object.freeze({
        ownerWebId:r.owner_webid,clientId:r.client_id,
        appUri:r.app_uri,grantId:r.grant_id,
        oauthRevision:r.oauth_revision,
        saiRevision:r.sai_revision,credentialEpoch:epochBefore,
        scopeSha256:r.scope_sha256
      });
    }
  });
}
module.exports={createDisposablePostEnrollmentOwnerReader};

'use strict';

// NONACTIVATED — the initial OAuth epoch may only follow a freshly
// owner-claimed, authenticated enrollment journal. This provider-held adapter
// does not accept owner WebID, DID, client ID, app or SAI rights from callers.
// PostgreSQL v7 derives those from a bound, unexpired enrollment session.
// General post-enrollment consent and revocation need a separate authority.
const EPOCH=/^(0|[1-9][0-9]{0,18})$/u;
const MAX=9223372036854775807n;
const GRANT=/^[A-Za-z0-9_-]{32}$/u;
const SCOPE='atproto repo:app.bsky.feed.post?action=create';

function deny(code) {
  const e=new Error('Bound initial OAuth generation unavailable');
  e.code=code;
  throw e;
}
function origin(value) {
  if(typeof value!=='string'||value.length<8||value.length>2048)return false;
  try {
    const u=new URL(value);
    return u.protocol==='https:'&&u.origin===value&&!u.username&&
      !u.password&&!u.search&&!u.hash;
  } catch { return false; }
}
function gate(){
  if(process.env.NODE_ENV!=='test'||
     process.env.PAPER_ACCOUNTS_DISPOSABLE!=='confirmed'||
     process.env.PAPER_JOURNAL_BOUND_SAI_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed')
    deny('OWNER_OAUTH_EPOCH_NOT_RELEASED');
}
function createDisposableInitialOwnerEpochIssuer({
  pool,providerId,browserOrigin,fixtureOnly=false
}={}) {
  gate();
  if(fixtureOnly!==true||!origin(providerId)||!origin(browserOrigin)||
     typeof pool?.connect!=='function')
    deny('OWNER_OAUTH_EPOCH_CONFIG_INVALID');

  async function borrow(){
    let timedOut=false,timer;
    const pending=Promise.resolve().then(()=>pool.connect()).then(c=>{
      if(timedOut) {
        c?.release?.(true);
        deny('OWNER_OAUTH_EPOCH_UNAVAILABLE');
      }
      if(typeof c?.query!=='function'||typeof c?.release!=='function')
        deny('OWNER_OAUTH_EPOCH_UNAVAILABLE');
      return c;
    });
    try {
      return await Promise.race([pending,new Promise((_,reject)=>{
        timer=setTimeout(()=>{
          timedOut=true;reject(Error('Owner OAuth issuer acquisition timed out'));
        },3500);
      })]);
    } finally {clearTimeout(timer)}
  }
  async function admission(c){
    let r;
    try{
      r=await c.query({
        text:"SELECT current_setting('server_version_num')::integer AS version,"+
          "current_user=session_user AS own_login,"+
          "NOT pg_catalog.pg_is_in_recovery() AS primary_host,"+
          "p.rolcanlogin AND NOT (p.rolsuper OR p.rolcreatedb OR"+
          " p.rolcreaterole OR p.rolreplication OR p.rolbypassrls) AS restricted,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_issuer','USAGE') AS issuer,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_issuer','SET') AS can_switch,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_revoker','MEMBER') AS revoker,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_signer','MEMBER') AS signer,"+
          "pg_catalog.pg_has_role(current_user,'paper_oauth_epoch_reader','MEMBER') AS reader,"+
          "pg_catalog.pg_has_role(current_user,'paper_atproto_consent_issuer','MEMBER') AS sai_issuer,"+
          "pg_catalog.pg_has_role(current_user,'paper_atproto_consent_attestor','MEMBER') AS sai_attestor,"+
          "pg_catalog.has_schema_privilege(current_user,'paper_atproto_authority','CREATE') AS schema_create,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_atproto_authority.oauth_generations',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS direct_oauth,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_atproto_authority.consents',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS direct_sai,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_atproto_authority.identities',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS direct_id,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_account_candidate.signup_operations',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS direct_journal,"+
          "pg_catalog.has_table_privilege(current_user,"+
          "'paper_account_reservation_proof.reservations',"+
          "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') AS direct_reservations,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_atproto_authority.bound_signup_owner_scope(uuid,uuid,text)',"+
          "'EXECUTE') AS can_claim_raw_owner,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_atproto_authority.issue_session_oauth_generation(text,text,bytea,text,text,bigint)',"+
          "'EXECUTE') AS can_issue_session,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_atproto_authority.issue_oauth_generation(text,text,text,text,bytea,bigint,bigint)',"+
          "'EXECUTE') AS can_issue_raw,"+
          "pg_catalog.has_function_privilege(current_user,"+
          "'paper_atproto_authority.revoke_session_oauth_generation(text,text,bytea,text,bigint)',"+
          "'EXECUTE') AS can_revoke_session,"+
          "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members WHERE member=p.oid) AS memberships,"+
          "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members am WHERE member=p.oid"+
          " AND (am.set_option OR am.admin_option OR NOT am.inherit_option)) AS bad_options,"+
          "(SELECT count(*)::integer FROM pg_catalog.pg_auth_members am"+
          " WHERE am.member='paper_oauth_epoch_issuer'::regrole) AS parent_roles"+
          " FROM pg_catalog.pg_roles p WHERE p.rolname=current_user",
        query_timeout:3000
      });
    }catch{deny('OWNER_OAUTH_EPOCH_ROLE_UNSAFE')}
    const x=r?.rows?.[0];
    if(r?.rowCount!==1||!Number.isInteger(x?.version)||
       x.version<180000||x?.own_login!==true||
       x?.primary_host!==true||x?.restricted!==true||
       x?.issuer!==true||x?.can_switch!==false||
       x?.revoker!==false||x?.signer!==false||x?.reader!==false||
       x?.sai_issuer!==false||x?.sai_attestor!==false||
       x?.schema_create!==false||x?.direct_oauth!==false||
       x?.direct_sai!==false||x?.direct_id!==false||
       x?.direct_journal!==false||x?.direct_reservations!==false||
       x?.can_claim_raw_owner!==false||
       x?.can_issue_session!==true||x?.can_issue_raw!==false||
       x?.can_revoke_session!==false||x?.memberships!==1||
       x?.bad_options!==0||x?.parent_roles!==0)
      deny('OWNER_OAUTH_EPOCH_ROLE_UNSAFE');
  }
  return Object.freeze({
    // Only FIRST generation; without an independently archived revocation
    // intent no reapproval/rotation may invalidate a previous grant safely.
    async issueFirst({tokenHash,grantId,scope}={}){
      gate();
      if(!Buffer.isBuffer(tokenHash)||tokenHash.length!==32||
         !GRANT.test(grantId||'')||scope!==SCOPE)
        deny('OWNER_OAUTH_EPOCH_SCOPE_INVALID');
      // Do not retain a caller-mutable Buffer across asynchronous admission.
      const trustedHash=Buffer.from(tokenHash);
      let c,discard=false;
      try {
        c=await borrow();
        // Admission and the CAS must run on the SAME restricted PG LOGIN.
        await admission(c);
        const r=await c.query({
          text:'SELECT paper_atproto_authority.issue_session_oauth_generation('+
            '$1::text,$2::text,$3::bytea,$4::text,$5::text,$6::bigint) AS revision',
          values:[providerId,browserOrigin,trustedHash,grantId,SCOPE,'0'],
          query_timeout:5000
        });
        const rev=r?.rows?.[0]?.revision;
        if(r?.rowCount!==1||typeof rev!=='string'||!EPOCH.test(rev)||
           BigInt(rev)>MAX||rev!=='1')
          deny('OWNER_OAUTH_EPOCH_JOURNAL_NOT_CURRENT');
        return rev;
      }catch(e){
        discard=true;
        if(typeof e?.code==='string'&&e.code.startsWith('OWNER_OAUTH_EPOCH_'))
          throw e;
        deny('OWNER_OAUTH_EPOCH_UNAVAILABLE');
      }finally{if(c)c.release(discard)}
    }
  });
}
module.exports={createDisposableInitialOwnerEpochIssuer,SCOPE};

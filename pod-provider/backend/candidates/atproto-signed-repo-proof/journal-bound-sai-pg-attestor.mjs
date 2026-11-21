/**
 * NONACTIVATED independent native-SAI reader -> journal-verified PostgreSQL
 * owner consent. The only accepted operation identity is the coordinator's
 * existing reservation and account-signup operation UUID pair.
 *
 * A successful readback + SQL confirmation is evidence, NOT a cross-store
 * snapshot or durable authorization ticket. Record signing must lock current
 * PostgreSQL consent again during its own signed-head transaction.
 */
import crypto from 'node:crypto';
import {verifyNativeSaiEvidence} from './native-sai-pg-consent-attestor.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
function fail(code){
 const e=Error('Journal-bound owner consent evidence unavailable');
 e.code=code;throw e;
}
function disposable(){
 if(process.env.NODE_ENV!=='test'||
    process.env.PAPER_JOURNAL_BOUND_SAI_DISPOSABLE!=='confirmed'||
    process.env.ATPROTO_SAI_ACTIVATION_DISPOSABLE!=='confirmed'||
    process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'){
   fail('JOURNAL_SAI_NOT_RELEASED');
 }
}
export async function createDisposableJournalBoundSaiAttestor({
 pool,readNativeSai,config,fixtureOnly=false
}={}){
 disposable();
 if(fixtureOnly!==true||typeof pool?.connect!=='function'||
   typeof readNativeSai!=='function')fail('JOURNAL_SAI_CONFIGURATION_INVALID');
 const borrow=()=>borrowFromPool(pool);
 const initial=await borrow();
 let badInitial=false;
 try{
  await admission(initial);
 }catch(error){
  badInitial=true;
  throw error;
 }finally{initial.release(badInitial);}
 const inspect=async()=>{
  disposable();
  return verifyNativeSaiEvidence(await readNativeSai(config),config);
 };
 return Object.freeze({
  inspect,
  async attest({reservationId,operationId}={}){
   disposable();
   if(!UUID.test(reservationId||'')||!UUID.test(operationId||'')){
    fail('JOURNAL_SAI_OPERATION_INVALID');
   }
   const ids=Object.freeze({reservationId,operationId});
   const client=await borrow();
   let discard=false;
   try{
    await admission(client);
    const before=await inspect();
    await queryBool(client,'attest_bound_owner_consent',ids,before);
    const after=await inspect();
    if(before.grant!==after.grant||before.registration!==after.registration||
       !crypto.timingSafeEqual(before.digest,after.digest)){
      fail('JOURNAL_SAI_RDF_CHANGED');
    }
    await queryBool(client,'confirm_bound_owner_consent',ids,after);
    return Object.freeze({attested:true,grantUri:after.grant,
      registrationUri:after.registration,evidenceSha256:after.digest.toString('hex'),
      status:'evidence_only',productionReady:false});
   }catch(error){
    discard=true;
    if(typeof error?.code==='string'&&error.code.startsWith('JOURNAL_SAI_'))throw error;
    if(error?.code==='SAI_ACTIVATION_EVIDENCE_INVALID' ||
       error?.code==='SAI_ACTIVATION_NOT_RELEASED')throw error;
    fail('JOURNAL_SAI_STORAGE_OR_READBACK_UNAVAILABLE');
   }finally{client.release(discard);}
  }
 });
}

async function borrowFromPool(pool){
 let expired=false,timer;
 const pending=Promise.resolve().then(()=>pool.connect()).then(client=>{
  if(expired){client?.release?.(true);fail('JOURNAL_SAI_PG_CONNECTION_UNAVAILABLE');}
  if(!client||typeof client.query!=='function'||typeof client.release!=='function'){
   fail('JOURNAL_SAI_PG_CONNECTION_UNAVAILABLE');
  }
  return client;
 });
 try{
  return await Promise.race([pending,new Promise((_,reject)=>{
   timer=setTimeout(()=>{
    expired=true;
    reject(Object.assign(new Error('Restricted PG lease timeout'),
      {code:'JOURNAL_SAI_PG_CONNECTION_UNAVAILABLE'}));
   },3500);
  })]);
 }finally{clearTimeout(timer);}
}

async function admission(client){
 let inspection;
 try{
  inspection=await client.query(
   "SELECT current_setting('server_version_num')::integer AS version,"+
   " current_user=session_user AS own_login,"+
   " r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR"+
   " r.rolreplication OR r.rolbypassrls) AS restricted,"+
   " pg_catalog.pg_has_role(current_user,'paper_atproto_consent_attestor','USAGE') AS member,"+
   " pg_catalog.pg_has_role(current_user,'paper_atproto_consent_attestor','SET') AS can_switch,"+
   " pg_catalog.pg_has_role(current_user,'paper_atproto_consent_issuer','MEMBER') AS issuer,"+
   " pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer,"+
   " pg_catalog.pg_has_role(current_user,'paper_atproto_authority_revoker','MEMBER') AS revoker,"+
   " pg_catalog.has_schema_privilege(current_user,'paper_atproto_authority','CREATE') AS schema_create,"+
   " pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS table_rights,"+
   " pg_catalog.has_any_column_privilege(current_user,'paper_atproto_authority.consents','SELECT,INSERT,UPDATE,REFERENCES') AS column_rights,"+
   " pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.attest_bound_owner_consent(uuid,uuid,text,text,bytea)','EXECUTE') AS attest,"+
   " pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.confirm_bound_owner_consent(uuid,uuid,text,text,bytea)','EXECUTE') AS confirm,"+
   " pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.begin_bound_owner_consent(uuid,uuid)','EXECUTE') AS begin,"+
   " pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.begin_owner_consent(text,text,text,uuid,bytea)','EXECUTE') AS legacy_begin,"+
   " pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.attest_owner_consent(text,text,text,uuid,text,bytea)','EXECUTE') AS legacy_attest,"+
   " (SELECT count(*)::integer FROM pg_catalog.pg_auth_members"+
   "  WHERE member=r.oid) AS memberships,"+
   " (SELECT count(*)::integer FROM pg_catalog.pg_auth_members am"+
   "  WHERE am.member=r.oid AND (am.set_option OR am.admin_option OR NOT am.inherit_option)) AS unsafe_memberships,"+
   " (SELECT count(*)::integer FROM pg_catalog.pg_auth_members am"+
   "  WHERE am.member='paper_atproto_consent_attestor'::regrole) AS parent_memberships"+
   " FROM pg_catalog.pg_roles AS r WHERE r.rolname=current_user"
  );
 }catch{fail('JOURNAL_SAI_ATTESTOR_ROLE_UNSAFE');}
 const v=inspection.rows?.[0];
 if(inspection.rowCount!==1||v.version<180000||v.own_login!==true||
    v.restricted!==true||v.member!==true||v.can_switch!==false||
    v.issuer!==false||v.importer!==false||v.revoker!==false||
    v.schema_create!==false||v.table_rights!==false||v.column_rights!==false||
    v.attest!==true||v.confirm!==true||v.begin!==false||
    v.legacy_begin!==false||v.legacy_attest!==false||
    v.memberships!==1||v.unsafe_memberships!==0||v.parent_memberships!==0){
   fail('JOURNAL_SAI_ATTESTOR_ROLE_UNSAFE');
 }
}
async function queryBool(client,name,ids,proof){
 const reply=await client.query(
  'SELECT paper_atproto_authority.'+name+
   '($1::uuid,$2::uuid,$3::text,$4::text,$5::bytea) AS accepted',
  [ids.reservationId,ids.operationId,proof.registration,proof.grant,proof.digest]);
 if(reply.rowCount!==1||reply.rows[0]?.accepted!==true){
  fail('JOURNAL_SAI_SCOPE_STALE_OR_REVOKED');
 }
}
/**
 * PostgreSQL 18 startup privilege admission for NONACTIVATED projection
 * worker. It must not inherit signer, importer, revoker, schema-owner, or
 * arbitrary data mutator privileges. Each role is a distinct LOGIN.
 */
function reject(){
  const e=new Error('Restricted projection worker SQL authority unavailable');
  e.code='PROJECTION_WORKER_ROLE_REQUIRED';
  throw e;
}
export async function assertRestrictedProjectionWorkerLogin(pool){
  if(typeof pool?.query!=='function')reject();
  let result;
  try{
    result=await pool.query(
      "SELECT current_user AS login,current_setting('server_version_num')::int AS version,"+
      "r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_projection_worker','USAGE') AS worker,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_projection_worker','SET') AS set_worker,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_reader','USAGE') AS reader,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_repo_writer','MEMBER') AS signer,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_revoker','MEMBER') AS revoker,"+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='paper_atproto_repo_proof'),'MEMBER') AS repo_owner,"+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='paper_atproto_authority'),'MEMBER') AS auth_owner,"+
      "pg_catalog.has_schema_privilege(current_user,'paper_atproto_repo_proof','CREATE') AS schema_create,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.rdf_projection_jobs','SELECT') AS jobs_read,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.rdf_projection_jobs','UPDATE') AS jobs_col_update,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.rdf_projection_jobs','INSERT') AS jobs_col_insert,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.rdf_projection_jobs','DELETE') AS jobs_delete,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.repos','UPDATE') AS repo_col_update,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.repos','INSERT') AS repo_col_insert,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.blocks','UPDATE') AS blocks_col_update,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.blocks','INSERT') AS blocks_col_insert,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.native_event_outbox','UPDATE') AS event_col_update,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.native_event_outbox','INSERT') AS event_col_insert,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.record_mutations','UPDATE') AS mutations_col_update,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.record_mutations','INSERT') AS mutations_col_insert,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_authority.consents','UPDATE') AS consent_col_update,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_authority.consents','INSERT') AS consent_col_insert,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_authority.identities','UPDATE') AS identity_col_update,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_authority.identities','INSERT') AS identity_col_insert,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.rdf_projection_jobs','UPDATE') AS jobs_update,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.native_event_outbox','UPDATE') AS outbox_update,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.repos','UPDATE') AS repo_update,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.blocks','INSERT') AS blocks_insert,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','UPDATE') AS consent_update,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.identities','INSERT') AS identity_insert,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_repo_proof.claim_verified_projection(text,text,uuid,integer,integer,text,text,bigint)','EXECUTE') AS can_claim,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_repo_proof.ack_verified_projection(text,text,uuid,bigint,text,text,text,bigint,text,text,bigint)','EXECUTE') AS can_ack,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_repo_proof.release_failed_projection(text,text,uuid,bigint,text,double precision,text)','EXECUTE') AS can_fail,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_repo_proof.block_exhausted_projection(text,text,integer)','EXECUTE') AS can_block,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.block_consent(text,text,text,bigint)','EXECUTE') AS can_revoke "+
      "FROM pg_catalog.pg_roles AS r WHERE r.rolname=current_user"
    );
  }catch{reject();}
  if(result.rowCount!==1)reject();
  const x=result.rows[0];
  if(x.version<180000||typeof x.login!=='string'||
     x.login==='paper_atproto_projection_worker'||
     x.rolsuper||x.rolcreatedb||x.rolcreaterole||x.rolreplication||
     x.rolbypassrls||!x.worker||x.set_worker||!x.reader||
     x.signer||x.importer||x.revoker||x.repo_owner||x.auth_owner||
     x.schema_create||!x.jobs_read||x.jobs_update||x.outbox_update||
     x.repo_update||x.blocks_insert||x.consent_update||x.identity_insert||
     x.jobs_col_update||x.jobs_col_insert||x.jobs_delete||
     x.repo_col_update||x.repo_col_insert||
     x.blocks_col_update||x.blocks_col_insert||
     x.event_col_update||x.event_col_insert||
     x.mutations_col_update||x.mutations_col_insert||
     x.consent_col_update||x.consent_col_insert||
     x.identity_col_update||x.identity_col_insert||
     !x.can_claim||!x.can_ack||!x.can_fail||!x.can_block||x.can_revoke){
    reject();
  }
  return Object.freeze({restricted:true,maySign:false,mayRegrant:false,
    mayBypassLeases:false,postgresVersion:x.version});
}

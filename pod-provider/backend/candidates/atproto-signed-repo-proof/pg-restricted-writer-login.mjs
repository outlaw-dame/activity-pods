/**
 * Exact PostgreSQL 18 startup admission for the NONACTIVATED signed
 * repository write worker. Query ONLY trusted pg_catalog metadata on
 * this connection. Never rely on environment strings declaring a role.
 *
 * The role may read canonical identity/SAI and advance signed repo data,
 * but can neither import/regrant identity, revoke canonical consent,
 * mark a projection applied, nor acknowledge outbox delivery.
 */
function deny(){
  const error=new Error('Restricted signed-repository writer login unavailable');
  error.code='RESTRICTED_REPO_WRITER_LOGIN_REQUIRED';
  throw error;
}
export async function assertRestrictedRepoWriterLogin(pool){
  if(typeof pool?.query!=='function')deny();
  let result;
  try{
    result=await pool.query(
      "SELECT current_user AS login, "+
      "current_setting('server_version_num')::integer AS version, "+
      "r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, "+
      "r.rolbypassrls, "+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_repo_writer','USAGE') AS writer_usage, "+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_repo_writer','SET') AS writer_set, "+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_reader','USAGE') AS reader_usage, "+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer_member, "+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_revoker','MEMBER') AS revoker_member, "+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace "+
      "WHERE nspname='paper_atproto_repo_proof'),'MEMBER') AS repo_owner_member, "+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace "+
      "WHERE nspname='paper_atproto_authority'),'MEMBER') AS authority_owner_member, "+
      "pg_catalog.has_schema_privilege(current_user,'paper_atproto_repo_proof','CREATE') AS schema_create, "+
      "pg_catalog.has_column_privilege(current_user,'paper_atproto_repo_proof.blocks','block','INSERT') AS block_insert, "+
      "pg_catalog.has_column_privilege(current_user,'paper_atproto_repo_proof.record_mutations','commit_cid','INSERT') AS mutation_insert, "+
      "pg_catalog.has_column_privilege(current_user,'paper_atproto_repo_proof.native_event_outbox','commit_cid','INSERT') AS event_insert, "+
      "pg_catalog.has_column_privilege(current_user,'paper_atproto_repo_proof.repos','head_cid','UPDATE') AS repo_head_update, "+
      "pg_catalog.has_column_privilege(current_user,'paper_atproto_repo_proof.rdf_projection_jobs','updated_at','UPDATE') AS projection_lock_update, "+
      "pg_catalog.has_column_privilege(current_user,'paper_atproto_repo_proof.rdf_projection_jobs','state','UPDATE') AS projection_state_update, "+
      "pg_catalog.has_column_privilege(current_user,'paper_atproto_repo_proof.native_event_outbox','status','UPDATE') AS event_ack_update, "+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.repos','INSERT') AS repo_genesis_insert, "+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.identities','INSERT') AS identity_insert, "+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','INSERT') AS consent_insert, "+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','UPDATE') AS consent_update, "+
      "pg_catalog.has_function_privilege(current_user,"+
      "'paper_atproto_authority.block_consent(text,text,text,bigint)','EXECUTE') AS revoke_execute, "+
      "pg_catalog.has_function_privilege(current_user,"+
      "'paper_atproto_authority.lock_writer_consent(text,text,text,text,bigint)',"+
      "'EXECUTE') AS consent_lock_execute, "+
      "pg_catalog.has_function_privilege(current_user,"+
      "'paper_atproto_repo_proof.reset_after_signed_commit(text,text,text,text,text,bigint,text,text,text,bigint)',"+
      "'EXECUTE') AS reset_execute "+
      "FROM pg_catalog.pg_roles r WHERE r.rolname=current_user"
    );
  }catch{deny();}
  if(result.rowCount!==1)deny();
  const x=result.rows[0];
  if(x.version<180000 ||
     typeof x.login!=='string'||x.login==='paper_atproto_repo_writer'||
     x.rolsuper||x.rolcreatedb||x.rolcreaterole||x.rolreplication||
     x.rolbypassrls||!x.writer_usage||x.writer_set||!x.reader_usage||
     x.importer_member||x.revoker_member||
     x.repo_owner_member||x.authority_owner_member||x.schema_create||
     !x.block_insert||!x.mutation_insert||!x.event_insert||
     !x.repo_head_update||!x.projection_lock_update||
     x.projection_state_update||x.event_ack_update||
     x.repo_genesis_insert||x.identity_insert||x.consent_insert||
     x.consent_update||x.revoke_execute||
     !x.consent_lock_execute||!x.reset_execute){
    deny();
  }
  return Object.freeze({restricted:true,role:'paper_atproto_repo_writer',
    postgresVersion:x.version,mayRegrant:false,
    mayMarkProjectionApplied:false,mayAckEvents:false});
}

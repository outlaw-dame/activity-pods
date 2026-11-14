/**
 * NONACTIVATED exact independent attestor PostgreSQL 18 LOGIN admission.
 * Only the attestor can submit protected Jena readback receipts. No direct
 * SQL DML, legacy or attested ACK, signing, import/regrant or SET ROLE.
 */
import {assertExactRuntimePrivileges} from './pg-exact-runtime-privileges.mjs';
function deny(){
  const e=new Error('Independent protected RDF attestor credential required');
  e.code='PROTECTED_RDF_ATTESTOR_ROLE_REQUIRED'; throw e;
}
export async function assertRestrictedRdfAttestorLogin(pool){
  if(typeof pool?.query!=='function')deny();
  let result;
  try{
    result=await pool.query(
      "SELECT current_user AS login,current_setting('server_version_num')::int AS version,"+
      "r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,r.rolbypassrls,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_rdf_attestor','USAGE') AS attestor,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_rdf_attestor','SET') AS set_attestor,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_reader','USAGE') AS reader,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_projection_worker','MEMBER') AS worker,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_repo_writer','MEMBER') AS signer,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_revoker','MEMBER') AS revoker,"+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer,"+
      "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='paper_atproto_repo_proof'),'MEMBER') AS owner,"+
      "pg_catalog.has_schema_privilege(current_user,'paper_atproto_repo_proof','CREATE') AS schema_create,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.repos','SELECT') AS repo_read,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.rdf_projection_jobs','SELECT') AS job_read,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.rdf_attestations','INSERT') AS attestation_insert,"+
      "pg_catalog.has_any_column_privilege(current_user,'paper_atproto_repo_proof.rdf_attestations','UPDATE') AS attestation_update,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.rdf_attestations','DELETE') AS attestation_delete,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.rdf_attestations','TRUNCATE') AS attestation_truncate,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.rdf_attestations','TRIGGER') AS attestation_trigger,"+
      "pg_catalog.has_table_privilege(current_user,'paper_atproto_repo_proof.rdf_attestations','REFERENCES') AS attestation_references,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_repo_proof.attest_protected_rdf(text,text,uuid,bigint,text,text,text,bigint,text,text,bigint,bytea)','EXECUTE') AS can_attest,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_repo_proof.ack_attested_projection(text,text,uuid,bigint,text,text,text,bigint,text,text,bigint)','EXECUTE') AS can_ack,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_repo_proof.ack_verified_projection(text,text,uuid,bigint,text,text,text,bigint,text,text,bigint)','EXECUTE') AS can_legacy_ack,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_repo_proof.claim_verified_projection(text,text,uuid,integer,integer,text,text,bigint)','EXECUTE') AS can_claim,"+
      "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.block_consent(text,text,text,bigint)','EXECUTE') AS can_revoke "+
      "FROM pg_catalog.pg_roles AS r WHERE r.rolname=current_user"
    );
  }catch{deny();}
  if(result.rowCount!==1)deny();
  const x=result.rows[0];
  if(x.version<180000||typeof x.login!=='string'||
    x.login==='paper_atproto_rdf_attestor'||x.rolsuper||x.rolcreatedb||
    x.rolcreaterole||x.rolreplication||x.rolbypassrls||!x.attestor||
    x.set_attestor||!x.reader||x.worker||x.signer||x.revoker||
    x.importer||x.owner||x.schema_create||!x.repo_read||!x.job_read||
    x.attestation_insert||x.attestation_update||x.attestation_delete||
    x.attestation_truncate||x.attestation_trigger||
    x.attestation_references||!x.can_attest||x.can_ack||
    x.can_legacy_ack||x.can_claim||x.can_revoke)deny();
  try{await assertExactRuntimePrivileges(pool,{role:'rdf-attestor'});}
  catch{deny();}
  return Object.freeze({independent:true,mayWriteRdfSql:false,
    mayAck:false,mayRegrant:false,postgresVersion:x.version});
}

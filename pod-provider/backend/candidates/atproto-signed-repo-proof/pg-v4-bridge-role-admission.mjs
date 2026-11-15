/**
 * TEST-ONLY exact PostgreSQL 18 role admission for the separate v4 binder
 * and finalizer. Neither principal owns canonical account tables, has
 * direct table/column DML, or inherits a worker/signing/administrator role.
 * Any ambient privilege drift must refuse BEFORE processing a request.
 */
function reject() {
  const error = Error('Restricted v4 completion bridge SQL privileges are unsafe');
  error.code = 'V4_BRIDGE_SQL_PRIVILEGES_UNSAFE';
  throw error;
}
const TABLES=[
  'paper_account_reservation_proof.reservations',
  'paper_account_reservation_proof.daily_usage',
  'paper_account_candidate.accounts',
  'paper_account_candidate.signup_operations',
  'paper_atproto_repo_proof.repos',
  'paper_atproto_repo_proof.rdf_projection_jobs',
  'paper_atproto_repo_proof.native_event_outbox',
  'paper_atproto_authority.identities',
  'paper_atproto_authority.consents'
];
const FN_BIND='paper_account_reservation_proof.bind_v4_signup(uuid,text,text,bytea,bytea,text,text,uuid,uuid,smallint,bytea,bytea)';
const FN_REFLECT='paper_account_reservation_proof.reflect_v4_ready(uuid,text,text,bytea,bytea)';
const FN_UNSAFE=[
  'paper_account_reservation_proof.reserve(text,text,bytea,bytea,text,text,integer,integer)',
  'paper_account_reservation_proof.start_side_effects(text,text,bytea,uuid,uuid)',
  'paper_account_reservation_proof.claim_signup_once(text,text,bytea,bytea,uuid,text,text)',
  'paper_account_reservation_proof.complete(text,text,bytea,uuid,uuid,text,text,text,text,bytea)',
  'paper_account_reservation_proof.dataset_binding_is_live(text,text,uuid,uuid,text,text)',
  'paper_account_reservation_proof.dataset_claim_lease(text,text,uuid,uuid,text,text)'
];
export async function assertRestrictedV4BridgeLogin(pool,kind){
  if(process.env.NODE_ENV!=='test' ||
     process.env.PAPER_ACCOUNTS_DISPOSABLE!=='confirmed' ||
     process.env.APODS_ACCOUNT_RESERVATION_DISPOSABLE!=='confirmed' ||
     process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
     !['binder','finalizer'].includes(kind) ||
     !pool || typeof pool.query!=='function')reject();
  const role='paper_account_bridge_'+kind;
  const query=await pool.query(`
    SELECT current_setting('server_version_num')::int AS version,
      (SELECT rolcanlogin FROM pg_catalog.pg_roles WHERE rolname=current_user)
         AS can_login,
      (SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
       FROM pg_catalog.pg_roles WHERE rolname=current_user) AS privileged,
      pg_has_role(current_user,$1,'USAGE') AS expected_role,
      pg_has_role(current_user,$1,'SET') AS role_switch,
      pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace
        WHERE nspname='paper_account_reservation_proof'),'MEMBER') AS owner_member,
      (SELECT count(*)::int FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles m ON m.oid=am.member
       JOIN pg_catalog.pg_roles t ON t.oid=am.roleid
       WHERE m.rolname=current_user AND t.rolname<>$1) AS extra_roles,
      (SELECT count(*)::int FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles m ON m.oid=am.member
       JOIN pg_catalog.pg_roles t ON t.oid=am.roleid
       WHERE m.rolname=current_user AND t.rolname=$1
         AND (am.set_option OR am.admin_option OR NOT am.inherit_option))
         AS bad_role_options,
      (SELECT count(*)::int FROM pg_catalog.pg_auth_members am
       JOIN pg_catalog.pg_roles m ON m.oid=am.member
       WHERE m.rolname=$1) AS inherited_extra_roles,
      has_schema_privilege(current_user,
        'paper_account_reservation_proof','CREATE') AS schema_create,
      pg_has_role(current_user,'pg_read_all_data','member') AS read_all,
      pg_has_role(current_user,'pg_write_all_data','member') AS write_all,
      pg_has_role(current_user,'pg_monitor','member') AS monitor
  `,[role]);
  const p=query.rows?.[0];
  if(query.rowCount!==1 || p?.version<180000 ||
     p?.can_login!==true || p?.privileged!==false ||
     p?.expected_role!==true || p?.role_switch!==false ||
     p?.owner_member!==false || p?.extra_roles!==0 ||
     p?.bad_role_options!==0 || p?.inherited_extra_roles!==0 ||
     p?.schema_create!==false || p?.read_all!==false ||
     p?.write_all!==false || p?.monitor!==false)reject();
  for(const name of TABLES){
    const x=await pool.query(
      'SELECT has_table_privilege(current_user,$1,'+
      "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN') "+
      'AS table_access, has_any_column_privilege(current_user,$1,'+
      "'SELECT,INSERT,UPDATE,REFERENCES') AS column_access",[name]
    );
    if(x.rowCount!==1 || x.rows[0]?.table_access!==false ||
       x.rows[0]?.column_access!==false)reject();
  }
  for(const [fn,expected] of [
    [FN_BIND,kind==='binder'],[FN_REFLECT,kind==='finalizer'],
    ...FN_UNSAFE.map(name=>[name,false])
  ]){
    const x=await pool.query(
      "SELECT has_function_privilege(current_user,$1,'EXECUTE') AS execute",
      [fn]
    );
    if(x.rowCount!==1 || x.rows[0]?.execute!==expected)reject();
  }
  return true;
}

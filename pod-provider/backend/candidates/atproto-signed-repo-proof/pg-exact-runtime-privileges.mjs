/**
 * Exact PostgreSQL 18 effective DML privilege inventory for the two
 * NONACTIVATED PDS runtime workers. No per-account/tenant scan; 7 fixed
 * catalog relations, once per process at startup. Deny unknown privilege
 * additions, including table-wide DML, column DML, TRUNCATE and role
 * membership escalation (NOINHERIT+SET ROLE).
 */
const tables=Object.freeze([
  'paper_atproto_repo_proof.repos',
  'paper_atproto_repo_proof.blocks',
  'paper_atproto_repo_proof.native_event_outbox',
  'paper_atproto_repo_proof.rdf_projection_jobs',
  'paper_atproto_repo_proof.record_mutations',
  'paper_atproto_authority.identities',
  'paper_atproto_authority.consents'
]);
const privilegeModel=Object.freeze({
  'repo-writer':{
    'paper_atproto_repo_proof.repos':{update:['head_cid','root_cid','rev','generation']},
    'paper_atproto_repo_proof.blocks':{insert:['did','cid','block']},
    'paper_atproto_repo_proof.native_event_outbox':{insert:['did','commit_cid','rev','kind']},
    'paper_atproto_repo_proof.rdf_projection_jobs':{update:['updated_at']},
    'paper_atproto_repo_proof.record_mutations':{
      insert:['did','commit_cid','previous_commit_cid','previous_root_cid',
        'previous_rev','rev','action','path','previous_record_cid',
        'record_cid','generation']
    }
  },
  'projection-worker':{},
  'rdf-attestor':{}
});
function deny(){
  const e=new Error('Runtime PostgreSQL credential has unexpected grants');
  e.code='PG_RUNTIME_PRIVILEGES_UNSAFE';throw e;
}
export async function assertExactRuntimePrivileges(pool,{role}={}){
  const allowed=privilegeModel[role];
  if(!allowed||typeof pool?.query!=='function')deny();
  const expectedRole=role==='repo-writer'?'paper_atproto_repo_writer':
    role==='rdf-attestor'?'paper_atproto_rdf_attestor':
      'paper_atproto_projection_worker';
  let rows,membership;
  try{
    // Every legitimate direct membership is the one expected worker
    // NOLOGIN role. Inherited read-only canonical authority is a *second*
    // hop and cannot grant the LOGIN an independent SET ROLE capability.
    membership=await pool.query(
      "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members AS m "+
      "JOIN pg_catalog.pg_roles AS login ON m.member=login.oid "+
      "JOIN pg_catalog.pg_roles AS role ON role.oid=m.roleid "+
      "WHERE login.rolname=current_user AND role.rolname<>$1) "+
      "AS unexpected_member, "+
      "pg_catalog.has_schema_privilege(current_user,'paper_atproto_authority','CREATE') "+
      "AS authority_schema_create",
      [expectedRole]
    );
    rows=await pool.query(
      "SELECT n.nspname||'.'||c.relname AS relation, "+
      "a.attname::text AS column_name, "+
      "pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'INSERT') AS col_insert, "+
      "pg_catalog.has_column_privilege(current_user,c.oid,a.attnum,'UPDATE') AS col_update, "+
      "pg_catalog.has_table_privilege(current_user,c.oid,'INSERT') AS tab_insert, "+
      "pg_catalog.has_table_privilege(current_user,c.oid,'UPDATE') AS tab_update, "+
      "pg_catalog.has_table_privilege(current_user,c.oid,'DELETE') AS tab_delete, "+
      "pg_catalog.has_table_privilege(current_user,c.oid,'TRUNCATE') AS tab_truncate, "+
      "pg_catalog.has_table_privilege(current_user,c.oid,'TRIGGER') AS tab_trigger, "+
      "pg_catalog.has_table_privilege(current_user,c.oid,'REFERENCES') AS tab_references, "+
      "pg_catalog.has_table_privilege(current_user,c.oid,'SELECT WITH GRANT OPTION') AS can_delegate_read "+
      "FROM pg_catalog.pg_class AS c "+
      "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace "+
      "JOIN pg_catalog.pg_attribute AS a ON a.attrelid=c.oid "+
      "WHERE c.oid=ANY(ARRAY["+
      tables.map(t=>"'"+t+"'::regclass").join(',')+
      "]::oid[]) AND c.relkind IN ('r','p') AND a.attnum>0 AND NOT a.attisdropped "+
      "ORDER BY n.nspname,c.relname,a.attnum"
    );
  }catch{deny();}
  if(membership.rowCount!==1||membership.rows[0].unexpected_member||
     membership.rows[0].authority_schema_create)deny();
  const seen=new Map(tables.map(t=>[t,new Set()]));
  if(rows.rowCount<tables.length)deny();
  for(const row of rows.rows){
    if(!seen.has(row.relation)||typeof row.column_name!=='string')deny();
    seen.get(row.relation).add(row.column_name);
    const policy=allowed[row.relation]||{};
    const inserts=new Set(policy.insert||[]);
    const updates=new Set(policy.update||[]);
    if(row.tab_insert||row.tab_update||row.tab_delete||
       row.tab_truncate||row.tab_trigger||row.tab_references||
       row.can_delegate_read||Boolean(row.col_insert)!==inserts.has(row.column_name)||
       Boolean(row.col_update)!==updates.has(row.column_name))deny();
  }
  for(const table of tables){
    const cols=seen.get(table);
    if(cols.size===0)deny();
    for(const name of allowed[table]?.insert||[]){if(!cols.has(name))deny();}
    for(const name of allowed[table]?.update||[]){if(!cols.has(name))deny();}
  }
  return Object.freeze({exact:true,role,tableCount:tables.length});
}

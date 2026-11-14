'use strict';

/**
 * Provider-managed canonical identity and consent authority. Never trust
 * mutable Pod RDF to decide whether a repository grant remains active.
 * The supplied pool must connect with a PG reader+revoker LOGIN distinct
 * from the general Fuseki, LDP and migration-owner credentials.
 */
const { safeIri, safeEpoch } = require('../candidates/atproto-signed-repo-proof/pod-consent-fence.cjs');
const SCHEMA = 'paper_atproto_authority';
const MAX_EPOCH = 9223372036854775807n;
function refused(code) {
  const error=new Error('Protected ATProto authority unavailable');
  error.code=code;
  throw error;
}
function canonicalHttps(value) {
  try {
    safeIri(value,{httpsOnly:true});
    const u = new URL(value);
    if (u.search || u.hash || u.username || u.password || u.href !== value) throw Error();
    return value;
  } catch { refused('ATPROTO_PG_AUTHORITY_INPUT'); }
}
function revision(value) {
  try { safeEpoch(String(value)); }
  catch { refused('ATPROTO_PG_AUTHORITY_EPOCH'); }
  return String(value);
}
function createCanonicalAtprotoPgAuthority({pool}={}) {
  if(!pool?.query) refused('ATPROTO_PG_AUTHORITY_POOL');
  return Object.freeze({
    async getIdentity({owner}) {
      canonicalHttps(owner);
      const r=await pool.query(
        'SELECT owner_webid,did,state,managed,revision::text AS revision '+
        'FROM '+SCHEMA+'.identities WHERE owner_webid=$1 LIMIT 2',[owner]);
      if(r.rowCount===0)return null;
      if(r.rowCount!==1 || r.rows[0].owner_webid!==owner ||
        r.rows[0].managed!==true || !['active','blocked'].includes(r.rows[0].state)) {
        refused('ATPROTO_PG_AUTHORITY_AMBIGUOUS');
      }
      revision(r.rows[0].revision);
      return Object.freeze({
        owner:r.rows[0].owner_webid,did:r.rows[0].did,
        state:r.rows[0].state,revision:r.rows[0].revision
      });
    },
    async getConsent({owner,app}) {
      canonicalHttps(owner);canonicalHttps(app);
      const r=await pool.query(
        'SELECT c.owner_webid,c.app_uri,c.grant_uri,c.state, '+
        'c.revision::text AS revision, i.did,i.state AS identity_state '+
        'FROM '+SCHEMA+'.consents AS c JOIN '+SCHEMA+'.identities AS i '+
        'ON i.owner_webid=c.owner_webid '+
        'WHERE c.owner_webid=$1 AND c.app_uri=$2 LIMIT 2',[owner,app]);
      if(r.rowCount===0)return null;
      if(r.rowCount!==1 || r.rows[0].owner_webid!==owner ||
        r.rows[0].app_uri!==app || r.rows[0].identity_state!=='active' ||
        !['active','blocked'].includes(r.rows[0].state)) {
        refused('ATPROTO_PG_AUTHORITY_AMBIGUOUS');
      }
      canonicalHttps(r.rows[0].grant_uri);revision(r.rows[0].revision);
      return Object.freeze({
        owner,app,grantUri:r.rows[0].grant_uri,
        state:r.rows[0].state,revision:r.rows[0].revision,
        did:r.rows[0].did
      });
    },
    async verifyActiveGrant({owner,app,grantUri,did,consentRevision}) {
      canonicalHttps(owner);canonicalHttps(app);canonicalHttps(grantUri);
      if (typeof did !== 'string' || !/^did:plc:[a-z2-7]{24}$/u.test(did)) {
        refused('ATPROTO_PG_PERMISSION_SCOPE_INVALID');
      }
      const expected = revision(consentRevision);
      // One indexed point lookup, no pod scan or mutable RDF permission
      // fallback. An active permission requires BOTH canonical PG records.
      const result = await pool.query(
        'SELECT i.did,i.state AS identity_state,c.state AS consent_state, ' +
        'c.grant_uri,c.revision::text AS consent_revision FROM '+SCHEMA+'.consents c ' +
        'JOIN '+SCHEMA+'.identities i ON i.owner_webid=c.owner_webid ' +
        'WHERE c.owner_webid=$1 AND c.app_uri=$2 LIMIT 2',
        [owner,app]
      );
      if (result.rowCount !== 1 || result.rows[0]?.did !== did ||
          result.rows[0]?.identity_state !== 'active' ||
          result.rows[0]?.consent_state !== 'active' ||
          result.rows[0]?.grant_uri !== grantUri ||
          result.rows[0]?.consent_revision !== expected) {
        refused('ATPROTO_PG_PERMISSION_DENIED');
      }
      return true;
    },
    async revoke({owner,app,grantUri,expectedRevision}) {
      canonicalHttps(owner);canonicalHttps(app);canonicalHttps(grantUri);
      const before=revision(expectedRevision);
      if(BigInt(before)>=MAX_EPOCH)refused('ATPROTO_PG_AUTHORITY_EPOCH_EXHAUSTED');
      const r=await pool.query(
        'SELECT new_revision::text AS revision,new_state AS state FROM '+
        SCHEMA+'.block_consent($1::text,$2::text,$3::text,$4::bigint)',
        [owner,app,grantUri,before]);
      if(r.rowCount!==1 || r.rows[0].state!=='blocked' ||
        BigInt(r.rows[0].revision)!==BigInt(before)+1n) {
        refused('ATPROTO_PG_AUTHORITY_STALE');
      }
      return Object.freeze({state:'blocked',revision:r.rows[0].revision});
    }
  });
}

/**
 * Required startup permission proof, checked by PostgreSQL, not an
 * application role-name claim. A deployment accidentally passing the DB
 * administrator or migration-importer login is rejected before any SAI
 * operation is permitted.
 */
async function assertRestrictedPgAuthorityLogin(pool) {
  if (!pool?.query) refused('ATPROTO_PG_AUTHORITY_POOL');
  let result;
  try {
    result = await pool.query(
    'SELECT r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolreplication,' +
    'r.rolbypassrls,r.rolcanlogin, ' +
    // A NOINHERIT member can still SET ROLE to an importer or schema
    // owner. Effective has_table_privilege alone is NOT sufficient.
    "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer_member, " +
    "pg_catalog.pg_has_role(current_user,(SELECT nspowner FROM pg_catalog.pg_namespace WHERE nspname='paper_atproto_authority'),'MEMBER') AS owner_member, " +
    "pg_catalog.has_schema_privilege(current_user,'paper_atproto_authority','CREATE') AS schema_create, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.identities','SELECT') AS identity_read, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','SELECT') AS consent_read, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.identities','INSERT') AS identity_insert, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.identities','UPDATE') AS identity_update, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.identities','DELETE') AS identity_delete, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.identities','TRUNCATE') AS identity_truncate, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','INSERT') AS consent_insert, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','UPDATE') AS consent_update, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','DELETE') AS consent_delete, " +
    "pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','TRUNCATE') AS consent_truncate, " +
    "pg_catalog.has_function_privilege(current_user,'paper_atproto_authority.block_consent(text,text,text,bigint)','EXECUTE') AS revoke_execute " +
    'FROM pg_catalog.pg_roles r WHERE r.rolname=current_user'
    );
  } catch {
    // Some PostgreSQL privilege introspection calls themselves raise
    // SQLSTATE 42501 for a generic login without USAGE on this schema.
    // Treat that as a privilege refusal, not a raw database exception.
    refused('ATPROTO_PG_AUTHORITY_PRIVILEGES_UNSAFE');
  }
  const row = result.rows?.[0];
  const blocked = ['rolsuper','rolcreatedb','rolcreaterole','rolreplication',
    'rolbypassrls','schema_create','importer_member','owner_member',
    'identity_insert','identity_update',
    'identity_delete','identity_truncate','consent_insert',
    'consent_update','consent_delete','consent_truncate'];
  if(result.rowCount!==1 || !row || row.rolcanlogin!==true ||
      row.identity_read!==true || row.consent_read!==true ||
      row.revoke_execute!==true || blocked.some(key=>row[key]!==false)) {
    refused('ATPROTO_PG_AUTHORITY_PRIVILEGES_UNSAFE');
  }
  return true;
}

// One bounded pool per provider process, not per Pod or service call.
// This is NOT a public Moleculer action. Owner authentication is enforced
// by beforeSaiMutation before calling into this private adapter.
let singleton;
let initializing = null;
let closing = false;
async function getProviderAtprotoPgAuthority() {
  if (process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED !== 'true') {
    refused('ATPROTO_PG_AUTHORITY_NOT_ENABLED');
  }
  const disposable = process.env.NODE_ENV === 'test' &&
    process.env.APODS_ATPROTO_TEST_STORAGE_DISPOSABLE === 'confirmed';
  if (!disposable) refused('ATPROTO_PG_AUTHORITY_NOT_RELEASED');
  if (closing) refused('ATPROTO_PG_AUTHORITY_STOPPING');
  if (singleton) return singleton.authority;
  // Single-flight initialization: concurrent first SAI calls must not each
  // create a PostgreSQL pool and leak the losing connections.
  if (!initializing) {
    initializing = (async () => {
      const dsn = process.env.APODS_ATPROTO_AUTHORITY_PG_URL;
      if (!dsn) refused('ATPROTO_PG_AUTHORITY_DSN_MISSING');
      // Only exact disposable loopback PG18 is permitted in unreleased
      // mode. Production connection TLS and certificate pins require a
      // separate reviewed release before accepting an external DB host.
      let uri;
      try { uri = new URL(dsn); }
      catch { refused('ATPROTO_PG_AUTHORITY_DSN_UNTRUSTED'); }
      if (!['postgres:','postgresql:'].includes(uri.protocol) ||
          uri.hostname !== '127.0.0.1' || uri.port !== '5548' ||
          uri.pathname !== '/atproto_signed_repo_proof_test' ||
          !uri.username || !uri.password || uri.hash) {
        refused('ATPROTO_PG_AUTHORITY_DSN_UNTRUSTED');
      }
      const { Pool } = require('pg');
      const pool = new Pool({
        connectionString: dsn, max: 2,
        connectionTimeoutMillis: 3000, idleTimeoutMillis: 10000,
        query_timeout: 5000, allowExitOnIdle: true
      });
      try {
        await assertRestrictedPgAuthorityLogin(pool);
        const authority = createCanonicalAtprotoPgAuthority({ pool });
        singleton = { pool, authority };
        return authority;
      } catch {
        await pool.end().catch(() => {});
        refused('ATPROTO_PG_AUTHORITY_UNAVAILABLE');
      }
    })().finally(() => { initializing = null; });
  }
  return initializing;
}
async function closeProviderAtprotoPgAuthority() {
  if (closing) return;
  closing = true;
  try {
    const pending = initializing;
    if (pending) await pending.catch(() => {});
    const current = singleton;
    singleton = null;
    if (current) await current.pool.end();
  } finally {
    closing = false;
  }
}
module.exports={
  createCanonicalAtprotoPgAuthority,
  assertRestrictedPgAuthorityLogin,
  getProviderAtprotoPgAuthority,closeProviderAtprotoPgAuthority
};

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
      const { Pool } = require('pg');
      const pool = new Pool({
        connectionString: dsn, max: 2,
        connectionTimeoutMillis: 3000, idleTimeoutMillis: 10000,
        query_timeout: 5000, allowExitOnIdle: true
      });
      try {
        await pool.query('SELECT 1');
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
  getProviderAtprotoPgAuthority,closeProviderAtprotoPgAuthority
};

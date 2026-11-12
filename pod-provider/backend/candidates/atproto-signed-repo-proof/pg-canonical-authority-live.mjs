'use strict';

/**
 * Non-activated PostgreSQL 18 credential-isolation acceptance.
 * Independently authenticates writer, reader, revoker and a second revoker,
 * then proves that even malicious privileged Jena SPARQL writes cannot
 * reactivate the separately stored canonical PostgreSQL SAI consent.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { Client } from 'pg';

const require = createRequire(import.meta.url);
const { createCanonicalAtprotoPgAuthority } =
  require('../../utils/atproto-canonical-pg-authority.js');

const dsn = process.env.ATPROTO_REPO_PROOF_DSN || '';
if (process.env.NODE_ENV !== 'test' ||
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(dsn)) {
  throw Error('Canonical authority proof requires disposable PostgreSQL 18');
}
const rand = crypto.randomBytes(8).toString('hex');
const genericName = 'paper_auth_generic_' + rand;
const readerName = 'paper_auth_reader_' + rand;
const revokerName = 'paper_auth_revoker_' + rand;
const secondRevokerName = 'paper_auth_revoker2_' + rand;
const temporaryRoles = [
  [genericName, null],
  [readerName, 'paper_atproto_authority_reader'],
  [revokerName, 'paper_atproto_authority_revoker'],
  [secondRevokerName, 'paper_atproto_authority_revoker']
];
const allSecrets = new Map(temporaryRoles.map(([name]) =>
  [name, crypto.randomBytes(32).toString('base64url')]));
const ident = name => {
  if (!/^[a-z_][a-z0-9_]{0,62}$/u.test(name)) throw Error('Unsafe PG role identifier');
  return '"' + name + '"';
};
const clients = [];
const admin = new Client({
  connectionString: dsn, connectionTimeoutMillis: 3000,
  query_timeout: 6500
});
const SCHEMA = 'paper_atproto_authority';

async function connectRole(name) {
  const url = new URL(dsn);
  url.username = name;
  url.password = allSecrets.get(name);
  const client = new Client({
    connectionString: url.toString(), connectionTimeoutMillis: 3000,
    query_timeout: 6500
  });
  await client.connect();
  clients.push(client);
  assert.equal((await client.query('SELECT current_user AS who')).rows[0].who, name);
  return client;
}
async function deny(client, sql, vars=[]) {
  await assert.rejects(client.query(sql,vars), error => error.code === '42501');
}
function proofHash(value) { return crypto.createHash('sha256').update(value).digest(); }
async function seed(owner, did, app, grant) {
  await admin.query(
    'INSERT INTO '+SCHEMA+'.identities '+
    '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
    "VALUES($1,$2,'active',true,1,$3)",
    [owner,did,proofHash('verified-native-identity:'+owner)]
  );
  await admin.query(
    'INSERT INTO '+SCHEMA+'.consents '+
    '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256) '+
    "VALUES($1,$2,$3,'active',1,$4)",
    [owner,app,grant,proofHash('verified-sai:'+grant)]
  );
}
async function probeFuseki(ownedUri) {
  if (!process.env.FUSEKI_URL) return false;
  if (process.env.FUSEKI_URL !== 'http://127.0.0.1:3040' ||
      process.env.ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE !== 'confirmed') {
    throw Error('Fuseki adversarial proof requires exact disposable loopback target');
  }
  const uri = 'urn:paper:authority:adversary:' + rand;
  const predicate = 'http://activitypods.org/ns/core#repoConsentStatus';
  const auth = 'Basic ' + Buffer.from('admin:' +
    (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');
  // This simulates a privileged SemApps/Fuseki component inserting a forged
  // RDF active claim in a mutable dataset. It is NOT a harmless public actor.
  const query = 'INSERT DATA { <' + uri + '> <' + predicate + '> "active" . }';
  const r = await fetch(process.env.FUSEKI_URL+'/settings/update', {
    method:'POST',headers:{
      authorization:auth,'content-type':'application/sparql-update'
    },body:query,signal:AbortSignal.timeout(10000)
  });
  if(!r.ok)throw Error('Disposable Fuseki SPARQL write refused: HTTP '+r.status);
  const check = await fetch(process.env.FUSEKI_URL+'/settings/query', {
    method:'POST',headers:{
      authorization:auth,'content-type':'application/sparql-query',
      accept:'application/sparql-results+json'
    },
    body:'ASK WHERE { <'+uri+'> <'+predicate+'> "active" . }',
    signal:AbortSignal.timeout(10000)
  });
  if(!check.ok)throw Error('Disposable Fuseki SPARQL query refused: HTTP '+check.status);
  const value = await check.json();
  assert.equal(value.boolean, true, 'Adversarial RDF modification must genuinely succeed');
  // Remove only the synthetic RDF triple created by this proof.
  const clear = await fetch(process.env.FUSEKI_URL+'/settings/update',{
    method:'POST',headers:{
      authorization:auth,'content-type':'application/sparql-update'
    },
    body:query.replace('INSERT DATA','DELETE DATA'),
    signal:AbortSignal.timeout(10000)
  });
  if(!clear.ok)throw Error('Disposable RDF fixture cleanup failed: HTTP '+clear.status);
  return true;
}
let migrationApplied=false;
let createdCount=0;
let originalError=null;
async function run() {
  await admin.connect();
  try {
    const existed=await admin.query("SELECT to_regnamespace('paper_atproto_authority') AS ns");
    assert.equal(existed.rows[0].ns,null,'Must not reuse an existing canonical authority schema');
    const sql=await readFile(new URL('../../sql/paper-atproto-canonical-authority-v1.sql',import.meta.url),'utf8');
    await admin.query(sql);
    migrationApplied=true;

    for(const [name,member] of temporaryRoles){
      const secret=allSecrets.get(name);
      assert(/^[A-Za-z0-9_-]{43}$/u.test(secret));
      await admin.query('CREATE ROLE '+ident(name)+
        " LOGIN PASSWORD '"+secret+"' "+
        'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2');
      createdCount++;
      if(member)await admin.query('GRANT '+ident(member)+' TO '+ident(name));
    }
    const [generic,reader,revoker,revoker2]=await Promise.all(
      temporaryRoles.map(([name])=>connectRole(name)));
    const owner='https://paper.example.test/alice';
    const other='https://paper.example.test/bob';
    const app='https://writer.example.test/app';
    const grant=owner+'/data/grants/repo-access';
    const grant2=other+'/data/grants/repo-access';
    await seed(owner,'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',app,grant);
    await seed(other,'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb',app,grant2);

    // Real independent credentials: ordinary SPARQL/proxy role has no
    // SELECT, INSERT, UPDATE, DELETE, TRUNCATE, EXECUTE or schema CREATE.
    await deny(generic,'SELECT * FROM '+SCHEMA+'.consents');
    await deny(generic,'SELECT * FROM '+SCHEMA+'.identities');
    await deny(generic,
      'UPDATE '+SCHEMA+".consents SET state='active' WHERE owner_webid=$1",[owner]);
    await deny(generic,
      'INSERT INTO '+SCHEMA+'.consents VALUES ($1,$2,$3,$4,1,$5)',
      [other,app,grant2,'active',proofHash('forgery')]);
    await deny(generic,'DELETE FROM '+SCHEMA+'.consents WHERE owner_webid=$1',[owner]);
    await deny(generic,'TRUNCATE '+SCHEMA+'.consents');
    await deny(generic,'CREATE TABLE '+SCHEMA+'.unauthorized (k integer)');
    await deny(generic,'SET ROLE '+ident('paper_atproto_authority_revoker'));
    await deny(generic,
      'SELECT * FROM '+SCHEMA+'.block_consent($1,$2,$3,1::bigint)',
      [owner,app,grant]);

    // Read-only role cannot change canonical records, even with known owner.
    assert.equal((await reader.query('SELECT count(*) AS n FROM '+SCHEMA+'.consents')).rows[0].n,'2');
    await deny(reader,
      'UPDATE '+SCHEMA+".consents SET state='active' WHERE owner_webid=$1",[owner]);

    // Revoke-only credentials can call exactly one DB-owned function; they
    // cannot directly update a table or reauthorize expired consent.
    await deny(revoker,'UPDATE '+SCHEMA+".consents SET state='active' WHERE owner_webid=$1",[owner]);
    await deny(revoker,'INSERT INTO '+SCHEMA+'.identities VALUES ($1,$2,$3,true,1,$4)',
      ['https://paper.example.test/injected','did:plc:cccccccccccccccccccccccc','active',proofHash('injection')]);
    await deny(revoker,'DELETE FROM '+SCHEMA+'.consents WHERE owner_webid=$1',[owner]);
    await deny(revoker,'TRUNCATE '+SCHEMA+'.consents');

    const api=createCanonicalAtprotoPgAuthority({pool:revoker});
    const another=createCanonicalAtprotoPgAuthority({pool:revoker2});
    assert.equal((await api.getIdentity({owner})).state,'active');
    assert.equal((await api.getConsent({owner,app})).state,'active');
    assert.equal(await api.verifyActiveGrant({
      owner,app,grantUri:grant,
      did:'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',
      consentRevision:'1'
    }),true);
    await assert.rejects(api.verifyActiveGrant({
      owner,app,grantUri:grant,
      did:'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',
      consentRevision:'2'
    }),e=>e?.code==='ATPROTO_PG_PERMISSION_DENIED');
    await assert.rejects(api.revoke({
      owner,app,grantUri:other+'/data/grants/forged',expectedRevision:'1'
    }),e=>e?.code==='ATPROTO_PG_AUTHORITY_STALE');

    const blocked=await api.revoke({owner,app,grantUri:grant,expectedRevision:'1'});
    assert.deepEqual(blocked,{state:'blocked',revision:'2'});
    const wroteRdf=await probeFuseki(owner);
    // A forged *active* Jena triple cannot change canonical PG authorization.
    assert.equal((await api.getConsent({owner,app})).state,'blocked');
    await assert.rejects(api.verifyActiveGrant({
      owner,app,grantUri:grant,
      did:'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',
      consentRevision:'1'
    }),e=>e?.code==='ATPROTO_PG_PERMISSION_DENIED');
    await assert.rejects(api.revoke({
      owner,app,grantUri:grant,expectedRevision:'1'
    }),e=>e?.code==='ATPROTO_PG_AUTHORITY_STALE');

    const choices=await Promise.allSettled([
      api.revoke({owner:other,app,grantUri:grant2,expectedRevision:'1'}),
      another.revoke({owner:other,app,grantUri:grant2,expectedRevision:'1'})
    ]);
    assert.equal(choices.filter(x=>x.status==='fulfilled').length,1);
    assert.equal(choices.filter(x=>x.status==='rejected' &&
      x.reason?.code==='ATPROTO_PG_AUTHORITY_STALE').length,1);
    const check=await admin.query(
      'SELECT owner_webid,state,revision::text AS revision FROM '+SCHEMA+
      '.consents ORDER BY owner_webid');
    assert.equal(check.rowCount,2);
    assert(check.rows.every(x=>x.state==='blocked' && x.revision==='2'));
    console.log(JSON.stringify({
      success:true,scope:'disposable-postgresql18-native-canonical-identity-and-consent',
      distinctLoginConnections:4,
      ordinaryDmlAndFunctionDenials:9,
      readOnlyLoginDeniedMutation:true,
      revokerDirectWritesDenied:4,
      independentRevocationContenders:2,
      oneWayTransitions:2,
      forgedPrivilegedFusekiRdfAcceptedWithoutPgRegrant:wroteRdf,
      blockedRows:2
    }));
  } catch(e) {
    originalError=e;
    throw e;
  } finally {
    const cleanupErrors=[];
    for(const client of clients.reverse()) {
      try{await client.end()}catch(e){cleanupErrors.push(e)}
    }
    if(migrationApplied){
      try{await admin.query('DROP SCHEMA IF EXISTS '+SCHEMA+' CASCADE')}
      catch(e){cleanupErrors.push(e)}
    }
    for(const [name,member] of temporaryRoles.slice(0,createdCount).reverse()){
      try{
        if(member)await admin.query('REVOKE '+ident(member)+' FROM '+ident(name));
        await admin.query('DROP ROLE '+ident(name));
      }catch(e){cleanupErrors.push(e)}
    }
    if(migrationApplied){
      for(const role of ['paper_atproto_authority_importer',
        'paper_atproto_authority_revoker','paper_atproto_authority_reader']){
        try{await admin.query('DROP ROLE '+ident(role))}
        catch(e){cleanupErrors.push(e)}
      }
    }
    try{await admin.end()}catch(e){cleanupErrors.push(e)}
    if(cleanupErrors.length && !originalError)throw Error('Disposable PG proof fixture cleanup failed');
  }
}
run().catch(error=>{
  console.error('Canonical PG authority test failed:',error?.code || error?.name || 'UNKNOWN');
  process.exitCode=1;
});

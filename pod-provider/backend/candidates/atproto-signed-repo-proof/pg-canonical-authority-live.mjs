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
import vm from 'node:vm';
import { Client } from 'pg';

const require = createRequire(import.meta.url);
const { createCanonicalAtprotoPgAuthority, assertRestrictedPgAuthorityLogin } =
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
const escalatableName = 'paper_auth_escalatable_' + rand;
const temporaryRoles = [
  [genericName, null],
  [readerName, 'paper_atproto_authority_reader'],
  [revokerName, 'paper_atproto_authority_revoker'],
  [secondRevokerName, 'paper_atproto_authority_revoker'],
  [escalatableName, 'paper_atproto_authority_revoker']
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
async function probeFuseki({ owner, app, grant, did, pgAuthority }) {
  if (!process.env.FUSEKI_URL) return false;
  if (process.env.FUSEKI_URL !== 'http://127.0.0.1:3040' ||
      process.env.ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE !== 'confirmed') {
    throw Error('Fuseki adversarial proof requires exact disposable loopback target');
  }
  const { consentSubject, readConsentQuery, parseConsentRows } =
    require('./pod-consent-fence.cjs');
  // The existing per-user Fuseki proof already created and owns the 'alice'
  // dataset. Forge a COMPLETE grant at the ACTUAL canonical subject within
  // that same dataset; a generic settings triple would not match SAI.
  const subject = consentSubject(owner, app);
  const auth = 'Basic ' + Buffer.from('admin:' +
    (process.env.FUSEKI_PASSWORD || 'admin')).toString('base64');
  const prefix = 'PREFIX apods: <http://activitypods.org/ns/core#> ';
  const triples = '<' + subject + '> apods:repoConsentStatus "active" ; ' +
    'apods:repoConsentRevision "1"^^<http://www.w3.org/2001/XMLSchema#integer> ; ' +
    'apods:repoConsentGrant <' + grant + '> . ';
  async function sparql(dataset, kind, statement) {
    if (!['settings','alice'].includes(dataset) ||
        !['update','query'].includes(kind)) throw Error('Untrusted Fuseki target');
    const response = await fetch(process.env.FUSEKI_URL+'/'+dataset+'/'+kind, {
      method:'POST',headers:{
        authorization:auth,
        'content-type':kind==='update'?'application/sparql-update':'application/sparql-query',
        accept:'application/sparql-results+json'
      },body:statement,signal:AbortSignal.timeout(10000)
    });
    if (!response.ok) throw Error('Disposable Fuseki '+kind+' failed: HTTP '+response.status);
    return kind==='query' ? (await response.json()).results.bindings : null;
  }
  // Keep the forged grant in place while the real provider SAI hook consults
  // canonical PG. Prove the legacy RDF parser WOULD accept this exact grant.
  await sparql('alice','update',prefix+'INSERT DATA { '+triples+' }');
  let forgedReadWouldAuthorize = false;
  let hookDeniedRdfFallback = false;
  try {
    const rows = await sparql('alice','query',readConsentQuery({subjectUri:subject}));
    const rdf = parseConsentRows(rows,{grantUri:grant});
    assert.equal(rdf.status,'active');
    assert.equal(rdf.revision,'1');
    forgedReadWouldAuthorize = true;
    await assert.rejects(pgAuthority.verifyActiveGrant({
      owner,app,grantUri:grant,did,consentRevision:'1'
    }),e=>e?.code==='ATPROTO_PG_PERMISSION_DENIED');

    // Execute the ACTUAL native SAI fence source with only a fake Moleculer
    // wiring layer. The data reads use real Fuseki and the authorization
    // adapter uses the real, restricted PostgreSQL login. Neither mock is
    // permitted to override its returned PG permission state.
    const file = new URL('../../services/utils/atproto-sai-native-fence.js',import.meta.url);
    const source = await readFile(file,'utf8');
    const m={exports:{}};
    class MoleculerError extends Error {
      constructor(message,status,type) {
        super(message);this.code=status;this.type=type;
      }
    }
    vm.runInNewContext(source,{
      module:m,exports:m.exports,process,Buffer,URL,BigInt,Set,
      require(name) {
        if(name==='moleculer') return {Errors:{MoleculerError}};
        if(name==='../../utils/atproto-canonical-pg-authority') {
          return {getProviderAtprotoPgAuthority: async()=>pgAuthority};
        }
        if(name==='../../candidates/atproto-signed-repo-proof/pod-consent-fence.cjs') {
          return require('./pod-consent-fence.cjs');
        }
        if(name==='../../candidates/atproto-signed-repo-proof/pod-account-lookup.cjs') {
          return require('./pod-account-lookup.cjs');
        }
        throw Error('Unexpected provider SAI dependency: '+name);
      }
    },{filename:'atproto-sai-native-fence.js',timeout:3000});
    const flags=['APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED',
      'APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED','APODS_ATPROTO_SAI_FENCED_APPS'];
    const old=Object.fromEntries(flags.map(key=>[key,process.env[key]]));
    try {
      process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED='true';
      process.env.APODS_ATPROTO_CANONICAL_PG_AUTHORITY_ENABLED='true';
      process.env.APODS_ATPROTO_SAI_FENCED_APPS=app;
      const observed=[];
      const ctx={
        meta:{webId:owner},
        params:{containerUri:owner+'/data/access-grants/'},
        async call(name,params) {
          observed.push(name);
          if(name==='access-grants.getContainerUri') return owner+'/data/access-grants/';
          if(name==='webacl.resource.hasRights') return {append:true,write:true};
          if(name==='triplestore.query') return sparql(params.dataset,'query',params.query);
          if(name==='triplestore.update') throw Error('No RDF consent fallback permitted');
          throw Error('Unexpected SAI action '+name);
        }
      };
      const grantResource={'interop:grantedBy':owner,'interop:grantee':app};
      const result=await m.exports.beforeSaiMutation(ctx,'access-grants',grantResource,'post');
      assert.equal(result.checked,true);
      assert.equal(result.blocked,true);
      assert.equal(observed.includes('triplestore.update'),false);
      assert.equal(observed.some(name=>name==='triplestore.query'),true,
        'Owner account-location lookup should still run');
      // RDF forged active grant remains legible; PG blocked consent wins.
      assert.equal((await sparql('alice','query',
        readConsentQuery({subjectUri:subject}))).length,1);
      hookDeniedRdfFallback=true;
    } finally {
      for(const [key,value] of Object.entries(old)) {
        if(value===undefined) delete process.env[key];
        else process.env[key]=value;
      }
    }
  } finally {
    await sparql('alice','update',prefix+'DELETE DATA { '+triples+' }');
    assert.equal((await sparql('alice','query',
      readConsentQuery({subjectUri:subject}))).length,0,
      'All forged RDF triples must be cleaned up');
  }
  assert.equal(forgedReadWouldAuthorize,true);
  assert.equal(hookDeniedRdfFallback,true);
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
      if(name===escalatableName) {
        // PG18 role membership can permit SET ROLE without INHERIT.
        // This login looks like a restricted revoker until it changes role.
        await admin.query('GRANT paper_atproto_authority_importer TO '+
          ident(name)+' WITH INHERIT FALSE, SET TRUE');
      }
    }
    const [generic,reader,revoker,revoker2,escalatable]=await Promise.all(
      temporaryRoles.map(([name])=>connectRole(name)));
    assert.equal(await assertRestrictedPgAuthorityLogin(revoker),true);
    assert.equal(await assertRestrictedPgAuthorityLogin(revoker2),true);
    const escalationCheck=await escalatable.query(
      "SELECT pg_catalog.has_table_privilege(current_user,'paper_atproto_authority.consents','INSERT') AS inherited_insert, "+
      "pg_catalog.pg_has_role(current_user,'paper_atproto_authority_importer','MEMBER') AS importer_member"
    );
    assert.equal(escalationCheck.rows[0].inherited_insert,false,
      'Unsafe import membership must not already be inherited');
    assert.equal(escalationCheck.rows[0].importer_member,true,
      'The login must be able to switch roles in this negative proof');
    await assert.rejects(assertRestrictedPgAuthorityLogin(escalatable),
      e=>e?.code==='ATPROTO_PG_AUTHORITY_PRIVILEGES_UNSAFE');
    await assert.rejects(assertRestrictedPgAuthorityLogin(admin),
      e=>e?.code==='ATPROTO_PG_AUTHORITY_PRIVILEGES_UNSAFE');
    await assert.rejects(assertRestrictedPgAuthorityLogin(generic),
      e=>e?.code==='ATPROTO_PG_AUTHORITY_PRIVILEGES_UNSAFE');
    const owner='https://paper.example.org/alice';
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
    const wroteRdf=await probeFuseki({owner,app,grant,did:'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',pgAuthority:api});
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
      unsafeNonInheritedImporterMembershipDenied:true,
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
        if(name===escalatableName) {
          await admin.query('REVOKE paper_atproto_authority_importer FROM '+ident(name));
        }
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

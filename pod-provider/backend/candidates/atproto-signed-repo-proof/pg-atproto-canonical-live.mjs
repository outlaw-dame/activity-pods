'use strict';

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import {Client} from 'pg';
import authorityModule from '../../utils/atproto-canonical-pg-authority.js';
const {createCanonicalAtprotoPgAuthority}=authorityModule;

// Never accept a non-disposable PG host, user, database or Fuseki origin.
const dsn=process.env.ATPROTO_REPO_PROOF_DSN||'';
if (process.env.NODE_ENV!=='test' ||
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed' ||
    !/^postgres(?:ql)?:\/\/paper_probe:probe_local_only@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u.test(dsn)) {
  throw Error('Canonical PG authority proof requires disposable local PG18');
}
const fusekiHost=process.env.ATPROTO_FUSEKI_URL;
if (fusekiHost && (fusekiHost!=='http://127.0.0.1:3040' ||
                   process.env.ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE!=='confirmed')) {
  throw Error('Canonical RDF tamper proof requires disposable loopback Fuseki');
}
const random=crypto.randomBytes(8).toString('hex');
const roles={
  ordinary:'paper_sparql_'+random,revoker:'paper_revoker_'+random,
  revoker2:'paper_revoker2_'+random,importer:'paper_importer_'+random
};
const secret=crypto.randomBytes(24).toString('base64url');
const q=name=>{
  if(!/^[a-z_][a-z0-9_]{0,62}$/u.test(name))throw Error('Untrusted role identifier');
  return '"'+name+'"';
};
const root=new URL('../../sql/paper-atproto-canonical-authority-v1.sql',import.meta.url);
const admin=new Client({connectionString:dsn,connectionTimeoutMillis:3000,query_timeout:5000});
const clients=[];
const created=[];
function roleClient(name){
  const url=new URL(dsn);url.username=name;url.password=secret;
  const c=new Client({connectionString:url.toString(),connectionTimeoutMillis:3000,query_timeout:5000});
  clients.push(c);return c;
}
async function denial(c,sql,args=[]){
  await assert.rejects(c.query(sql,args),e=>e?.code==='42501');
}
const webid='https://paper.example.test/alice';
const app='https://paper.example.test/managed-app';
const grant=webid+'/data/access-grant/pg';
const did='did:plc:aaaaaaaaaaaaaaaaaaaaaaaa';
const evidence=crypto.createHash('sha256').update('verified-provider-claim-fixture').digest();
const revoked=crypto.createHash('sha256').update('verified-sai-grant-fixture').digest();
async function seed(c,owner=webid){
  await c.query(
    'INSERT INTO paper_atproto_authority.identities '+
    '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
    "VALUES ($1,$2,'active',true,1,$3)",
    [owner,owner===webid?did:'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb',evidence]);
  await c.query(
    'INSERT INTO paper_atproto_authority.consents '+
    '(owner_webid,app_uri,grant_uri,state,revision,grant_proof_sha256) '+
    "VALUES ($1,$2,$3,'active',1,$4)",
    [owner,app,owner===webid?grant:owner+'/data/access-grant/pg',revoked]);
}
async function tamperRdfAndVerifyBlocked(authority) {
  if (!fusekiHost) return false;
  const subject='urn:paper:pg-canonical:'+random;
  const update='INSERT DATA { <'+subject+'> '+
    '<http://activitypods.org/ns/core#repoConsentStatus> "active" . }';
  const auth='Basic '+Buffer.from('admin:'+(process.env.FUSEKI_PASSWORD||'admin')).toString('base64');
  const response=await fetch(fusekiHost+'/settings/update',{
    method:'POST',headers:{authorization:auth,'content-type':'application/sparql-update'},
    body:update,signal:AbortSignal.timeout(5000)
  });
  assert.equal(response.ok,true,'Privileged SPARQL fixture must be writable');
  const pg=await authority.getConsent({owner:webid,app});
  assert.equal(pg.state,'blocked',
    'SPARQL may forge RDF projection, but it cannot restore PG authorization');
  const ask=await fetch(fusekiHost+'/settings/query',{
    method:'POST',headers:{authorization:auth,
      'content-type':'application/sparql-query',
      accept:'application/sparql-results+json'},
    body:'ASK WHERE { <'+subject+'> <http://activitypods.org/ns/core#repoConsentStatus> "active" . }',
    signal:AbortSignal.timeout(5000)
  });
  assert.equal(ask.status,200);
  assert.equal((await ask.json()).boolean,true);
  await fetch(fusekiHost+'/settings/update',{
    method:'POST',headers:{authorization:auth,'content-type':'application/sparql-update'},
    body:'DELETE WHERE { <'+subject+'> ?p ?o . }',signal:AbortSignal.timeout(5000)
  });
  return true;
}
async function main(){
  await admin.connect();
  let started=false;
  try{
    const pre=await admin.query("SELECT to_regnamespace('paper_atproto_authority') AS ns");
    assert.equal(pre.rows[0].ns,null,'Never overwrite protected authority schema');
    await admin.query(await fs.readFile(root,'utf8'));
    started=true;
    for(const [kind,name] of Object.entries(roles)){
      await admin.query('CREATE ROLE '+q(name)+
        " LOGIN PASSWORD '"+secret+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT "+
        'NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2');
      created.push(name);
      // Explicitly INHERIT each named NOLOGIN role. NOINHERIT on the LOGIN
      // would otherwise deny unqualified SELECT/EXECUTE even after GRANT.
      const role=kind==='ordinary'?null:
        kind==='importer'?'paper_atproto_authority_importer':
          'paper_atproto_authority_revoker';
      if(role)await admin.query('GRANT '+q(role)+' TO '+q(name)+' WITH INHERIT TRUE');
      if(kind.startsWith('revoker'))await admin.query(
        'GRANT paper_atproto_authority_reader TO '+q(name)+' WITH INHERIT TRUE');
    }
    const ordinary=roleClient(roles.ordinary);
    const importer=roleClient(roles.importer);
    const rev=roleClient(roles.revoker);
    const rev2=roleClient(roles.revoker2);
    await Promise.all(clients.map(c=>c.connect()));
    await seed(importer);
    const other='https://paper.example.test/bob';
    await seed(importer,other);
    const authority=createCanonicalAtprotoPgAuthority({pool:rev});
    const a2=createCanonicalAtprotoPgAuthority({pool:rev2});
    assert.equal((await authority.getIdentity({owner:webid})).did,did);
    assert.equal((await authority.getConsent({owner:webid,app})).state,'active');
    const select='SELECT * FROM paper_atproto_authority.consents WHERE owner_webid=$1';
    const update="UPDATE paper_atproto_authority.consents SET state='active' WHERE owner_webid=$1";
    const call='SELECT * FROM paper_atproto_authority.block_consent($1,$2,$3,$4::bigint)';
    await denial(ordinary,select,[webid]);
    await denial(ordinary,update,[webid]);
    await denial(ordinary,call,[webid,app,grant,'1']);
    await denial(rev,update,[webid]);
    await denial(importer,update,[webid]);
    const blocked=await authority.revoke({owner:webid,app,grantUri:grant,expectedRevision:'1'});
    assert.deepEqual(blocked,{state:'blocked',revision:'2'});
    assert.equal((await authority.getConsent({owner:webid,app})).state,'blocked');
    await assert.rejects(authority.revoke({
      owner:webid,app,grantUri:grant,expectedRevision:'1'
    }),e=>e?.code==='ATPROTO_PG_AUTHORITY_STALE');
    await assert.rejects(authority.revoke({
      owner:webid,app,grantUri:webid+'/data/forged',expectedRevision:'1'
    }),e=>e?.code==='ATPROTO_PG_AUTHORITY_STALE');
    const secondGrant=other+'/data/access-grant/pg';
    const contenders=await Promise.allSettled([
      authority.revoke({owner:other,app,grantUri:secondGrant,expectedRevision:'1'}),
      a2.revoke({owner:other,app,grantUri:secondGrant,expectedRevision:'1'})
    ]);
    assert.equal(contenders.filter(x=>x.status==='fulfilled').length,1);
    assert.equal(contenders.filter(x=>x.status==='rejected'&&
      x.reason?.code==='ATPROTO_PG_AUTHORITY_STALE').length,1);
    const rdfTamperProof=await tamperRdfAndVerifyBlocked(authority);
    const states=await admin.query(
      'SELECT owner_webid,state,revision FROM paper_atproto_authority.consents');
    assert.equal(states.rowCount,2);
    assert(states.rows.every(r=>r.state==='blocked'&&r.revision==='2'));
    console.log(JSON.stringify({
      success:true,scope:'disposable-canonical-pg18-source-of-truth',
      independentLoginCredentials:4,
      prohibitedOrdinaryDml:true,prohibitedRevokerDirectDml:true,
      revokedRows:2,concurrentCasWinnerCount:1,
      privilegedFusekiRdfSpoofDidNotRegrant:rdfTamperProof,
      noProductionActivation:true
    }));
  }finally{
    for(const c of clients)await c.end().catch(()=>{});
    if(started)await admin.query('DROP SCHEMA IF EXISTS paper_atproto_authority CASCADE');
    for(const name of created.reverse())await admin.query('DROP ROLE '+q(name));
    // Migration creates named NOLOGIN roles in this isolated disposable DB.
    if(started)for(const name of [
      'paper_atproto_authority_importer','paper_atproto_authority_revoker',
      'paper_atproto_authority_reader'
    ])await admin.query('DROP ROLE IF EXISTS '+q(name));
    await admin.end();
  }
}
main().catch(error=>{
  console.error('Canonical PG proof failed:',error?.code||error?.name||'UNKNOWN');
  process.exitCode=1;
});

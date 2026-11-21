/** Nonactivated real-PG18 owner SAI consent activation and revocation proof.
 * These SQL tests do not fabricate native Jena readback approval: the attestor
 * credential must separately be wired to a real protected Jena reader.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {Client} from 'pg';
const require=createRequire(import.meta.url);
const {createCanonicalAtprotoPgAuthority,assertRestrictedPgAuthorityLogin}=
  require('../../utils/atproto-canonical-pg-authority.js');
const DSN='postgres://paper_probe:probe_local_only@127.0.0.1:5548/atproto_signed_repo_proof_test';
if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_REPO_PROOF_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_SAI_ACTIVATION_DISPOSABLE!=='confirmed'||
   process.env.ATPROTO_REPO_PROOF_DSN!==DSN)throw Error('Disposable PostgreSQL 18 only');
const schema='paper_atproto_authority';
const suffix=crypto.randomBytes(6).toString('hex');
const roles={issuer:'paper_atproto_consent_issuer',
  attestor:'paper_atproto_consent_attestor',
  attestor2:'paper_atproto_consent_attestor',
  revoker:'paper_atproto_authority_revoker',
  revoker2:'paper_atproto_authority_revoker',ordinary:null};
const logins=Object.fromEntries(Object.keys(roles).map(kind=>
  [kind,'paper_sai_activation_'+kind+'_'+suffix]));
const passwords=Object.fromEntries(Object.keys(roles).map(kind=>
  [kind,crypto.randomBytes(32).toString('hex')]));
const admin=new Client({connectionString:DSN,connectionTimeoutMillis:3000,query_timeout:6000});
const clients=[];const created=[];const errors=[];let schemaCreated=false,failed;
const identifier=v=>{assert.match(v,/^[a-z_][a-z0-9_]{0,62}$/u);return '"'+v+'"';};
const sha=v=>crypto.createHash('sha256').update(v).digest();
const sample=(letter,num)=>({owner:'https://paper.example.org/new-owner-'+num,
  did:'did:plc:'+letter.repeat(24),app:'https://app.paper.example.org/app',
  get grant(){return this.owner+'/data/access-grants/native-sai';},
  operation:crypto.randomUUID()});
const owners=[sample('a',1),sample('b',2),sample('c',3)];
async function login(kind){
  const url=new URL(DSN);url.username=logins[kind];url.password=passwords[kind];
  const client=new Client({connectionString:url.toString(),
    connectionTimeoutMillis:3000,query_timeout:6000});
  await client.connect();clients.push(client);
  assert.equal((await client.query('SELECT current_user AS who')).rows[0].who,logins[kind]);
  return client;
}
async function denied(client,sql,args=[]){
  await assert.rejects(client.query(sql,args),e=>e?.code==='42501');
}
async function invoke(client,kind,p){
  const name=kind==='begin'?'begin_owner_consent':'attest_owner_consent';
  const values=kind==='begin'?
    [p.owner,p.did,p.app,p.operation,p.digest]:
    [p.owner,p.did,p.app,p.operation,p.grant,p.digest];
  const sig=kind==='begin'?'$1,$2,$3,$4::uuid,$5::bytea':
    '$1,$2,$3,$4::uuid,$5,$6::bytea';
  const r=await client.query('SELECT '+schema+'.'+name+'('+sig+') AS ok',values);
  assert.equal(r.rowCount,1);return r.rows[0].ok;
}
async function read(owner){
  const r=await admin.query('SELECT state,revision::text AS revision,grant_uri,'+
   'grant_proof_sha256,activation_operation,activation_native_readback_at FROM '+
   schema+'.consents WHERE owner_webid=$1',[owner]);
  assert.equal(r.rowCount,1);return r.rows[0];
}
async function seed(p){
  await admin.query('INSERT INTO '+schema+'.identities '+
    '(owner_webid,did,state,managed,revision,source_proof_sha256) '+
    "VALUES($1,$2,'active',true,1,$3)",[p.owner,p.did,sha('managed-identity:'+p.owner)]);
}
async function run(){
  await admin.connect();
  try{
    const prior=await admin.query("SELECT to_regnamespace('paper_atproto_authority') AS ns");
    assert.equal(prior.rows[0].ns,null,'Never reuse canonical schema in tests');
    await admin.query(await readFile(new URL('../../sql/paper-atproto-canonical-authority-v1.sql',
      import.meta.url),'utf8'));schemaCreated=true;
    await admin.query(await readFile(new URL('../../sql/paper-atproto-canonical-authority-v2-owner-consent.sql',
      import.meta.url),'utf8'));
    for(const [kind,baseRole] of Object.entries(roles)){
      await admin.query('CREATE ROLE '+identifier(logins[kind])+
        " LOGIN PASSWORD '"+passwords[kind]+"' "+
        'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS');
      created.push(kind);
      if(baseRole)await admin.query('GRANT '+identifier(baseRole)+' TO '+
        identifier(logins[kind])+' WITH INHERIT TRUE,SET FALSE,ADMIN FALSE');
    }
    const [issuer,attestor,attestor2,revoker,revoker2,ordinary]=
      await Promise.all(Object.keys(roles).map(login));
    assert.equal(await assertRestrictedPgAuthorityLogin(revoker),true);
    assert.equal(await assertRestrictedPgAuthorityLogin(revoker2),true);
    for(const role of [issuer,attestor,attestor2,revoker,ordinary]){
      await denied(role,'UPDATE '+schema+".consents SET state='active'");
      await denied(role,'DELETE FROM '+schema+'.consents');
      await denied(role,'INSERT INTO '+schema+'.consents VALUES (DEFAULT)');
    }
    const first=owners[0];
    const begin={...first,digest:sha('verified-owner-approval:'+first.owner)};
    const attest={...first,digest:sha('independent-native-sai:'+first.grant)};
    await denied(ordinary,'SELECT '+schema+'.begin_owner_consent($1,$2,$3,$4::uuid,$5::bytea)',
      [begin.owner,begin.did,begin.app,begin.operation,begin.digest]);
    await denied(attestor,'SELECT '+schema+'.begin_owner_consent($1,$2,$3,$4::uuid,$5::bytea)',
      [begin.owner,begin.did,begin.app,begin.operation,begin.digest]);
    await denied(issuer,'SELECT '+schema+'.attest_owner_consent($1,$2,$3,$4::uuid,$5,$6::bytea)',
      [attest.owner,attest.did,attest.app,attest.operation,attest.grant,attest.digest]);
    await denied(ordinary,'SELECT '+schema+'.confirm_owner_consent($1,$2,$3,$4::uuid,$5,$6::bytea)',
      [attest.owner,attest.did,attest.app,attest.operation,attest.grant,attest.digest]);
    await denied(issuer,'SELECT '+schema+'.confirm_owner_consent($1,$2,$3,$4::uuid,$5,$6::bytea)',
      [attest.owner,attest.did,attest.app,attest.operation,attest.grant,attest.digest]);
    for(const owner of owners)await seed(owner);
    const api=createCanonicalAtprotoPgAuthority({pool:revoker});
    // Admission is irreversible, bounded to a single owner operation.
    assert.equal(await invoke(issuer,'begin',begin),true);
    assert.equal(await invoke(issuer,'begin',begin),true,'Lost begin ACK is idempotent');
    assert.equal(await invoke(issuer,'begin',{...begin,operation:crypto.randomUUID()}),false);
    assert.equal(await invoke(issuer,'begin',{...begin,digest:sha('wrong receipt')}),false);
    assert.equal(await invoke(issuer,'begin',{...begin,did:owners[1].did}),false);
    assert.equal((await api.getConsent({owner:first.owner,app:first.app})).state,'pending');
    await assert.rejects(api.verifyActiveGrant({
      owner:first.owner,app:first.app,grantUri:first.grant,did:first.did,
      consentRevision:'1'}),e=>e?.code==='ATPROTO_PG_PERMISSION_DENIED');
    assert.equal(await invoke(attestor,'attest',{...attest,
      grant:'https://other.example/foreign'}),false);
    assert.equal(await invoke(attestor,'attest',{...attest,operation:crypto.randomUUID()}),false);
    assert.equal(await invoke(attestor,'attest',attest),true);
    assert.equal((await attestor.query('SELECT '+schema+'.confirm_owner_consent('+
      '$1,$2,$3,$4::uuid,$5,$6::bytea) AS accepted',
      [attest.owner,attest.did,attest.app,attest.operation,attest.grant,attest.digest])).rows[0].accepted,true);
    assert.equal(await invoke(attestor2,'attest',attest),true,'Lost attest ACK is idempotent');
    assert.equal(await invoke(attestor,'attest',{...attest,digest:sha('stale RDF')}),false);
    assert.equal(await api.verifyActiveGrant({
      owner:first.owner,app:first.app,grantUri:first.grant,did:first.did,
      consentRevision:'1'}),true);
    assert.deepEqual(await api.revoke({owner:first.owner,app:first.app,
      grantUri:first.grant,expectedRevision:'1'}),{state:'blocked',revision:'2'});
    assert.equal((await attestor.query('SELECT '+schema+'.confirm_owner_consent('+
      '$1,$2,$3,$4::uuid,$5,$6::bytea) AS accepted',
      [attest.owner,attest.did,attest.app,attest.operation,attest.grant,attest.digest])).rows[0].accepted,false,
      'Revocation acknowledged before confirmation must fail closed');
    assert.equal(await invoke(attestor,'attest',attest),false,
      'SAI regrant cannot revive credentials from a revoked epoch');
    assert.equal(await invoke(issuer,'begin',begin),false);
    // Native owner DELETE during initial SAI POST blocks the pending row.
    const second=owners[1];
    const b={...second,digest:sha('owner approved:'+second.owner)};
    const proofB={...second,digest:sha('native Jena readback:'+second.owner)};
    assert.equal(await invoke(issuer,'begin',b),true);
    const pending=await api.getConsent({owner:second.owner,app:second.app});
    assert.equal(pending.state,'pending');
    assert.deepEqual(await api.revoke({owner:second.owner,app:second.app,
      grantUri:pending.grantUri,expectedRevision:'1'}),{state:'blocked',revision:'2'});
    assert.equal(await invoke(attestor,'attest',proofB),false);
    assert.equal(await invoke(issuer,'begin',b),false);
    // Independently connected attestors can retry a lost ACK across workers.
    const third=owners[2];
    const c={...third,digest:sha('verified signup:'+third.owner)};
    const proofC={...third,digest:sha('native Jena readback:'+third.grant)};
    assert.equal(await invoke(issuer,'begin',c),true);
    const claims=await Promise.all([
      invoke(attestor,'attest',proofC),invoke(attestor2,'attest',proofC)
    ]);
    assert.deepEqual(claims,[true,true]);
    const row=await read(third.owner);
    assert.equal(row.state,'active');assert.equal(row.revision,'1');
    assert.equal(Buffer.compare(row.grant_proof_sha256,proofC.digest),0);
    // Race current revocation with a late attestor: only a blocked row can
    // survive and neither repeated activation nor stale tickets revive it.
    const otherRevoker=createCanonicalAtprotoPgAuthority({pool:revoker2});
    const revocations=await Promise.allSettled([
      api.revoke({owner:third.owner,app:third.app,
        grantUri:third.grant,expectedRevision:'1'}),
      otherRevoker.revoke({owner:third.owner,app:third.app,
        grantUri:third.grant,expectedRevision:'1'})
    ]);
    assert.equal(revocations.filter(x=>x.status==='fulfilled').length,1,
      'Two independent PostgreSQL workers must have exactly one revocation winner');
    assert.equal(revocations.filter(x=>x.status==='rejected'&&
      x.reason?.code==='ATPROTO_PG_AUTHORITY_STALE').length,1);
    assert.deepEqual(revocations.find(x=>x.status==='fulfilled').value,
      {state:'blocked',revision:'2'});
    assert.equal(await invoke(attestor2,'attest',proofC),false);
    await assert.rejects(api.verifyActiveGrant({
      owner:third.owner,app:third.app,grantUri:third.grant,did:third.did,
      consentRevision:'1'}),e=>e?.code==='ATPROTO_PG_PERMISSION_DENIED');
    const states=(await admin.query('SELECT state,count(*)::int AS n FROM '+
      schema+'.consents GROUP BY state')).rows;
    assert.deepEqual(states,[{state:'blocked',n:3}]);
    console.log('PASS: PG18 canonical native consent pending/attested/blocked; '+
      '6 restricted logins, two attestors, no stale grant revival, release CLOSED');
  }catch(e){failed=e;throw e}
  finally{
    for(const client of clients.reverse())try{await client.end()}catch(e){errors.push(e)}
    if(schemaCreated)try{await admin.query('DROP SCHEMA '+schema+' CASCADE')}
      catch(e){errors.push(e)}
    for(const name of created.reverse())try{
      await admin.query('DROP ROLE '+identifier(logins[name]))
    }catch(e){errors.push(e)}
    if(schemaCreated)for(const name of [
      'paper_atproto_consent_issuer','paper_atproto_consent_attestor',
      'paper_atproto_authority_importer','paper_atproto_authority_revoker',
      'paper_atproto_authority_reader'
    ])try{await admin.query('DROP ROLE '+identifier(name))}
      catch(e){errors.push(e)}
    try{await admin.end()}catch(e){errors.push(e)}
    // eslint-disable-next-line no-unsafe-finally
    if(errors.length&&!failed)throw Error('Disposable authority role cleanup failed');
  }
}
await run();

'use strict';
/**
 * Disposable localhost Fuseki proof for G2 streamed index compaction.
 * No public routes, external actors, recipient HTTP, production credentials
 * or index publication of the newly staged revision.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const rdf = require('../utils/collective-membership-rdf');
const index = require('../utils/collective-membership-page-index');
const pub = require('../utils/collective-membership-publication');
const {
  readCompactionBaseQuery, decodeCompactionBase,
  stageCompactedMembership, verifyStagedCompactionManifest,
} = require('../utils/collective-membership-stream-compactor');
if (process.env.G2_BENCH_DISPOSABLE !== 'confirmed') throw Error('Disposable fixture required');
const host = process.env.FUSEKI_URL;
if (!host || !/^http:\/\/(?:localhost|127\.0\.0\.1):[0-9]+\/?$/u.test(host)) {
  throw Error('Refusing non-local TDB2 target');
}
const groupId = 'cg_' + 'a'.repeat(32);
const owner = 'https://paper-test.example/users/owner';
const app = 'https://paper-test.example/app';
const ns = 'http://activitypods.org/ns/core#';
const g = rdf.groupSubject(groupId);
const origin = host.replace(/\/+$/u,'') + '/settings';
const basic = Buffer.from((process.env.FUSEKI_USER||'admin') + ':' +
  (process.env.FUSEKI_PASSWORD||'')).toString('base64');
async function send(kind, statement) {
  const res = await fetch(origin + '/' + kind, {
    method:'POST', headers: {
      Authorization:'Basic '+basic,
      'content-type':'application/sparql-'+kind,
      accept:'application/sparql-results+json'
    }, body: statement, signal: AbortSignal.timeout(60000)
  });
  if (!res.ok) throw Error('TDB2 '+kind+' rejected '+res.status+' '+(await res.text()).slice(0,200));
  return kind==='query' ? (await res.json()).results.bindings : null;
}
function actor(n) { return 'https://federated.example/users/u'+String(n).padStart(6,'0'); }
async function main() {
  const before = await send('query','SELECT ?s WHERE { ?s ?p ?o } LIMIT 1');
  assert.equal(before.length,0,'Settings dataset must be disposable and EMPTY');
  const account='<urn:apods:compaction-test-owner>';
  const consent=rdf.consentSubject(owner,app);
  await send('update','INSERT DATA { '+account+
    ' a <http://semapps.org/ns/core#AuthAccount> ; '+
    '<http://semapps.org/ns/core#webId> '+JSON.stringify(owner)+' . '+
    consent+' <'+ns+'collectiveConsentStatus> "stable" ; '+
    '<'+ns+'collectiveConsentRevision> "1" . '+
    g+' a <'+ns+'CollectiveReservationV1> ; '+
    '<'+ns+'collectiveOwner> '+JSON.stringify(owner)+' ; '+
    '<'+ns+'collectiveApp> '+JSON.stringify(app)+' . }');
  await send('update',rdf.initializeQuery({groupId,owner,app}));
  const members=[{actorUri:owner,role:'owner'}];
  for(let i=0;i<300;i++) members.push({actorUri:actor(i),role:'member'});
  members.sort((a,b)=>a.actorUri<b.actorUri?-1:1);
  let cursor=null, offset=0, initialPages=0;
  while(offset<members.length) {
    const p=index.packPage({groupId,revision:1,cursor,
      members:members.slice(offset,offset+101),
      sourceHasMore: offset+101<members.length});
    await send('update',index.stagePageQuery(p.page));
    offset+=p.consumedCount;
    cursor=p.page.nextCursor;
    initialPages++;
  }
  await send('update',index.publishQuery({groupId,owner,app,revision:1}));
  assert.equal((await send('query',index.readPageQuery({
    groupId,owner,app,revision:1,cursor:null}))).length,1);
  await send('update',rdf.mutateQuery({
    groupId,owner,app,member:actor(42),role:'moderator',status:'active',
    expectedEpoch:1,receipt:crypto.randomUUID(),indexDelta:true
  }));
  assert.equal((await send('query',index.readPageQuery({
    groupId,owner,app,revision:1,cursor:null}))).length,0);
  let reads=0, stageCalls=0;
  const started=performance.now();
  const manifest=await stageCompactedMembership({
    groupId,owner,expectedBaseCount:members.length,
    deltaSnapshot: {
      groupId,baseRevision:1,membershipRevision:2,deltaCount:1,
      changes:[{actorUri:actor(42),kind:'upsert',role:'moderator'}]
    },
    async readBasePage({cursor}) {
      reads++;
      const rows=await send('query',readCompactionBaseQuery({
        groupId,owner,app,baseRevision:1,membershipRevision:2,cursor
      }));
      return decodeCompactionBase(rows,{groupId,baseRevision:1,membershipRevision:2,cursor});
    },
    async stagePages(pages) {
      stageCalls++;
      for (const page of pages) await send('update',index.stagePageQuery(page));
    }
  });
  const verify=await verifyStagedCompactionManifest({
    manifest,owner,async readPersistedPage({cursor}) {
      const s=index.pageSubject(groupId,2,cursor);
      const rows=await send('query','PREFIX apods: <'+ns+'> '+
        'SELECT ?pageJson ?pageDigest WHERE { '+s+
        ' apods:collectiveIndexPageJson ?pageJson ; '+
        'apods:collectiveIndexPageDigest ?pageDigest . } LIMIT 2');
      assert(rows.length<=1,'Multiple conflicting stored page representations');
      return rows.length ? {
        json:rows[0].pageJson.value,digest:rows[0].pageDigest.value
      }:null;
    }
  });
  assert.equal(verify.verifiedMembers,301);
  assert.equal(reads,initialPages,'Base read should be once per page, not per recipient');
  assert.equal(manifest.memberCount,301);
  // The staged revision is not published by staging or verification.
  const publicationArgs = { groupId, owner, app, manifest };
  assert.equal((await send('query',pub.readPublicationQuery(publicationArgs))).length,0);
  // A seal alone is not publication, and fails for stale/other revisions.
  await send('update',pub.sealManifestQuery(publicationArgs));
  assert.equal((await send('query',pub.readPublicationQuery(publicationArgs))).length,0);
  // A forged digest can never publish this generation.
  await send('update',pub.publishSealedManifestQuery({
    ...publicationArgs,manifest:{...manifest,digest:'f'.repeat(64)}
  }));
  assert.equal((await send('query',pub.readPublicationQuery(publicationArgs))).length,0);
  // A stale expected epoch does not publish, nor erase delta pointers.
  await send('update',pub.publishSealedManifestQuery({
    ...publicationArgs,manifest:{...manifest,membershipRevision:3}
  }));
  assert.equal((await send('query',pub.readPublicationQuery(publicationArgs))).length,0);
  // Staged revision must stay private until an authorized, atomic publisher
  // verifies manifest, delta, lease and live Group epoch together.
  assert.equal((await send('query',index.readPageQuery({
    groupId,owner,app,revision:2,cursor:null}))).length,0);
  // The verified sealed generation can be atomically published only while
  // the same live membership epoch, old base and consent remain valid.
  await send('update',pub.publishSealedManifestQuery(publicationArgs));
  assert.equal((await send('query',pub.readPublicationQuery(publicationArgs))).length,1);
  assert.equal((await send('query',index.readPageQuery({
    groupId,owner,app,revision:2,cursor:null
  }))).length,1);
  // Replay must be an idempotent no-op.
  await send('update',pub.publishSealedManifestQuery(publicationArgs));
  assert.equal((await send('query',pub.readPublicationQuery(publicationArgs))).length,1);
  // Revoking current SAI immediately suppresses even trusted compaction reads.
  await send('update','PREFIX apods: <'+ns+'> DELETE DATA { '+
    consent+' apods:collectiveConsentStatus "stable" . }; '+
    'INSERT DATA { '+consent+' apods:collectiveConsentStatus "blocked" . }');
  assert.equal((await send('query',readCompactionBaseQuery({
    groupId,owner,app,baseRevision:1,membershipRevision:2,cursor:null
  }))).length,0);
  console.log(JSON.stringify({proof:'g2-streaming-compaction-tdb2',ok:true,
    baselineMembers:301,initialPages,baseReadQueries:reads,
    stagingCalls:stageCalls,manifestPages:manifest.pageCount,
    verifiedMembers:verify.verifiedMembers,buildVerifyMs:Number(
      (performance.now()-started).toFixed(2)),
    published:true,remoteDelivery:false}));
}
main().catch(error=>{console.error('G2_STREAM_COMPACTION_PROOF_FAILED '+error.message);process.exitCode=1;});

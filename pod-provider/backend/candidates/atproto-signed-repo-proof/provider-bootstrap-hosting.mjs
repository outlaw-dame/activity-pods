// Disposable loopback genesis hosting. Each request observes the attested head,
// independently checks protected RDF and uses the existing sync XRPC protocol.
import {readVerifiedProviderGenesis} from './provider-bootstrap-genesis.mjs';
import {createReadOnlySyncXrpc} from './sync-xrpc-candidate.mjs';
import {makeDisposableProtectedFusekiReader,verifyProtectedBindingTerms} from './protected-rdf-attestor.mjs';

export function createBootstrapHosting(pool) {
  async function scope(did) {
    const result=await pool.query({text:'SELECT * FROM paper_account_reservation_proof.hosted_genesis_scope($1)',
      values:[did],query_timeout:2500});
    if(result.rowCount!==1) throw Error('Attested provider head unavailable');
    return result.rows[0];
  }
  async function snapshot(did) {
    const row=await scope(did);
    const proof=await readVerifiedProviderGenesis(pool,{reservationId:row.reservation_id,operationId:row.operation_id,did});
    const read=makeDisposableProtectedFusekiReader({origin:'http://127.0.0.1:3041',password:'fixture-attestor-only',bootstrapDid:did});
    const digest=verifyProtectedBindingTerms(await read(),{...proof,accountId:proof.webId,leaseEpoch:row.lease_epoch});
    if(!digest.equals(row.rdf_digest)) throw Error('Protected signup projection changed');
    return {...proof,accountId:proof.webId,verified:true,outboxStatus:row.outbox_status,fence:row.lease_epoch};
  }
  const repositoryAuthority={verifyReady:({did})=>snapshot(did)};
  const projectionAuthority={async readiness({did}) {
    const proof=await snapshot(did);
    return {...proof,ready:true,headCid:proof.commitCid};
  }};
  const resolvePublicKey=async({did})=>(await snapshot(did)).publicKeyPem;
  // Reuse a snapshot only within one HTTP request. Always check the current
  // head again at the dispatcher's final hosting check.
  let active=0;
  const handle=async(req,res)=>{
    if(active>=4){res.writeHead(503,{'cache-control':'no-store'});res.end();return;}
    active++;
    try{
      let proof;
      const current=async ({did})=>{
        const fresh=await snapshot(did);
        if(proof && (proof.commitCid!==fresh.commitCid || proof.fence!==fresh.fence ||
            proof.publicKeyPem!==fresh.publicKeyPem || proof.outboxStatus!==fresh.outboxStatus)) {
          throw Error('Provider genesis changed during read');
        }
        proof=fresh;
        return {webId:proof.webId,activityPubActorId:proof.webId,did,handle:proof.handle,
          pdsUrl:proof.pdsOrigin,atprotoManaged:true,atprotoSource:'local',status:'active'};
      };
      const checked=did=>{
        if(!proof||proof.did!==did) throw Error('Missing verified hosting snapshot');
        return proof;
      };
      const sync=createReadOnlySyncXrpc({fixtureOnly:true,pdsOrigin:'https://paper.example.org',resolveHostedAccount:current,
        repositoryAuthority:{verifyReady:({did})=>checked(did)},resolvePublicKey:({did})=>checked(did).publicKeyPem,
        projectionAuthority:{readiness:({did})=>({...checked(did),ready:true,headCid:proof.commitCid})},
        signedRepoStore:{verify:({did})=>checked(did)}});
      await sync.handle(req,res);
    }finally{active--;}
  };
  return {handle,repositoryAuthority,projectionAuthority,resolvePublicKey,snapshot};
}

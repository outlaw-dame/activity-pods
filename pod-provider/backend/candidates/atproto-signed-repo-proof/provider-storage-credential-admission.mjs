/**
 * NON-ACTIVATED direct Fuseki credential-admission gate for the REAL
 * ActivityPods provider architecture. Its ordinary TripleStoreService and
 * dataset-provisioning currently share CONFIG.JENA_USER/PASSWORD; this gate
 * verifies the admission invariants a future split must meet.
 *
 * No arbitrary SPARQL, dataset or URL comes from callers. Probe statements
 * are non-mutating random-key DELETE WHERE against disposable loopback
 * datasets. This cannot release production or replace service-level grants.
 */
import crypto from 'node:crypto';

const ORIGIN='http://127.0.0.1:3041';
const DATASETS=Object.freeze({ordinary:'ordinary-proof',protected:'protected-proof'});
const PREDICATE='<urn:paper:isolated:state>';
const PROTECTED_SUBJECT='<urn:paper:isolated:identity-binding>';
const EXPECTED='signed-baseline';
function refused(step='unknown') {
  const error=new Error('Provider protected storage credentials are not independently admitted');
  error.code='PROTECTED_STORAGE_CREDENTIAL_BOUNDARY_UNSAFE';
  error.step=step;
  throw error;
}
function guard(){
  if(process.env.NODE_ENV!=='test'||
     process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'||
     process.env.FUSEKI_ISOLATION_URL!==ORIGIN){
    refused('not_released');
  }
}
function principal(p,who){
  if(!p||typeof p.username!=='string'||typeof p.password!=='string'||
     !/^[A-Za-z][A-Za-z0-9-]{0,63}$/u.test(p.username)||
     p.password.length<8||p.password.length>256||p.password.includes(':')){
    refused(who+'_credential');
  }
  return Object.freeze({username:p.username,password:p.password});
}
function requestCredential(principal){
  return 'Basic '+Buffer.from(principal.username+':'+principal.password).toString('base64');
}
async function query(endpoint,credential,opts={}){
  const ctl=new AbortController();
  // Referenced timer prevents premature Node exit during cold-start
  // sockets and closes stalled connections on each bounded request.
  const timer=setTimeout(()=>ctl.abort(),8000);
  try{
    const response=await fetch(ORIGIN+endpoint,{
      method:opts.method||'POST',
      headers:{
        authorization:requestCredential(credential),
        ...(opts.type?{'content-type':opts.type}:{}),
        ...(opts.accept?{accept:opts.accept}: {})
      },
      body:opts.body||undefined,
      redirect:'manual',signal:ctl.signal
    });
    // No unbounded error response buffering or accidental redirect to
    // an unprotected SPARQL route.
    if(response.body)await response.body.cancel();
    return response.status;
  }catch{
    refused('fuseki_unreachable');
  }finally{clearTimeout(timer);}
}
function needs(status,allowed,label){
  if(!allowed.includes(status))refused(label);
}
function sparqlRead(name,subject=PROTECTED_SUBJECT){
  if(name!=='ordinary'&&name!=='protected')refused('unknown_dataset');
  return {method:'POST',type:'application/sparql-query',
    accept:'application/sparql-results+json',
    body:'ASK WHERE { '+subject+' '+PREDICATE+' ?value }'};
}
function noOpUpdate(nonce){
  // This random, never-used subject cannot match a real user resource.
  // Auditing an accidentally overprivileged credential MUST NOT delete
  // actual protected data as a side effect.
  return {method:'POST',type:'application/sparql-update',
    body:'DELETE WHERE { <urn:paper:credential-audit:'+nonce+'> '+
      '<urn:paper:credential-audit:never> ?value }'};
}
/**
 * The supplied "ordinary" credential models exactly what the real SemApps
 * TripleStoreService must retain. The projector and attestor must live in
 * different provider processes/secret scopes before production release.
 */
export async function proveProviderProtectedStorageBoundary({
  origin=ORIGIN,ordinary,projector,attestor,fixtureOnly=false
}={}){
  guard();
  if(fixtureOnly!==true||origin!==ORIGIN)refused('configuration');
  const roles={
    ordinary:principal(ordinary,'ordinary'),
    projector:principal(projector,'projector'),
    attestor:principal(attestor,'attestor')
  };
  if(new Set(Object.values(roles).map(p=>p.username)).size!==3||
     new Set(Object.values(roles).map(p=>p.password)).size!==3){
    refused('shared_principal');
  }
  const ordinaryRoute='/'+DATASETS.ordinary;
  const protectedRoute='/'+DATASETS.protected;
  const noop=noOpUpdate(crypto.randomBytes(16).toString('hex'));
  let checks=0;
  async function allow(route,role,opts,statuses,label){
    needs(await query(route,roles[role],opts),statuses,label);
    checks++;
  }
  async function deny(route,role,opts,label){
    needs(await query(route,roles[role],opts),[401,403],label);
    checks++;
  }
  const generic=roles.ordinary;
  // Ordinary ActivityPods/SemApps functionality MUST still work while
  // the generic credential cannot read, write, or administrate canonical
  // protected RDF. 401/403 is necessary; 404/405/302 is not evidence.
  await allow(ordinaryRoute+'/query','ordinary',
    sparqlRead('ordinary','<urn:paper:isolated:ordinary>'),[200],
    'ordinary_query_unavailable');
  await allow(ordinaryRoute+'/update','ordinary',noop,[200,204],
    'ordinary_update_unavailable');
  for(const route of [protectedRoute+'/update',
                       protectedRoute+'/sparql',
                       protectedRoute,protectedRoute+'/']){
    await deny(route,'ordinary',noop,'generic_protected_write');
  }
  await deny(protectedRoute+'/query','ordinary',sparqlRead('protected'),
    'generic_protected_read');
  await deny('/$/datasets','ordinary',{method:'GET'},'generic_admin_access');

  // The provider's projector must not access ordinary Pod datasets or
  // administrative routes, even when a no-op update would succeed.
  await allow(protectedRoute+'/update','projector',noop,[200,204],
    'projector_write_unavailable');
  await allow(protectedRoute+'/query','projector',sparqlRead('protected'),[200],
    'projector_read_unavailable');
  await deny(ordinaryRoute+'/update','projector',noop,
    'projector_ordinary_write');
  await deny(ordinaryRoute+'/query','projector',
    sparqlRead('ordinary','<urn:paper:isolated:ordinary>'),
    'projector_ordinary_read');
  await deny('/$/datasets','projector',{method:'GET'},
    'projector_admin_access');

  // Independent attestor can read protected RDF but has neither SPARQL
  // Update nor ordinary data/service administration capability.
  await allow(protectedRoute+'/query','attestor',sparqlRead('protected'),[200],
    'attestor_read_unavailable');
  await deny(protectedRoute+'/update','attestor',noop,
    'attestor_write_available');
  await deny(ordinaryRoute+'/update','attestor',noop,
    'attestor_ordinary_write');
  await deny(ordinaryRoute+'/query','attestor',
    sparqlRead('ordinary','<urn:paper:isolated:ordinary>'),
    'attestor_ordinary_read');
  await deny('/$/datasets','attestor',{method:'GET'},
    'attestor_admin_access');

  // Credentials are never returned or logged, not even encoded.
  return Object.freeze({isolated:true,checkedRoutes:checks,
    genericPodReadsAndWrites:true,independentProjector:true,
    independentReadOnlyAttestor:true,productionStorageReleased:false});
}

/**
 * Disposable admission proof for the real provider's future credential split.
 * Executes after the isolated Jena test creates two durable TDB2 datasets.
 * No production environment, network endpoint, admin secret, or user Pod.
 */
import assert from 'node:assert/strict';
import {proveProviderProtectedStorageBoundary} from './provider-storage-credential-admission.mjs';

if(process.env.NODE_ENV!=='test'||
   process.env.ATPROTO_FUSEKI_ISOLATION_DISPOSABLE!=='confirmed'||
   process.env.FUSEKI_ISOLATION_URL!=='http://127.0.0.1:3041'||
   !['prepare','verify'].includes(process.argv[2])){
 throw new Error('Disposable real Jena provider-boundary proof only');
}
const baseline={
 origin:process.env.FUSEKI_ISOLATION_URL,fixtureOnly:true,
 ordinary:{username:'fixture-ordinary',password:'fixture-ordinary-only'},
 projector:{username:'fixture-projector',password:'fixture-projector-only'},
 attestor:{username:'fixture-attestor',password:'fixture-attestor-only'}
};
const correct=await proveProviderProtectedStorageBoundary(baseline);
assert.equal(correct.isolated,true);
assert.equal(correct.checkedRoutes,16);
assert.equal(correct.productionStorageReleased,false);

const cases=[
 ['generic admin credentials',()=>({
   ...baseline,ordinary:{username:'admin',password:'fixture-admin-only'}
 })],
 ['generic attestor credentials',()=>({
   ...baseline,ordinary:{...baseline.attestor}
 })],
 ['generic projector credentials',()=>({
   ...baseline,ordinary:{...baseline.projector}
 })],
 ['attestor shares projector password',()=>({
   ...baseline,attestor:{...baseline.attestor,
     password:baseline.projector.password}
 })],
 ['wrong ordinary service password',()=>({
   ...baseline,ordinary:{...baseline.ordinary,password:'wrong-test-only'}
 })],
 ['bad origin',()=>({...baseline,origin:'http://127.0.0.1:3040'})]
];
for(const [label,configuration] of cases){
 await assert.rejects(proveProviderProtectedStorageBoundary(configuration()),
   error=>error?.code==='PROTECTED_STORAGE_CREDENTIAL_BOUNDARY_UNSAFE',label);
}
const previous=process.env.NODE_ENV;
try{
 process.env.NODE_ENV='production';
 await assert.rejects(proveProviderProtectedStorageBoundary(baseline),
   error=>error?.code==='PROTECTED_STORAGE_CREDENTIAL_BOUNDARY_UNSAFE');
}finally{process.env.NODE_ENV=previous;}
console.log('REAL_PROVIDER_CREDENTIAL_SPLIT_ADMISSION '+JSON.stringify({
 phase:process.argv[2],safeProbeChecks:correct.checkedRoutes,
 misconfigurationDenials:cases.length,
 productionAdmissionDenied:true,realHttpFusedDatasetIsolation:true,
 noNonDisposableNetwork:true,actualProviderStorageReleased:false
}));

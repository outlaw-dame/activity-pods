#!/usr/bin/env node
/**
 * Read-only REAL AWS S3 custody and immutable version inspection.
 * No production activation, no fixtures, no S3 PUT/DELETE, and no secret logs.
 *
 * Install exact SDK versions outside the source checkout and set
 * PAPER_WORM_SDK_ROOT to the directory containing node_modules.
 * All AWS credentials are resolved from two distinct named local profiles.
 * Never run with a test endpoint, a shared profile or a project admin role.
 */
import {createRequire} from 'node:module';
import path from 'node:path';
import {inspectIndependentS3Custody} from
 '../candidates/oauth-s3-independent-custody.mjs';

function invalid(){
  const e=new Error('Immutable S3 external operator configuration unavailable');
  e.code='WORM_CUSTODY_OPERATOR_CONFIGURATION';
  throw e;
}
const env=process.env;
async function main(){
  if(env.PAPER_WORM_CUSTODY_OPERATOR_CONFIRM!=='read-only-verified')
    invalid();
  const mandatory=[
    'PAPER_WORM_SDK_ROOT','PAPER_WORM_PROVIDER_PROFILE',
    'PAPER_WORM_READER_PROFILE','PAPER_WORM_BUCKET',
    'PAPER_WORM_REGION','PAPER_WORM_PROVIDER_ACCOUNT_ID',
    'PAPER_WORM_ARCHIVE_ACCOUNT_ID'
  ];
  if(mandatory.some(x=>!env[x]||typeof env[x]!=='string'))
    invalid();
  if(!path.isAbsolute(env.PAPER_WORM_SDK_ROOT)||
     env.PAPER_WORM_PROVIDER_PROFILE===env.PAPER_WORM_READER_PROFILE||
     !/^[a-z0-9-]{2,25}$/u.test(env.PAPER_WORM_REGION)||
     env.AWS_ENDPOINT_URL||env.AWS_ENDPOINT_URL_S3||
     env.PAPER_WORM_ENDPOINT||env.NODE_ENV==='test')
    invalid();

  const mode=env.PAPER_WORM_CUSTODY_PHASE;
  if(mode!=='preflight'&&mode!=='receipt')invalid();
  const fields=['PAPER_WORM_RECEIPT_KEY','PAPER_WORM_RECEIPT_VERSION',
    'PAPER_WORM_RECEIPT_SHA256'];
  if(mode==='receipt'&&fields.some(x=>!env[x]))invalid();
  if(mode==='preflight'&&fields.some(x=>env[x]))invalid();

  const require=createRequire(path.join(env.PAPER_WORM_SDK_ROOT,'package.json'));
  let s3,sts,providers;
  try {
    for(const name of ['@aws-sdk/client-s3','@aws-sdk/client-sts',
      '@aws-sdk/credential-providers']){
      if(require(name+'/package.json').version!=='3.1174.0')invalid();
    }
    s3=require('@aws-sdk/client-s3');
    sts=require('@aws-sdk/client-sts');
    providers=require('@aws-sdk/credential-providers');
  }catch{invalid()}
  const providerCredentials=providers.fromIni({
    profile:env.PAPER_WORM_PROVIDER_PROFILE
  });
  const readerCredentials=providers.fromIni({
    profile:env.PAPER_WORM_READER_PROFILE
  });
  const writerSts=new sts.STSClient({
    region:env.PAPER_WORM_REGION,credentials:providerCredentials,
    maxAttempts:1
  });
  const readerSts=new sts.STSClient({
    region:env.PAPER_WORM_REGION,credentials:readerCredentials,
    maxAttempts:1
  });
  const readerS3=new s3.S3Client({
    region:env.PAPER_WORM_REGION,credentials:readerCredentials,
    maxAttempts:1,forcePathStyle:false
  });
  const commands={...s3,...sts};
  try {
    const inspected=await inspectIndependentS3Custody({
      writerSts,readerSts,readerS3,commands,
      bucket:env.PAPER_WORM_BUCKET,
      expectedProviderAccount:env.PAPER_WORM_PROVIDER_ACCOUNT_ID,
      expectedBucketOwner:env.PAPER_WORM_ARCHIVE_ACCOUNT_ID,
      sample:mode==='receipt'?{
        key:env.PAPER_WORM_RECEIPT_KEY,
        versionId:env.PAPER_WORM_RECEIPT_VERSION,
        sha256:env.PAPER_WORM_RECEIPT_SHA256
      }:null
    });
    // No profile names, account IDs, keys, secrets or token bytes printed.
    // This output is NOT a production signoff or proof of IAM separation.
    process.stdout.write(JSON.stringify({
      schema:'paper.worm.external-custody-observation.v1',
      observedAt:new Date().toISOString(),phase:mode,
      configurationVerified:inspected.configurationVerified,
      receiptVerified:inspected.receiptVerified,
      retentionDays:inspected.retentionDays,
      releaseAccepted:false
    })+'\n');
  } finally {
    readerS3.destroy();readerSts.destroy();writerSts.destroy();
  }
}
main().catch(error=>{
  // Never leak credentials, AWS response objects or request URLs.
  process.stderr.write('REFUSED: '+
    (error?.code?.startsWith('WORM_CUSTODY_')?error.code:
      'WORM_CUSTODY_REMOTE_UNAVAILABLE')+'\n');
  process.exitCode=1;
});

'use strict';

// NONACTIVATED recovery gate. Existing Redis grants are not trusted to
// authorize signed PDS writes after a Redis-only backup restore.
// This candidate can run ONLY in explicitly disposable test fixtures.
// Production release remains CLOSED until issuer/revoker/hosted PDS and an
// independent PostgreSQL PITR anti-rollback witness are proven together.
const { MoleculerError } = require('moleculer').Errors;
const EPOCH=/^[1-9][0-9]{0,18}$/u;
const MAX=9223372036854775807n;
const GRANT=/^[A-Za-z0-9_-]{32}$/u;

function enabled() {
  const configured=process.env.PAPER_OAUTH_PG_EPOCH_DISPOSABLE;
  if(configured===undefined)return false;
  if(configured!=='confirmed'||process.env.NODE_ENV!=='test'||
     process.env.PAPER_OAUTH_PG_RESTORE_DISPOSABLE!=='confirmed'||
     process.env.PAPER_OAUTH_EPOCH_REDIS_DISPOSABLE!=='confirmed') {
    throw new MoleculerError('PostgreSQL OAuth recovery gate is unavailable',
      503,'PG_OAUTH_EPOCH_NOT_RELEASED');
  }
  return true;
}
function invalid() {
  throw new MoleculerError('OAuth consent generation is no longer authorized',
    400,'INVALID_GRANT');
}
function validEpoch(value) {
  return typeof value==='string'&&EPOCH.test(value)&&BigInt(value)<=MAX;
}
function claim(p) {
  if(typeof p?.canonicalAccountId!=='string'||
     p.canonicalAccountId.length<8||p.canonicalAccountId.length>2048||
     !p.canonicalAccountId.startsWith('https://')||
     typeof p.clientId!=='string'||p.clientId.length<8||p.clientId.length>2048||
     !p.clientId.startsWith('https://')||
     typeof p.scope!=='string'||p.scope.length<1||p.scope.length>8192||
     !GRANT.test(p.consentGrantId||''))invalid();
  return {
    canonicalAccountId:p.canonicalAccountId,clientId:p.clientId,
    consentGrantId:p.consentGrantId,scope:p.scope
  };
}
// Always read the current primary PG generation. No request/session cache.
async function current(ctx,p) {
  if(!enabled())return null;
  const record=claim(p);
  let revision;
  try { revision=await ctx.call('oauth-pg-epoch.current',record); }
  catch { invalid(); }
  if(!validEpoch(revision))invalid();
  return revision;
}
// Each minted refresh, rotated refresh and access-token introspection must
// compare the EXACT originally authorized revision and grant/scope binding.
async function verify(ctx,p) {
  if(!enabled())return true;
  const record=claim(p);
  if(!validEpoch(p.oauthPgRevision))invalid();
  let granted;
  try {
    granted=await ctx.call('oauth-pg-epoch.verify',
      {...record,oauthPgRevision:p.oauthPgRevision});
  } catch { invalid(); }
  if(granted!==true)invalid();
  return true;
}
module.exports={ enabled,current,verify,validEpoch };

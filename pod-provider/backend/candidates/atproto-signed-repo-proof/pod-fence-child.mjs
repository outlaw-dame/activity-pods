/**
 * Disposable helper for real multi-process Fuseki contention and SIGKILL.
 * Each process has its own HTTP connection. It cannot change production data.
 */
import crypto from 'node:crypto';
import { buildFencedRepoProjectionSparql } from './fuseki-fence.mjs';
import { consentSubject } from './pod-consent-fence.mjs';

if (process.env.NODE_ENV === 'production' ||
    process.env.ATPROTO_REPO_FUSEKI_PROOF_DISPOSABLE !== 'confirmed' ||
    process.env.FUSEKI_URL !== 'http://127.0.0.1:3040') {
  throw Error('Refusing to run a process-level test outside disposable Fuseki');
}
const [mode, epoch] = process.argv.slice(2);
if (!['write', 'crash-after-dispatch'].includes(mode) || !/^[3-9]$/u.test(epoch || '')) {
  throw Error('Unexpected test process arguments');
}
const origin = 'https://paper.example.org';
const accountId = origin + '/alice';
const appUri = origin + '/applications/paper';
const grantUri = accountId + '/data/access-grants/ag1';
const did = 'did:plc:' + 'a'.repeat(24);
const rootCid = 'bafyre' + 'a'.repeat(53);
const rev = '2222222222222';
const resourceUri = accountId + '/data/identity-bindings/atproto-' +
  crypto.createHash('sha256').update(accountId).digest('hex').slice(0, 24);
const query = buildFencedRepoProjectionSparql({
  resourceUri, accountId, did, rootCid, rev, fence: epoch,
  consentFence: {
    subjectUri: consentSubject(accountId, appUri),
    grantUri, revision: '1'
  }
});
const auth = 'Basic ' + Buffer.from(
  'admin:' + (process.env.FUSEKI_PASSWORD || 'admin')
).toString('base64');
const request = fetch(process.env.FUSEKI_URL + '/alice/update', {
  method: 'POST',
  headers: {
    authorization: auth,
    'content-type': 'application/sparql-update'
  },
  body: query,
  signal: AbortSignal.timeout(10000)
});
if (mode === 'crash-after-dispatch') {
  process.send?.({ dispatched: true });
}
const response = await request;
if (!response.ok) {
  throw Error('Jena rejected protected CAS with HTTP ' + response.status +
    ': ' + (await response.text()).slice(0, 350));
}
// Leave the process alive after dispatch so the parent can terminate it
// regardless of whether Fuseki has already completed this transaction.
if (mode === 'crash-after-dispatch') {
  await new Promise(resolve => setTimeout(resolve, 15000));
}

import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { Pool } from 'pg';
import { createCanonicalCoordinatorAdmission } from './canonical-coordinator-admission.mjs';

// Explicit local rehearsal only. Credentials never enter provider responses.
export async function loadCanonicalCoordinator(filename) {
  const pools = [];
  let file;
  try {
    if (process.env.NODE_ENV !== 'test' || process.env.PAPER_ACCOUNTS_DISPOSABLE !== 'confirmed') throw Error();
    file = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > 16384 || stat.size < 2 || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()) throw Error();
    const bytes = Buffer.alloc(16385);
    const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
    if (bytesRead !== stat.size) throw Error();
    const config = JSON.parse(bytes.subarray(0, bytesRead).toString('utf8'));
    bytes.fill(0);
    const keys = ['appClientId','reserverDsn','binderDsn','hmacKeyBase64','hmacKeyVersion'];
    if (!config || Object.keys(config).sort().join(',') !== keys.sort().join(',')) throw Error();
    const key = Buffer.from(config.hmacKeyBase64, 'base64');
    if (key.length !== 32 || key.toString('base64') !== config.hmacKeyBase64) throw Error();
    for (const [field, login] of [['reserverDsn','paper_account_reserver_login'],['binderDsn','paper_bridge_binder_login']]) {
      const url = new URL(config[field]);
      if (!['postgres:', 'postgresql:'].includes(url.protocol) || url.hostname !== '127.0.0.1' ||
          url.port !== '5548' || url.pathname !== '/atproto_signed_repo_proof_test' ||
          url.username !== login || !url.password || url.search || url.hash) throw Error();
      const pool = new Pool({ connectionString: url.href, max: 2, connectionTimeoutMillis: 2500,
        statement_timeout: 3000, query_timeout: 3500, idleTimeoutMillis: 1000, allowExitOnIdle: true });
      pool.on('error', () => {}); // Individual operations still fail closed; never log a DSN.
      pools.push(pool);
    }
    const admission = createCanonicalCoordinatorAdmission({ reserverPool: pools[0], binderPool: pools[1],
      appClientId: config.appClientId, hmacKey: key, hmacKeyVersion: config.hmacKeyVersion });
    key.fill(0);
    return Object.freeze({ admit: admission.admit, close: () => Promise.all(pools.map(pool => pool.end())) });
  } catch {
    await Promise.allSettled(pools.map(pool => pool.end()));
    throw Error('Canonical coordinator local configuration refused');
  } finally { await file?.close(); }
}

'use strict';

// A NON-ACTIVATED PostgreSQL 18 acceptance proof. It tests actual LOGIN
// credentials and SQLSTATE 42501, not mocked role checks or SET ROLE from
// an administrator. No production DB, migrations or credentials are touched.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Client } from 'pg';
import { createDisposablePgCanonicalRevoker } from './pg-canonical-revocation-gate.mjs';

const DSN = process.env.ATPROTO_REPO_PROOF_DSN || '';
const expected = /^postgres(?:ql)?:\/\/[^@]+@127\.0\.0\.1:5548\/atproto_signed_repo_proof_test$/u;
if (process.env.NODE_ENV !== 'test' ||
    process.env.ATPROTO_REPO_PROOF_DISPOSABLE !== 'confirmed' ||
    !expected.test(DSN)) {
  throw Error('Private authority proof requires disposable local PostgreSQL 18');
}

const random = crypto.randomBytes(8).toString('hex');
const schema = 'paper_private_auth_' + random;
const writer = 'paper_auth_writer_' + random;
const ordinary = 'paper_general_' + random;
const writerSecret = crypto.randomBytes(32).toString('base64url');
const ordinarySecret = crypto.randomBytes(32).toString('base64url');
const identifier = name => {
  if (!/^[a-z_][a-z0-9_]{0,62}$/u.test(name)) {
    throw Error('Invalid internal PostgreSQL identifier');
  }
  return '"' + name + '"';
};
const sqlSchema = identifier(schema);
const authority = sqlSchema + '.canonical_consent';
const revokeFunction = sqlSchema + '.block_consent';
const created = [];
const admin = new Client({
  connectionString: DSN, connectionTimeoutMillis: 3000,
  query_timeout: 5000
});
let ownerClient;
let ordinaryClient;
let secondRevoker;

function asRoleConnection(user, password) {
  const url = new URL(DSN);
  url.username = user;
  url.password = password;
  return new Client({
    connectionString: url.toString(), connectionTimeoutMillis: 3000,
    query_timeout: 5000
  });
}
async function deny(client, sql, params = []) {
  await assert.rejects(
    client.query(sql, params),
    error => error.code === '42501',
    'An ordinary or underprivileged writer must be denied by PostgreSQL'
  );
}

async function main() {
  await admin.connect();
  try {
    // Secrets contain only unquoted base64url characters. They are not
    // printed, reused or loaded from a deployment environment.
    for (const [name, secret] of [
      [writer, writerSecret], [ordinary, ordinarySecret]
    ]) {
      assert(/^[A-Za-z0-9_-]{43}$/u.test(secret));
      await admin.query(
        'CREATE ROLE ' + identifier(name) +
        " LOGIN PASSWORD '" + secret + "'" +
        ' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT' +
        ' NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2'
      );
      created.push(name);
    }
    await admin.query('CREATE SCHEMA ' + sqlSchema);
    await admin.query('REVOKE ALL ON SCHEMA ' + sqlSchema + ' FROM PUBLIC');
    await admin.query('GRANT USAGE ON SCHEMA ' + sqlSchema +
      ' TO ' + identifier(writer) + ', ' + identifier(ordinary));
    await admin.query('CREATE TABLE ' + authority +
      " (owner_id text PRIMARY KEY, app_id text NOT NULL," +
      " grant_uri text NOT NULL, revision bigint NOT NULL CHECK (revision > 0)," +
      " state text NOT NULL CHECK (state IN ('active','blocked')))");
    await admin.query('REVOKE ALL ON TABLE ' + authority + ' FROM PUBLIC');
    // The revocation-only login has NO direct table permissions. In
    // particular, UPDATE would allow a stolen login to reactivate consent.
    // A narrow SECURITY DEFINER function is the sole mutation surface.
    await admin.query(
      'CREATE FUNCTION ' + revokeFunction +
      ' (p_owner text, p_app text, p_grant text, p_expected bigint) ' +
      'RETURNS TABLE (new_revision bigint, new_state text) ' +
      'LANGUAGE SQL SECURITY DEFINER SET search_path = pg_catalog AS $body$ ' +
      'UPDATE ' + authority + ' AS c SET state = \'blocked\', revision = c.revision + 1 ' +
      'WHERE c.owner_id = p_owner AND c.app_id = p_app AND c.grant_uri = p_grant ' +
      'AND c.revision = p_expected AND c.state = \'active\' ' +
      'AND c.revision < 9223372036854775807 ' +
      'RETURNING c.revision, c.state $body$'
    );
    await admin.query('REVOKE ALL ON FUNCTION ' + revokeFunction +
      ' (text, text, text, bigint) FROM PUBLIC');
    await admin.query('GRANT EXECUTE ON FUNCTION ' + revokeFunction +
      ' (text, text, text, bigint) TO ' + identifier(writer));

    ownerClient = asRoleConnection(writer, writerSecret);
    ordinaryClient = asRoleConnection(ordinary, ordinarySecret);
    await Promise.all([ownerClient.connect(), ordinaryClient.connect()]);
    assert.equal((await ownerClient.query('SELECT current_user AS u')).rows[0].u, writer);
    assert.equal((await ordinaryClient.query('SELECT current_user AS u')).rows[0].u, ordinary);
    const ownerId = 'https://paper.example.test/alice';
    const appId = 'https://writer.example.test/app';
    const grantUri = ownerId + '/data/grants/verified';
    await admin.query(
      'INSERT INTO ' + authority +
      ' (owner_id,app_id,grant_uri,revision,state) VALUES ($1,$2,$3,1,$4)',
      [ownerId, appId, grantUri, 'active']
    );
    await deny(ordinaryClient, 'SELECT * FROM ' + authority + ' WHERE owner_id=$1', [ownerId]);
    await deny(ordinaryClient,
      'UPDATE ' + authority + " SET state='active',revision=99 WHERE owner_id=$1",
      [ownerId]);
    await deny(ordinaryClient,
      'INSERT INTO ' + authority +
      " (owner_id,app_id,grant_uri,revision,state) VALUES ($1,$2,$3,99,'active')",
      ['https://paper.example.test/attacker', appId, grantUri]);
    await deny(ordinaryClient, 'DELETE FROM ' + authority + ' WHERE owner_id=$1', [ownerId]);
    await deny(ordinaryClient, 'TRUNCATE TABLE ' + authority);
    await deny(ordinaryClient,
      'CREATE TABLE ' + sqlSchema + '.unauthorized_copy (id text)');
    await deny(ordinaryClient, 'SET ROLE ' + identifier(writer));
    await deny(ownerClient, 'DELETE FROM ' + authority + ' WHERE owner_id=$1', [ownerId]);
    await deny(ownerClient,
      'UPDATE ' + authority + " SET state='active',revision=99 WHERE owner_id=$1",
      [ownerId]);
    await deny(ownerClient, 'SELECT * FROM ' + authority + ' WHERE owner_id=$1', [ownerId]);
    await deny(ownerClient,
      'INSERT INTO ' + authority +
      " (owner_id,app_id,grant_uri,revision,state) VALUES ($1,$2,$3,1,'active')",
      ['https://paper.example.test/attacker', appId, grantUri]);
    await deny(ordinaryClient,
      'SELECT * FROM ' + revokeFunction + ' ($1,$2,$3,$4::bigint)',
      [ownerId, appId, grantUri, '1']);

    const revoker = createDisposablePgCanonicalRevoker({
      client: ownerClient, schemaName: schema, fixtureOnly: true
    });
    await assert.rejects(
      revoker.revoke({ ownerId, appId, grantUri: 'https://paper.example.test/forged', revision: '1' }),
      error => error.code === 'CANONICAL_CONSENT_STALE'
    );
    const blocked = await revoker.revoke({ ownerId, appId, grantUri, revision: '1' });
    assert.equal(blocked.state, 'blocked');
    assert.equal(blocked.revision, '2');
    // Replay and stale requests must never succeed or re-activate consent.
    await assert.rejects(
      revoker.revoke({ ownerId, appId, grantUri, revision: '1' }),
      error => error.code === 'CANONICAL_CONSENT_STALE'
    );

    // Separate process credentials compete over an independent active row.
    // One conditional PG UPDATE wins; the other sees a stale revision.
    const secondOwner = 'https://paper.example.test/other';
    const secondGrant = secondOwner + '/data/grants/verified';
    await admin.query(
      'INSERT INTO ' + authority +
      ' (owner_id,app_id,grant_uri,revision,state) VALUES ($1,$2,$3,1,$4)',
      [secondOwner, appId, secondGrant, 'active']
    );
    secondRevoker = asRoleConnection(writer, writerSecret);
    await secondRevoker.connect();
    const otherRevoker = createDisposablePgCanonicalRevoker({
      client: secondRevoker, schemaName: schema, fixtureOnly: true
    });
    const contenders = await Promise.allSettled([
      revoker.revoke({ ownerId: secondOwner, appId, grantUri: secondGrant, revision: '1' }),
      otherRevoker.revoke({ ownerId: secondOwner, appId, grantUri: secondGrant, revision: '1' })
    ]);
    assert.equal(contenders.filter(x => x.status === 'fulfilled').length, 1);
    assert.equal(contenders.filter(x => x.status === 'rejected' &&
      x.reason?.code === 'CANONICAL_CONSENT_STALE').length, 1);
    const actual = await admin.query('SELECT owner_id,app_id,revision,state FROM ' + authority);
    assert.equal(actual.rowCount, 2);
    const byOwner = new Map(actual.rows.map(row => [row.owner_id, row]));
    assert.equal(byOwner.get(ownerId)?.app_id, appId);
    assert.equal(byOwner.get(ownerId)?.revision, '2');
    assert.equal(byOwner.get(ownerId)?.state, 'blocked');
    assert.equal(byOwner.get(secondOwner)?.revision, '2');
    assert.equal(byOwner.get(secondOwner)?.state, 'blocked');
    console.log(JSON.stringify({
      success: true, scope: 'non-activated-postgresql18-canonical-storage-isolation',
      independentLogins: 3, deniedUnauthorizedOperations: 7,
      deniedWriterDeletion: true, deniedWriterDirectDml: true,
      atomicCasContenders: 2, blockedCanonicalRows: 2,
      canonicalStateRetained: true
    }));
  } finally {
    // Terminate our own clients before removing test roles. Do not DROP
    // any external schema, database, role or key. Every name has a random,
    // validated per-run prefix; the known disposable DB was verified above.
    if (secondRevoker) await secondRevoker.end().catch(() => {});
    if (ordinaryClient) await ordinaryClient.end().catch(() => {});
    if (ownerClient) await ownerClient.end().catch(() => {});
    await admin.query('DROP SCHEMA IF EXISTS ' + sqlSchema + ' CASCADE');
    for (const name of created.reverse()) {
      await admin.query('DROP ROLE ' + identifier(name));
    }
    await admin.end();
  }
}
main().catch(error => {
  console.error('PG private authority proof failed:', error.code || error.name);
  process.exitCode = 1;
});

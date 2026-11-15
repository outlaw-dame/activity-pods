'use strict';

const crypto = require('node:crypto');
const { createPgBootstrapReadiness } = require('../candidates/postgres-bootstrap-readiness');

const secret = Buffer.alloc(32, 0x5a);
const scope = {
  idempotencyKey: 'entryway:acct_11111111-1111-4111-8111-111111111111:aaaaaaaaaaaaaaaaaaaaaaaa',
  username: 'alice',
  webId: 'https://paper.example.org/users/alice',
  actorId: 'https://paper.example.org/users/alice',
  atprotoDid: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',
  atprotoHandle: 'alice.paper.example.org'
};
const row = {
  account_id: '11111111-1111-4111-8111-111111111111',
  grant_uri: 'https://paper.example.org/users/alice/data/grants/repo',
  consent_revision: '2',
  account_generation: '3'
};
function config(pool) {
  return {
    pool, providerId: 'https://paper.example.org',
    appClientId: 'https://app.paper.example.org/app',
    appUri: 'https://writer.paper.example.org/app',
    hmacKey: secret, hmacKeyVersion: 1, fixtureOnly: true
  };
}
let saved;
beforeEach(() => {
  saved = {
    NODE_ENV: process.env.NODE_ENV,
    PAPER_ACCOUNTS_DISPOSABLE: process.env.PAPER_ACCOUNTS_DISPOSABLE,
    ATPROTO_REPO_PROOF_DISPOSABLE: process.env.ATPROTO_REPO_PROOF_DISPOSABLE,
    PAPER_ACCOUNT_COMPLETION_DISPOSABLE: process.env.PAPER_ACCOUNT_COMPLETION_DISPOSABLE
  };
  process.env.NODE_ENV = 'test';
  process.env.PAPER_ACCOUNTS_DISPOSABLE = 'confirmed';
  process.env.ATPROTO_REPO_PROOF_DISPOSABLE = 'confirmed';
  process.env.PAPER_ACCOUNT_COMPLETION_DISPOSABLE = 'confirmed';
});
afterEach(() => {
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

test('reads exact HMAC scope without forwarding raw entryway key', async () => {
  const pool = { query: jest.fn(async () => ({ rowCount: 1, rows: [row] })) };
  const reader = createPgBootstrapReadiness(config(pool));
  const result = await reader.assertCurrent(scope);
  expect(result).toEqual({
    verified: true, accountId: row.account_id,
    grantUri: row.grant_uri, consentRevision: '2',
    accountGeneration: '3',
    canAuthenticate: false, releaseAuthorized: false
  });
  expect(Object.isFrozen(result)).toBe(true);
  expect(pool.query).toHaveBeenCalledTimes(1);
  const [sql, params] = pool.query.mock.calls[0];
  expect(sql).toContain('paper_account_candidate.current_bootstrap_proof');
  expect(params.slice(0, 3)).toEqual([
    'https://paper.example.org', 'https://app.paper.example.org/app', 1
  ]);
  expect(params[3]).toEqual(
    crypto.createHmac('sha256', secret)
      .update('account-signup-idempotency-v1\0', 'utf8')
      .update(scope.idempotencyKey).digest()
  );
  expect(params.slice(4)).toEqual([
    'alice', scope.webId, scope.actorId, scope.atprotoDid,
    scope.atprotoHandle, 'https://writer.paper.example.org/app'
  ]);
  expect(JSON.stringify(params)).not.toContain(scope.idempotencyKey);
});

test.each([
  { idempotencyKey: 'forged-request' },
  { idempotencyKey: 'entryway:acct_foo:aaaa' },
  { username: 'ALICE' },
  { webId: 'https://attacker:secret@paper.example.org/users/alice' },
  { webId: 'https://paper.example.org/users/alice#me' },
  { actorId: 'https://another.example.org/users/bob' },
  { atprotoDid: 'did:web:paper.example.org' },
  { atprotoHandle: 'bad handle' },
])('invalid or cross-account scope is denied before database access: %j', async change => {
  const pool = { query: jest.fn() };
  await expect(createPgBootstrapReadiness(config(pool)).assertCurrent({
    ...scope, ...change
  })).rejects.toMatchObject({ code: 'BOOTSTRAP_PG_SCOPE_INVALID' });
  expect(pool.query).not.toHaveBeenCalled();
});

test('cannot bypass release fuse with a preconstructed reader or runtime flag', async () => {
  const pool = { query: jest.fn() };
  const reader = createPgBootstrapReadiness(config(pool));
  for (const override of [
    { NODE_ENV: 'production' },
    { ATPROTO_REPO_PROOF_DISPOSABLE: 'no' },
    { PAPER_ACCOUNT_COMPLETION_DISPOSABLE: 'no' }
  ]) {
    const [key, value] = Object.entries(override)[0];
    const before = process.env[key];
    process.env[key] = value;
    await expect(reader.assertCurrent(scope)).rejects.toMatchObject({
      code: 'BOOTSTRAP_PG_NOT_RELEASED'
    });
    if (before === undefined) delete process.env[key];
    else process.env[key] = before;
  }
  await expect(createPgBootstrapReadiness({
    ...config(pool), fixtureOnly: false
  }).assertCurrent(scope)).rejects.toMatchObject({
    code: 'BOOTSTRAP_PG_NOT_RELEASED'
  });
  expect(pool.query).not.toHaveBeenCalled();
});

test.each([
  { rowCount: 0, rows: [] },
  { rowCount: 2, rows: [row, row] },
  { rowCount: 1, rows: [{ ...row, consent_revision: '0' }] },
  { rowCount: 1, rows: [{ ...row, grant_uri: 'https://attacker:token@example.org/grant' }] },
])('missing or ambiguous current authority refuses readiness: %j', async response => {
  const pool = { query: jest.fn(async () => response) };
  await expect(createPgBootstrapReadiness(config(pool)).assertCurrent(scope))
    .rejects.toMatchObject({ code: 'BOOTSTRAP_PG_NOT_READY' });
});

test('does not leak SQL errors or grant state when database access fails', async () => {
  const pool = { query: jest.fn(async () => {
    throw new Error('postgres://postgres:password@private-host/mydb');
  }) };
  await expect(createPgBootstrapReadiness(config(pool)).assertCurrent(scope))
    .rejects.toMatchObject({
      code: 'BOOTSTRAP_PG_UNAVAILABLE',
      message: 'Current provider signup readiness is unavailable'
    });
});

test('requires provider-owned configuration and a secret unrelated to raw HTTP claims', () => {
  const pool = { query: jest.fn() };
  for (const override of [
    { hmacKey: Buffer.alloc(16) },
    { hmacKeyVersion: 0 },
    { providerId: 'http://insecure.example.org' },
    { appUri: 'https://app.example.org/?redirect=evil' },
    { appClientId: 'https://user:pass@app.example.org/app' },
    { pool: {} },
  ]) {
    expect(() => createPgBootstrapReadiness({
      ...config(pool), ...override
    })).toThrow('Current provider signup readiness is unavailable');
  }
});

const restrictedRole = Object.freeze({
  is_superuser: false, bypass_rls: false,
  can_create_db: false, can_create_role: false, can_replicate: false,
  can_login: true, session_matches: true,
  importer_member: false, revoker_member: false,
  read_all_member: false, write_all_member: false,
  exec_program_member: false, read_files_member: false, write_files_member: false,
  account_owner_member: false, authority_owner_member: false,
  repo_owner_member: false,
  reader_member: true, account_schema: true,
  can_create: false, can_create_schema: false,
  can_read_authority: false,
  can_read_repo: false, can_prove: true,
  can_select_accounts: false, can_select_journal: false,
  can_write_accounts: false, can_write_journal: false
});

function mockRestrictedPool(query) {
  const client = { query: jest.fn(query), release: jest.fn() };
  return {
    client,
    pool: { query: jest.fn(query), connect: jest.fn(async () => client) }
  };
}

test('restricted provider bootstrap mode checks DB role at every current proof read', async () => {
  const { pool, client } = mockRestrictedPool(async sql =>
    sql.includes('FROM pg_catalog.pg_roles')
      ? { rowCount: 1, rows: [{ ...restrictedRole }] }
      : { rowCount: 1, rows: [row] });
  const reader = createPgBootstrapReadiness({
    ...config(pool), requireRestrictedReader: true
  });
  expect(await reader.assertReaderRole()).toBe(true);
  expect((await reader.assertCurrent(scope)).verified).toBe(true);
  expect((await reader.assertCurrent(scope)).verified).toBe(true);
  expect(pool.query).toHaveBeenCalledTimes(1); // startup
  expect(pool.connect).toHaveBeenCalledTimes(2);
  const operations = client.query.mock.calls.map(([sql]) =>
    sql.includes('FROM pg_catalog.pg_roles') ? 'role' : 'proof');
  expect(operations).toEqual(['role','proof','role','proof']);
  expect(client.release).toHaveBeenCalledTimes(2);
  expect(client.release).toHaveBeenCalledWith(false);
  const roleSql = pool.query.mock.calls[0][0];
  expect(roleSql).toContain('paper_account_bootstrap_reader');
  expect(roleSql).toContain('has_table_privilege');
  expect(roleSql).toContain('has_function_privilege');
  expect(roleSql).not.toContain(scope.idempotencyKey);
});

test.each([
  { is_superuser: true },
  { bypass_rls: true },
  { can_create_db: true },
  { can_create_role: true },
  { can_replicate: true },
  { can_login: false },
  { session_matches: false },
  { importer_member: true },
  { revoker_member: true },
  { read_all_member: true },
  { write_all_member: true },
  { exec_program_member: true },
  { read_files_member: true },
  { write_files_member: true },
  { account_owner_member: true },
  { authority_owner_member: true },
  { repo_owner_member: true },
  { reader_member: false },
  { account_schema: false },
  { can_create: true },
  { can_create_schema: true },
  { can_read_authority: true },
  { can_read_repo: true },
  { can_prove: false },
  { can_select_accounts: true },
  { can_select_journal: true },
  { can_write_accounts: true },
  { can_write_journal: true },
])('rejects overly broad or incomplete PostgreSQL reader role: %j', async change => {
  const { pool, client } = mockRestrictedPool(async sql =>
    sql.includes('FROM pg_catalog.pg_roles')
      ? { rowCount: 1, rows: [{ ...restrictedRole, ...change }] }
      : { rowCount: 1, rows: [row] });
  await expect(createPgBootstrapReadiness({
    ...config(pool), requireRestrictedReader: true
  }).assertCurrent(scope)).rejects.toMatchObject({
    code: 'BOOTSTRAP_PG_ROLE_UNAUTHORIZED',
    message: 'Current provider signup readiness is unavailable'
  });
  expect(pool.query).not.toHaveBeenCalled();
  expect(client.query).toHaveBeenCalledTimes(1);
  expect(client.release).toHaveBeenCalledWith(false);
});

test('credentialed database failures do not leak through reader role checks', async () => {
  const { pool, client } = mockRestrictedPool(async () => {
    throw new Error('postgresql://admin:password@private-db/production');
  });
  await expect(createPgBootstrapReadiness({
    ...config(pool), requireRestrictedReader: true
  }).assertCurrent(scope)).rejects.toMatchObject({
    code: 'BOOTSTRAP_PG_ROLE_UNAVAILABLE',
    message: 'Current provider signup readiness is unavailable'
  });
  expect(client.release).toHaveBeenCalledWith(true);
});

test('role validation is unavailable once the disposable authority is disabled', async () => {
  const pool = { query: jest.fn(), connect: jest.fn() };
  const reader = createPgBootstrapReadiness({
    ...config(pool), requireRestrictedReader: true
  });
  process.env.NODE_ENV = 'production';
  await expect(reader.assertReaderRole()).rejects.toMatchObject({
    code: 'BOOTSTRAP_PG_NOT_RELEASED'
  });
  expect(pool.query).not.toHaveBeenCalled();
});

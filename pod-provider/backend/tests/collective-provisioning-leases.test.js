'use strict';

const crypto = require('node:crypto');
const service = require('../services/collective-provisioning-leases.service');

const SECRET = 'w'.repeat(48);
const ID = 'cg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const WORKER = 'worker-node-001';
const PURPOSE = 'provider.collective.worker.lease.v1';

function tokenHash(token) { return crypto.createHash('sha256').update(token).digest('hex'); }
function grant(operation, id = ID, workerId = WORKER, hash = '') {
  const issuedAt = Date.now() - 400;
  const expiresAt = issuedAt + 20000;
  const fields = [PURPOSE, operation, id, workerId, hash, issuedAt, expiresAt];
  return {
    purpose: PURPOSE, operation, groupId: id, workerId, tokenHash: hash,
    issuedAt, expiresAt,
    mac: crypto.createHmac('sha256', SECRET).update(JSON.stringify(fields)).digest('hex')
  };
}
function harness(settings = {}) {
  const calls = [];
  const instance = {
    settings: { enabled: true, secret: SECRET, ttlMs: 30000, ...settings },
    _load: async () => null
  };
  const ctx = params => ({
    params, call: async (name, args) => {
      calls.push({ name, args });
      throw Error('unexpected external call: ' + name);
    }
  });
  return { instance, calls, action(name, params) {
    return service.actions[name].handler.call(instance, ctx(params));
  }};
}
async function rejects(promise, code) {
  await expect(promise).rejects.toMatchObject({ type: code });
}

describe('durable provider worker lease authorization', () => {
  test('default disabled denies before any state access', async () => {
    const h = harness({ enabled: false });
    await rejects(h.action('claim', {
      canonicalGroupId: ID, workerId: WORKER, workerGrant: grant('claim')
    }), 'COLLECTIVE_WORKER_LEASE_DISABLED');
    expect(h.calls).toHaveLength(0);
  });

  test('missing independent worker secret disables claims', async () => {
    const h = harness({ secret: '' });
    await rejects(h.action('claim', {
      canonicalGroupId: ID, workerId: WORKER, workerGrant: grant('claim')
    }), 'COLLECTIVE_WORKER_LEASE_DISABLED');
    expect(h.calls).toHaveLength(0);
  });

  test.each([
    ['invalid ID', { canonicalGroupId: '../private' }, 'COLLECTIVE_INVALID_ID'],
    ['invalid worker', { workerId: '../app' }, 'COLLECTIVE_INVALID_WORKER'],
    ['missing worker grant', { workerGrant: null }, 'COLLECTIVE_WORKER_UNAUTHORIZED'],
    ['wrong operation', { workerGrant: grant('release') }, 'COLLECTIVE_WORKER_UNAUTHORIZED'],
    ['wrong worker', { workerGrant: grant('claim', ID, 'another-worker') }, 'COLLECTIVE_WORKER_UNAUTHORIZED'],
    ['wrong group', { workerGrant: grant('claim', 'cg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb') }, 'COLLECTIVE_WORKER_UNAUTHORIZED'],
    ['bad HMAC', { workerGrant: { ...grant('claim'), mac: '0'.repeat(64) } }, 'COLLECTIVE_WORKER_UNAUTHORIZED'],
    ['Unicode HMAC', { workerGrant: { ...grant('claim'), mac: 'é'.repeat(64) } }, 'COLLECTIVE_WORKER_UNAUTHORIZED'],
    ['stale grant', { workerGrant: { ...grant('claim'), expiresAt: Date.now() - 1 } }, 'COLLECTIVE_WORKER_UNAUTHORIZED']
  ])('fails closed for %s', async (_label, overrides, type) => {
    const h = harness();
    await rejects(h.action('claim', {
      canonicalGroupId: ID, workerId: WORKER, workerGrant: grant('claim'), ...overrides
    }), type);
    expect(h.calls).toHaveLength(0);
  });

  test('invalid or missing release token never touches persistent state', async () => {
    const h = harness();
    await rejects(h.action('release', {
      canonicalGroupId: ID, workerId: WORKER, leaseToken: '../stolen',
      workerGrant: grant('release')
    }), 'COLLECTIVE_INVALID_LEASE_TOKEN');
    expect(h.calls).toHaveLength(0);
  });

  test('worker grant is bound to the particular lease token digest', async () => {
    const h = harness();
    const token = 'a'.repeat(43);
    await rejects(h.action('renew', {
      canonicalGroupId: ID, workerId: WORKER, leaseToken: token,
      workerGrant: grant('renew', ID, WORKER, tokenHash('b'.repeat(43)))
    }), 'COLLECTIVE_WORKER_UNAUTHORIZED');
    expect(h.calls).toHaveLength(0);
  });

  test('expired active lease cannot be renewed or released as proof of current authority', async () => {
    const h = harness();
    const token = 'a'.repeat(43);
    const hash = tokenHash(token);
    h.instance._load = async () => ({
      owner: WORKER, hash, until: Date.now() - 500, epoch: crypto.randomUUID()
    });
    await rejects(h.action('renew', {
      canonicalGroupId: ID, workerId: WORKER, leaseToken: token,
      workerGrant: grant('renew', ID, WORKER, hash)
    }), 'COLLECTIVE_LEASE_UNAVAILABLE');
  });

  test('corrupt duplicate lease row is rejected rather than silently resolved', async () => {
    const ctx = { call: async () => [{ owner: { value: WORKER } }, { owner: { value: WORKER } }] };
    await rejects(service.methods._load(ctx, ID), 'COLLECTIVE_CORRUPT_LEASE');
  });
});

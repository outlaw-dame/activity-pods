'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  createDisposableCredentialEpochMiddleware,
  runDisposableCredentialChange
} = require('../middlewares/credential-epoch');

process.env.NODE_ENV = 'test';
process.env.PAPER_CREDENTIAL_EPOCH_DISPOSABLE = 'confirmed';
const webId = 'https://paper.example.org/claimtest-12345678';
const legacy = 'https://paper.example.org/legacy-account';
const opId = '11111111-1111-4111-8111-111111111111';
const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const clock = () => 1795393000;
function b64(payload) { return Buffer.from(JSON.stringify(payload)).toString('base64url'); }
function sign(payload) {
  const header = b64({ alg: 'RS256', typ: 'JWT' });
  const body = b64(payload);
  const message = header + '.' + body;
  const signature = crypto.sign('sha256', Buffer.from(message), keys.privateKey);
  return message + '.' + signature.toString('base64url');
}
function verify(token) {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  if (!crypto.verify('sha256', Buffer.from(parts[0] + '.' + parts[1]),
    keys.publicKey, Buffer.from(parts[2], 'base64url'))) return false;
  try { return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); }
  catch { return false; }
}
function stateful() {
  const accounts = new Map([
    [webId, { webId, username: 'claimtest-12345678',
      signupReservationId: 'reservation-00001', hashedPassword: 'old' }],
    [legacy, { webId: legacy, username: 'legacy-account', hashedPassword: 'legacy' }]
  ]);
  const epochs = new Map([
    [webId, { webId, epoch: '1', state: 'active', mode: 'unified' }],
    [legacy, { webId: legacy, mode: 'legacy' }]
  ]);
  let readFailure = false;
  const authority = {
    async readOwnerState(id) {
      if (readFailure) throw Error('independent unavailable');
      return { ...epochs.get(id) };
    },
    async beginChange({ webId: id }) {
      const old = epochs.get(id);
      if (!old || old.state !== 'active') return { accepted: false };
      const nextEpoch = (BigInt(old.epoch) + 1n).toString();
      epochs.set(id, { webId: id, epoch: old.epoch,
        state: 'pending', mode: 'unified', nextEpoch });
      return { accepted: true, previousEpoch: old.epoch, nextEpoch };
    },
    async commitChange({ webId: id, nextEpoch }) {
      const current = epochs.get(id);
      if (current?.state !== 'pending' || current.nextEpoch !== nextEpoch)
        return { committed: false };
      epochs.set(id, { webId: id, epoch: nextEpoch, state: 'active', mode: 'unified' });
      return { committed: true, epoch: nextEpoch };
    }
  };
  const broker = {
    async call(name, params, options) {
      assert.equal(name, 'auth.account.findByWebId');
      assert.deepEqual(options.meta, {});
      assert.equal(options.retries, 0);
      return accounts.get(params.webId) || null;
    }
  };
  const makeCtx = (params, meta = {}) => ({ params, broker, meta });
  const guard = createDisposableCredentialEpochMiddleware({
    fixtureOnly: true, authority, now: clock, ttlSeconds: 900
  });
  const mint = guard.localAction(ctx => sign(ctx.params.payload), {
    name: 'auth.jwt.generateServerSignedToken'
  });
  const inspect = guard.localAction(ctx => verify(ctx.params.token), {
    name: 'auth.jwt.verifyServerSignedToken'
  });
  const issue = async (id = webId) => mint(makeCtx({ payload: { webId: id } }));
  const check = async token => inspect(makeCtx({ token }));
  return { guard, authority, accounts, epochs, broker, makeCtx, mint,
    inspect, issue, check, setReadFailure: v => { readFailure = v; } };
}
async function denies(fn, code) {
  await assert.rejects(fn, e => e?.type === code);
}
test('new unified account JWT is RS256 signed with exp and generation', async () => {
  const f = stateful();
  const token = await f.issue();
  const payload = verify(token);
  assert.equal(payload.webId, webId);
  assert.equal(payload.paper_credential_epoch, '1');
  assert.equal(payload.iat, clock());
  assert.equal(payload.exp, clock() + 900);
  assert.equal((await f.check(token)).webId, webId);
});
test('legacy accounts retain existing login/verification behavior', async () => {
  const f = stateful();
  const oldToken = sign({ webId: legacy });
  assert.equal(verify(await f.issue(legacy)).paper_credential_epoch, undefined);
  assert.equal((await f.check(oldToken)).webId, legacy);
  assert.equal(await f.check(sign({ webId: 'https://missing.example.org/a' })), false);
});
test('missing epoch claim, stale generation and old never-expiring tokens deny', async () => {
  const f = stateful();
  const token = await f.issue();
  assert.equal(await f.check(sign({ webId })), false);
  assert.equal(await f.check(sign({ webId,
    paper_credential_epoch: '1', iat: clock(), exp: clock() + 400 })), false);
  f.epochs.set(webId, { webId, epoch: '2', state: 'active', mode: 'unified' });
  assert.equal(await f.check(token), false);
  assert.equal((await f.check(await f.issue())).paper_credential_epoch, '2');
});
test('failed/blocked canonical epoch read fails closed without caching', async () => {
  const f = stateful();
  const token = await f.issue();
  f.setReadFailure(true);
  await denies(() => f.issue(), 'CREDENTIAL_EPOCH_UNAVAILABLE');
  assert.equal(await f.check(token), false);
  f.setReadFailure(false);
  f.epochs.set(webId, { webId, epoch: '1', state: 'pending', mode: 'unified' });
  await denies(() => f.issue(), 'CREDENTIAL_EPOCH_UNAVAILABLE');
  assert.equal(await f.check(token), false);
});
test('credential change begins independent pending fence before password write', async () => {
  const f = stateful();
  const old = await f.issue();
  const result = await runDisposableCredentialChange({
    authority: f.authority, webId, operationId: opId,
    fixtureOnly: true,
    apply: async () => {
      assert.equal(f.epochs.get(webId).state, 'pending');
      assert.equal(await f.check(old), false);
      f.accounts.get(webId).hashedPassword = 'rotated';
      return { changed: true };
    }
  });
  assert.deepEqual(result, { changed: true });
  assert.equal(f.epochs.get(webId).epoch, '2');
  assert.equal(await f.check(old), false);
  assert.equal((await f.check(await f.issue())).paper_credential_epoch, '2');
});
test('missing or negative downstream ACK must not seal a credential epoch', async () => {
  for (const outcome of [undefined, null, false, { changed: false }, { ok: true }]) {
    const f = stateful();
    const old = await f.issue();
    let commitCalled = false;
    const originalCommit = f.authority.commitChange;
    f.authority.commitChange = async params => {
      commitCalled = true;
      return originalCommit(params);
    };
    await denies(() => runDisposableCredentialChange({
      authority: f.authority, webId, operationId: opId, fixtureOnly: true,
      apply: async () => {
        f.accounts.get(webId).hashedPassword = 'possibly-updated';
        return outcome;
      }
    }), 'CREDENTIAL_EPOCH_MUTATION_UNCERTAIN');
    assert.equal(commitCalled, false);
    assert.equal(f.epochs.get(webId).state, 'pending');
    assert.equal(await f.check(old), false);
    await denies(() => f.issue(), 'CREDENTIAL_EPOCH_UNAVAILABLE');
  }
});
test('ambiguous password update leaves pending fence denying old bearer', async () => {
  const f = stateful(); const token = await f.issue();
  await denies(() => runDisposableCredentialChange({
    authority: f.authority, webId, operationId: opId, fixtureOnly: true,
    apply: async () => {
      f.accounts.get(webId).hashedPassword = 'perhaps-changed';
      throw Error('transport lost after durable account change');
    }
  }), 'CREDENTIAL_EPOCH_MUTATION_UNCERTAIN');
  assert.equal(f.epochs.get(webId).state, 'pending');
  assert.equal(await f.check(token), false);
  await denies(() => f.issue(), 'CREDENTIAL_EPOCH_UNAVAILABLE');
});
test('simultaneous signing and rotation cannot return stale bearer', async () => {
  const f = stateful(); let releaseSign;
  let signed;
  const pendingSign = new Promise(resolve => { releaseSign = resolve; });
  const next = ctx => {
    signed = sign(ctx.params.payload);
    return pendingSign.then(() => signed);
  };
  const delayedMint = f.guard.localAction(next, {
    name: 'auth.jwt.generateServerSignedToken'
  });
  const task = delayedMint(f.makeCtx({ payload: { webId } }));
  // Allow issuer to reach signing before beginning rotation.
  for (let i = 0; i < 20 && !signed; i++) await new Promise(setImmediate);
  assert.ok(signed);
  await runDisposableCredentialChange({
    authority: f.authority, webId, operationId: opId, fixtureOnly: true,
    apply: async () => {
      f.accounts.get(webId).hashedPassword = 'new';
      return { changed: true };
    }
  });
  releaseSign();
  await denies(() => task, 'CREDENTIAL_EPOCH_CHANGED');
  assert.equal(await f.check(signed), false);
});
test('caller cannot inject epoch, expiration or issued-at for new account', async () => {
  const f = stateful();
  for (const injected of [
    { paper_credential_epoch: '999' }, { iat: clock() - 100 },
    { exp: clock() + 100000 }
  ]) {
    await denies(() => f.mint(f.makeCtx({
      payload: { webId, ...injected }
    })), 'CREDENTIAL_EPOCH_TOKEN_SHAPE_INVALID');
  }
});
test('new-account expired/unknown-epoch tokens denied; legacy unaffected', async () => {
  const f = stateful();
  const expired = sign({ webId, paper_credential_epoch: '1',
    iat: clock() - 900, exp: clock() });
  assert.equal(await f.check(expired), false);
  assert.equal(await f.check(sign({ webId, paper_credential_epoch: '999999',
    iat: clock(), exp: clock() + 900 })), false);
  assert.ok(await f.check(sign({ webId: legacy })));
});
test('rewound account marker cannot downgrade unified owner to legacy', async () => {
  const f = stateful();
  const token = await f.issue();
  delete f.accounts.get(webId).signupReservationId;
  assert.equal(await f.check(token), false);
  await denies(() => f.issue(), 'CREDENTIAL_EPOCH_DOWNGRADE_DENIED');
  // A restored authority that misclassifies a currently enrolled account
  // is also a hard error when the marker still exists.
  f.accounts.get(webId).signupReservationId = 'reservation-00001';
  f.epochs.set(webId, { webId, mode: 'legacy' });
  assert.equal(await f.check(token), false);
  await denies(() => f.issue(), 'CREDENTIAL_EPOCH_DOWNGRADE_DENIED');
});
test('absent independent classification does not fall through to legacy', async () => {
  const f = stateful();
  const token = await f.issue();
  f.epochs.delete(webId);
  assert.equal(await f.check(token), false);
  await denies(() => f.issue(), 'CREDENTIAL_EPOCH_UNAVAILABLE');
});
test('test-only guard cannot be activated from production environment', () => {
  const f = stateful();
  assert.throws(() => createDisposableCredentialEpochMiddleware({
    authority: f.authority, fixtureOnly: false
  }), e => e?.type === 'CREDENTIAL_EPOCH_NOT_RELEASED');
  assert.equal(f.guard.localAction(x => x, { name: 'unrelated.action' }) instanceof Function, true);
});

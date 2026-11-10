'use strict';
const crypto = require('node:crypto');
const service = require('../services/collective-memberships.service');
const rdf = require('../utils/collective-membership-rdf');
const gate = require('../services/utils/collective-release-gate');

const groupId = 'cg_1234567890abcdef1234567890abcdef';
const owner = 'https://paper.example/users/alice#me';
const app = 'https://paper.example/app';
const member = 'https://remote.example/users/bob';
const secret = 'membership-test-secret-' + 'f'.repeat(40);
const settings = { enabled: true, approvedApps: [app], secret };
function authorized(operation, extras = {}) {
  const params = {
    groupId, owner, app, ...extras
  };
  const requestHash = service._test.canonicalRequest(operation, params);
  const issuedAt = Date.now() - 500;
  const expiresAt = issuedAt + 30000;
  const fields = [service._test.PURPOSE, operation, groupId, owner, app,
    requestHash, issuedAt, expiresAt];
  const mac = crypto.createHmac('sha256', secret)
    .update(JSON.stringify(fields)).digest('hex');
  return { ...params, grant: {
    purpose: service._test.PURPOSE, operation, groupId, owner, app,
    requestHash, issuedAt, expiresAt, mac
  } };
}
function fakeCtx(params, queryRows) {
  const calls = [];
  const ctx = {
    params,
    async call(name, args) {
      calls.push({ name, args });
      if (name === 'auth.account.findByWebId') return { webId: owner };
      if (name === 'app-registrations.isRegistered') return true;
      if (name === 'access-authorizations.getSpecialRights') {
        return ['http://activitypods.org/ns/core#ManageMembers'];
      }
      if (name === 'triplestore.query') return typeof queryRows === 'function'
        ? queryRows(calls) : queryRows;
      return null;
    }
  };
  return { ctx, calls };
}
const binding = value => ({ value: String(value) });

describe('G2 owner-scoped membership authority release boundary', () => {
  test('no production actions can be enabled by environment flags alone', () => {
    expect(gate.CONSENT_BRIDGE_RELEASED).toBe(false);
    expect(service.settings.enabled).toBe(false);
  });
  test('disabled actions and forged grants produce zero Fuseki work', async () => {
    const params = authorized('initialize');
    const a = fakeCtx(params, [{ epoch: binding(1) }]);
    await expect(service.actions.initialize.handler.call({ settings: { ...settings, enabled: false } }, a.ctx))
      .rejects.toMatchObject({ type: 'GROUP_MEMBERSHIP_DISABLED' });
    expect(a.calls).toHaveLength(0);
    const invalid = fakeCtx({
      ...params, grant: { ...params.grant, mac: 'a'.repeat(64) }
    }, [{ epoch: binding(1) }]);
    await expect(service.actions.initialize.handler.call({ settings }, invalid.ctx))
      .rejects.toMatchObject({ type: 'GROUP_MEMBERSHIP_UNAUTHORIZED' });
    expect(invalid.calls).toHaveLength(0);
  });
  test('initialization verifies real owner/account in one settings transaction', async () => {
    const t = fakeCtx(authorized('initialize'), [{ epoch: binding(1) }]);
    const result = await service.actions.initialize.handler.call({ settings }, t.ctx);
    expect(result).toEqual({ groupId, membershipRevision: 1 });
    expect(t.calls.map(c => c.name)).toEqual([
      'auth.account.findByWebId', 'app-registrations.isRegistered',
      'access-authorizations.getSpecialRights',
      'triplestore.update', 'triplestore.query',
      'auth.account.findByWebId', 'app-registrations.isRegistered',
      'access-authorizations.getSpecialRights'
    ]);
    const storage = t.calls.filter(c => c.name.startsWith('triplestore.'));
    expect(storage.every(c => c.args.dataset === 'settings')).toBe(true);
    expect(storage[0].args.query).toContain('AuthAccount');
    expect(storage[0].args.query).toContain('deletedAt');
    expect(storage[0].args.query).toContain('collectiveConsentStatus "stable"');
  });
  test('membership mutation checks the same committed receipt, not just matching state', async () => {
    const params = authorized('change', {
      member, role: 'moderator', status: 'active', expectedEpoch: 3
    });
    let receipt = null;
    const t = fakeCtx(params, calls => {
      const body = calls.find(c => c.name === 'triplestore.update').args.query;
      const found = body.match(/apods:collectiveMemberMutationReceipt "([0-9a-f-]{36})"/u);
      receipt = found && found[1];
      return [{
        epoch: binding(4), role: binding('moderator'),
        status: binding('active'), receipt: binding(receipt)
      }];
    });
    expect(await service.actions.change.handler.call({ settings }, t.ctx))
      .toMatchObject({ membershipRevision: 4, member, role: 'moderator' });
    expect(receipt).toMatch(/^[0-9a-f-]{36}$/u);
    expect(t.calls.filter(c => c.name.startsWith('triplestore.'))).toHaveLength(2);
    expect(t.calls.find(c => c.name === 'triplestore.update').args.query)
      .toContain('FILTER(xsd:integer(?oldEpoch) = 3)');
    const losing = fakeCtx(params, [{
      epoch: binding(4), role: binding('moderator'),
      status: binding('active'), receipt: binding(crypto.randomUUID())
    }]);
    await expect(service.actions.change.handler.call({ settings }, losing.ctx))
      .rejects.toMatchObject({ type: 'GROUP_MEMBERSHIP_STALE_EPOCH' });
  });
  test('owner identity cannot be overwritten and no provider-scanning calls occur', async () => {
    const params = authorized('change', {
      member: owner, role: 'admin', status: 'active', expectedEpoch: 1
    });
    const t = fakeCtx(params, []);
    await expect(service.actions.change.handler.call({ settings }, t.ctx))
      .rejects.toThrow('cannot modify Group owner');
    expect(t.calls).toHaveLength(0);
  });
  test('bounded keyset read returns revision-bound owner scoped page', async () => {
    const params = authorized('list', { cursor: undefined, limit: 2 });
    const t = fakeCtx(params, [
      { actor: binding(member), role: binding('member'), epoch: binding(4) },
      { actor: binding('https://paper.example/users/alice#me'),
        role: binding('owner'), epoch: binding(4) },
      { actor: binding('https://remote.example/users/carol'),
        role: binding('member'), epoch: binding(4) }
    ]);
    // This fixture intentionally returns unsorted actors; refuse it.
    await expect(service.actions.list.handler.call({ settings }, t.ctx))
      .rejects.toMatchObject({ type: 'GROUP_MEMBERSHIP_SNAPSHOT_UNVERIFIED' });
    const queries = t.calls.filter(c => c.name === 'triplestore.query');
    expect(queries).toHaveLength(1);
    expect(queries[0].args.query).toContain('LIMIT 3');
    expect(queries[0].args.query).not.toContain('OFFSET');
  });
  test('membership template rejects excessive page limits and inconsistent actor URL', () => {
    expect(() => rdf.listQuery({ groupId, owner, app, limit: 1001 })).toThrow('limit');
    expect(() => rdf.mutateQuery({
      groupId, owner, app, member: 'not an actor', role: 'member', status: 'active',
      expectedEpoch: 1, receipt: crypto.randomUUID()
    })).toThrow('actor');
  });
});

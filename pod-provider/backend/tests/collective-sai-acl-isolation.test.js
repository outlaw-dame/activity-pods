'use strict';

const service = require('../services/sai/access-authorizations');

function audit(operation, rights) {
  const calls = [];
  const ctx = {
    params: {
      podOwner: 'https://provider.example/users/alice#me',
      appUri: 'https://forum.example/app',
      specialRightsUris: rights
    },
    async call(name, args) {
      calls.push({ name, args });
      if (name === 'activitypub.collection.getContainerUri') return 'https://provider.example/collections';
      if (name === 'files.getContainerUri') return 'https://provider.example/files';
      if (name === 'activitypub.activity.getContainerUri') return 'https://provider.example/activities';
      return true;
    }
  };
  return service.actions[operation](ctx).then(() => calls);
}

describe('SAI social Group rights are not personal Pod ACL rights', () => {
  test.each(['addPermissionsFromSpecialRights', 'removePermissionsFromSpecialRights'])(
    '%s: CreateGroup and ReadGroups alone never touch WebACL or personal data',
    async operation => {
      for (const rights of [
        ['apods:CreateGroup'],
        ['apods:ReadGroups'],
        ['apods:ReadGroups', 'apods:CreateGroup']
      ]) {
        expect(await audit(operation, rights)).toEqual([]);
      }
    }
  );

  test('explicit legacy CreateCollection continues its existing WebACL path', async () => {
    const calls = await audit('addPermissionsFromSpecialRights', ['apods:CreateCollection']);
    expect(calls.some(c => c.name === 'webacl.resource.addRights')).toBe(true);
  });

  test('Group plus legacy Collection rights leaves legacy path explicit', async () => {
    const calls = await audit('addPermissionsFromSpecialRights', [
      'apods:CreateGroup', 'apods:CreateCollection'
    ]);
    expect(calls.some(c => c.name === 'webacl.resource.addRights')).toBe(true);
  });
});

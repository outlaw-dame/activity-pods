import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  needIdentifier,
  uniqueNeedIdentifiers,
  initialConsentSelection,
  hasMissingRequirements,
  acceptedUpgradeNeeds,
  persistApprovedUpgrade
} from './consentPolicy.mjs';

test('first install preselects required rights only, never optional rights', () => {
  const required = [
    { id: 'https://app.example/access/required' },
    'apods:ReadInbox',
    { id: 'https://app.example/access/required' }
  ];
  const optional = [
    { id: 'https://app.example/access/optional' },
    'apods:PostOutbox'
  ];
  const initial = initialConsentSelection(required);
  assert.deepEqual(initial, ['https://app.example/access/required', 'apods:ReadInbox']);
  assert(!initial.includes(optional[0].id));
  assert(!initial.includes(optional[1]));
  assert.deepEqual(initialConsentSelection([]), []);
});

test('identifier extraction handles invalid and duplicate needs without undefined grants', () => {
  assert.equal(needIdentifier(null), null);
  assert.equal(needIdentifier({ id: '' }), null);
  assert.equal(needIdentifier({ unknown: 'value' }), null);
  assert.equal(needIdentifier('  apods:ReadOutbox  '), 'apods:ReadOutbox');
  assert.deepEqual(uniqueNeedIdentifiers([
    'apods:ReadInbox', 'apods:ReadInbox', null, {},
    { id: 'https://app.example/n1' }, { id: 'https://app.example/n1' },
    { id: undefined }
  ]), ['apods:ReadInbox', 'https://app.example/n1']);
});

test('new optional rights alone require the owner consent screen', () => {
  assert.equal(hasMissingRequirements([], ['apods:PostOutbox']), true);
  assert.equal(hasMissingRequirements([{ id: 'https://example.org/required' }], []), true);
  assert.equal(hasMissingRequirements([], []), false);
  assert.equal(hasMissingRequirements([], [null, undefined]), false);
});

test('unchecked optional permissions cause no authorization mutation', () => {
  const result = acceptedUpgradeNeeds(
    ['apods:ReadInbox'], [], [], ['apods:PostOutbox']
  );
  assert.deepEqual(result, {
    grants: ['apods:ReadInbox'], additions: [], changed: false
  });
});

test('selected optional rights are added once only after owner action', () => {
  const result = acceptedUpgradeNeeds(
    ['apods:ReadInbox'], [], ['apods:PostOutbox', 'apods:PostOutbox'],
    ['apods:PostOutbox']
  );
  assert.deepEqual(result, {
    grants: ['apods:ReadInbox', 'apods:PostOutbox'],
    additions: ['apods:PostOutbox'], changed: true
  });
});

test('required rights are preselected but unapproved extra rights are rejected', () => {
  const required = ['apods:ReadInbox'];
  const optional = [{ id: 'https://app.example/optional' }];
  const approved = acceptedUpgradeNeeds(
    ['apods:ReadOutbox'], required,
    ['apods:ReadInbox', 'https://app.example/optional'],
    optional
  );
  assert.deepEqual(approved.grants, [
    'apods:ReadOutbox', 'apods:ReadInbox', 'https://app.example/optional'
  ]);
  assert.deepEqual(approved.additions, [
    'apods:ReadInbox', 'https://app.example/optional'
  ]);
  assert.throws(
    () => acceptedUpgradeNeeds([], required, [], optional),
    /SAI_CONSENT_SELECTION_INVALID/
  );
  assert.throws(
    () => acceptedUpgradeNeeds([], required, ['apods:ReadInbox', 'apods:UpdateWebId'], optional),
    /SAI_CONSENT_SELECTION_INVALID/
  );
});

test('never silently expand existing grants when manifest adds optional needs', () => {
  const oldRights = ['apods:ReadInbox', 'apods:ReadOutbox'];
  const required = [];
  const optional = [
    'apods:PostOutbox',
    'apods:UpdateWebId',
    { id: 'https://app.example/data/delete' }
  ];
  assert.equal(hasMissingRequirements(required, optional), true);
  const result = acceptedUpgradeNeeds(oldRights, required, initialConsentSelection(required), optional);
  assert.deepEqual(result.grants, oldRights);
  assert.equal(result.changed, false);
});


test('declining all new optional rights persists the new manifest without expanding grants', async () => {
  let called = 0;
  const result = await persistApprovedUpgrade({
    appUri: 'https://memory.example/app',
    existingGrants: ['apods:ReadInbox'],
    requiredMissing: [],
    selectedMissing: [],
    optionalMissing: ['apods:PostOutbox', 'apods:UpdateWebId'],
    upgradeApp: async ({ appUri, grantedAccessNeeds }) => {
      called += 1;
      assert.equal(appUri, 'https://memory.example/app');
      assert.deepEqual(grantedAccessNeeds, ['apods:ReadInbox']);
    }
  });
  assert.equal(called, 1, 'manifest acknowledgment must not be skipped when rights do not change');
  assert.equal(result.changed, false);
  assert.deepEqual(result.additions, []);
});

test('accepted optional rights are persisted once, while existing grants survive', async () => {
  const calls = [];
  const approved = await persistApprovedUpgrade({
    appUri: 'https://memory.example/app',
    existingGrants: ['apods:ReadInbox'],
    requiredMissing: [],
    selectedMissing: ['apods:PostOutbox', 'apods:PostOutbox'],
    optionalMissing: ['apods:PostOutbox', 'apods:UpdateWebId'],
    upgradeApp: async payload => calls.push(payload)
  });
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], {
    appUri: 'https://memory.example/app',
    grantedAccessNeeds: ['apods:ReadInbox', 'apods:PostOutbox']
  });
  assert.deepEqual(approved.additions, ['apods:PostOutbox']);
});

test('invalid selected rights and backend failures do not permit a false manifest acknowledgment', async () => {
  let writes = 0;
  const write = async () => { writes += 1; };
  await assert.rejects(persistApprovedUpgrade({
    appUri: 'https://memory.example/app',
    existingGrants: ['apods:ReadInbox'],
    requiredMissing: [],
    selectedMissing: ['apods:UpdateWebId'],
    optionalMissing: ['apods:PostOutbox'],
    upgradeApp: write
  }), /SAI_CONSENT_SELECTION_INVALID/);
  assert.equal(writes, 0);

  await assert.rejects(persistApprovedUpgrade({
    appUri: 'https://memory.example/app',
    existingGrants: ['apods:ReadInbox'],
    requiredMissing: [],
    selectedMissing: [],
    optionalMissing: ['apods:PostOutbox'],
    upgradeApp: async () => {
      throw new Error('SAI revision failed to commit');
    }
  }), /SAI revision failed to commit/);
});

test('manifest-only upgrade calls the backend exactly once even if no permission requirements changed', async () => {
  const operations = [];
  await persistApprovedUpgrade({
    appUri: 'https://memory.example/app',
    existingGrants: ['apods:ReadOutbox'],
    requiredMissing: [],
    selectedMissing: [],
    optionalMissing: [],
    upgradeApp: async payload => operations.push(payload)
  });
  assert.deepEqual(operations, [{
    appUri: 'https://memory.example/app',
    grantedAccessNeeds: ['apods:ReadOutbox']
  }]);
});

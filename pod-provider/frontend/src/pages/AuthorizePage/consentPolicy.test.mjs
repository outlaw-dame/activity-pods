import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  needIdentifier,
  uniqueNeedIdentifiers,
  initialConsentSelection,
  hasMissingRequirements,
  acceptedUpgradeNeeds
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

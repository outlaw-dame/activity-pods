'use strict';
const crypto = require('node:crypto');
const rdf = require('../../utils/collective-membership-rdf');
const PURPOSE = 'provider.collective.membership.v1';

function requestHash(operation, params) {
  const { groupId, owner, app } = params;
  rdf.validateId(groupId);
  rdf.validateActor(owner);
  rdf.validateActor(app);
  if (operation === 'initialize') return digest([operation, groupId, owner, app]);
  if (operation === 'change') {
    rdf.validateActor(params.member);
    if (params.member === owner) throw new TypeError('cannot modify Group owner membership');
    if (!rdf.ROLES.has(params.role) || !rdf.STATUSES.has(params.status)) {
      throw new TypeError('GROUP_MEMBER_INVALID_INPUT');
    }
    if (!Number.isSafeInteger(params.expectedEpoch) || params.expectedEpoch < 1) {
      throw new TypeError('GROUP_MEMBERSHIP_INVALID_EPOCH');
    }
    return digest([operation, groupId, owner, app, params.member,
      params.role, params.status, params.expectedEpoch]);
  }
  if (operation === 'list') {
    if (params.cursor != null) rdf.validateActor(params.cursor);
    if (!Number.isSafeInteger(params.limit) || params.limit < 1 ||
        params.limit > rdf.MAX_LIMIT) {
      throw new TypeError('GROUP_MEMBERSHIP_INVALID_LIMIT');
    }
    return digest([operation, groupId, owner, app, params.cursor ?? null, params.limit]);
  }
  throw new TypeError('GROUP_MEMBERSHIP_INVALID_OPERATION');
}
function digest(fields) {
  return crypto.createHash('sha256').update(JSON.stringify(fields)).digest('hex');
}
function issueGrant(secret, operation, params) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) {
    throw new TypeError('GROUP_MEMBERSHIP_ISSUER_DISABLED');
  }
  const hash = requestHash(operation, params);
  const issuedAt = Date.now();
  const expiresAt = issuedAt + 30000;
  const fields = [PURPOSE, operation, params.groupId, params.owner, params.app,
    hash, issuedAt, expiresAt];
  return {
    purpose: PURPOSE, operation, groupId: params.groupId, owner: params.owner,
    app: params.app, requestHash: hash, issuedAt, expiresAt,
    mac: crypto.createHmac('sha256', secret).update(JSON.stringify(fields)).digest('hex')
  };
}
module.exports = { PURPOSE, requestHash, issueGrant };

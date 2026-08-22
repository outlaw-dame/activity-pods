'use strict';

const crypto = require('crypto');

const MAX_AUTHORIZATION_HEADER_BYTES = 8 * 1024;
const BEARER_PREFIX_BYTES = Buffer.byteLength('Bearer ', 'ascii');
const MAX_BEARER_TOKEN_BYTES = MAX_AUTHORIZATION_HEADER_BYTES - BEARER_PREFIX_BYTES;
const MIN_SIGNING_TOKEN_BYTES = 32;
const BEARER_TOKEN_RE = /^[A-Za-z0-9\-._~+/]+=*$/;
const IMF_FIXDATE_RE = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

function configuredSigningToken(env = process.env) {
  const token = env.ACTIVITYPODS_TOKEN;
  if (typeof token !== 'string') return null;

  const tokenBytes = Buffer.byteLength(token, 'utf8');
  if (tokenBytes < MIN_SIGNING_TOKEN_BYTES || tokenBytes > MAX_BEARER_TOKEN_BYTES) return null;
  return BEARER_TOKEN_RE.test(token) ? token : null;
}

function parseBearerToken(authorization) {
  if (typeof authorization !== 'string' || authorization.length === 0) return null;
  if (Buffer.byteLength(authorization, 'utf8') > MAX_AUTHORIZATION_HEADER_BYTES) return null;

  const match = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i.exec(authorization);
  return match ? match[1] : null;
}

function timingSafeSecretEqual(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string' || actual.length === 0 || expected.length === 0) {
    return false;
  }

  const actualDigest = crypto.createHash('sha256').update(actual, 'utf8').digest();
  const expectedDigest = crypto.createHash('sha256').update(expected, 'utf8').digest();
  return crypto.timingSafeEqual(actualDigest, expectedDigest);
}

function isDateWithinSkew(dateString, maxClockSkewSeconds, nowMs = Date.now()) {
  if (typeof dateString !== 'string' || !IMF_FIXDATE_RE.test(dateString)) return false;

  const maxSkewSeconds = Number(maxClockSkewSeconds);
  if (!Number.isFinite(maxSkewSeconds) || maxSkewSeconds < 0) return false;
  if (!Number.isFinite(nowMs)) return false;

  const parsedMs = Date.parse(dateString);
  if (!Number.isFinite(parsedMs)) return false;
  if (new Date(parsedMs).toUTCString() !== dateString) return false;

  return Math.abs(nowMs - parsedMs) <= maxSkewSeconds * 1000;
}

module.exports = {
  MAX_AUTHORIZATION_HEADER_BYTES,
  MAX_BEARER_TOKEN_BYTES,
  MIN_SIGNING_TOKEN_BYTES,
  configuredSigningToken,
  isDateWithinSkew,
  parseBearerToken,
  timingSafeSecretEqual
};

'use strict';

/**
 * Provider G1 deployment fuse. Environment variables alone MUST NOT turn on
 * a partially integrated SAI-to-Fuseki consent bridge. The flag is a code
 * review/release decision, not a remotely configurable authorization bypass.
 *
 * To move this gate, first prove:
 * - every SAI/registration/account mutation path is fenced before commit;
 * - grant restoration is reconciled and serialized with reservation insertion;
 * - the worker cannot advance a revoked/unreconciled reservation;
 * - deployment E2E tests and the real Fuseki concurrency proof pass.
 *
 * A synthetic Fuseki consent row is NOT equivalent to SAI consent.
 */
const CONSENT_BRIDGE_RELEASED = false;

module.exports = Object.freeze({ CONSENT_BRIDGE_RELEASED });

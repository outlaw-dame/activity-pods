'use strict';

const RdfJSONSerializer = require('../RdfJSONSerializer');

const MODE_SINGLE = 'single';
const MODE_DISTRIBUTED = 'distributed';
const GROUP_POD_CELL = 'pod-cell';
const GROUP_P1_PROBE = 'p1-probe';

// Moleculer 0.14.34 defaults to a 10s heartbeat and 30s timeout, and checks
// remote nodes only once per timeout. Because expiry is tested with `>` rather
// than `>=`, those defaults can retain a dead endpoint for almost 60 seconds.
// ADSP's frozen recovery ceiling is 30 seconds, so supported distributed cells
// use a policy with substantial detection margin. Single-process mode preserves
// upstream defaults because it does not require horizontal failure detection.
const DEFAULT_DISTRIBUTED_HEARTBEAT_INTERVAL = 5;
const DEFAULT_DISTRIBUTED_HEARTBEAT_TIMEOUT = 10;
const MAX_DISTRIBUTED_HEARTBEAT_TIMEOUT = 12;

const VALID_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const VALID_REDIS_PROTOCOLS = new Set(['redis:', 'rediss:']);

function optionalString(value) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function validateIdentifier(value, label) {
  if (!VALID_IDENTIFIER.test(value)) {
    throw new Error(
      `${label} must be 1-128 characters and contain only letters, numbers, dot, underscore or hyphen`
    );
  }
  return value;
}

function validateRedisTransporterUrl(value) {
  const explicit = optionalString(value);
  if (!explicit) return undefined;

  let parsed;
  try {
    parsed = new URL(explicit);
  } catch {
    throw new Error('SEMAPPS_REDIS_TRANSPORTER_URL must be a valid redis:// or rediss:// URL');
  }

  if (!VALID_REDIS_PROTOCOLS.has(parsed.protocol) || !parsed.hostname) {
    throw new Error('SEMAPPS_REDIS_TRANSPORTER_URL must be a valid redis:// or rediss:// URL');
  }

  return explicit;
}

function parseMode(value) {
  const mode = optionalString(value) || MODE_SINGLE;
  if (mode !== MODE_SINGLE && mode !== MODE_DISTRIBUTED) {
    throw new Error(`Unsupported Moleculer fabric mode: ${mode}`);
  }
  return mode;
}

function parseServiceGroup(value) {
  const group = optionalString(value) || GROUP_POD_CELL;
  if (group !== GROUP_POD_CELL && group !== GROUP_P1_PROBE) {
    throw new Error(`Unsupported Moleculer service group: ${group}`);
  }
  return group;
}

function resolveNodeId(mode, value) {
  const explicit = optionalString(value);
  if (mode === MODE_SINGLE) {
    return explicit ? validateIdentifier(explicit, 'Moleculer node ID') : 'pod-provider';
  }
  if (!explicit) {
    throw new Error('Distributed Moleculer mode requires SEMAPPS_MOLECULER_NODE_ID');
  }
  const nodeId = validateIdentifier(explicit, 'Moleculer node ID');
  if (nodeId === 'pod-provider') {
    throw new Error('Distributed Moleculer mode requires a unique node ID, not the single-node default');
  }
  return nodeId;
}

function resolveNamespace(mode, value) {
  const explicit = optionalString(value);
  if (mode === MODE_SINGLE) {
    return explicit ? validateIdentifier(explicit, 'Moleculer namespace') : undefined;
  }
  if (!explicit) {
    throw new Error('Distributed Moleculer mode requires SEMAPPS_MOLECULER_NAMESPACE');
  }
  return validateIdentifier(explicit, 'Moleculer namespace');
}

function parsePositiveIntegerSeconds(value, label, fallback) {
  const explicit = optionalString(value);
  if (!explicit) return fallback;
  const parsed = Number(explicit);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer number of seconds`);
  }
  return parsed;
}

function resolveHeartbeatPolicy(mode, env) {
  if (mode !== MODE_DISTRIBUTED) {
    return { heartbeatInterval: undefined, heartbeatTimeout: undefined };
  }

  const heartbeatInterval = parsePositiveIntegerSeconds(
    env.SEMAPPS_MOLECULER_HEARTBEAT_INTERVAL,
    'SEMAPPS_MOLECULER_HEARTBEAT_INTERVAL',
    DEFAULT_DISTRIBUTED_HEARTBEAT_INTERVAL
  );
  const heartbeatTimeout = parsePositiveIntegerSeconds(
    env.SEMAPPS_MOLECULER_HEARTBEAT_TIMEOUT,
    'SEMAPPS_MOLECULER_HEARTBEAT_TIMEOUT',
    DEFAULT_DISTRIBUTED_HEARTBEAT_TIMEOUT
  );

  if (heartbeatTimeout <= heartbeatInterval) {
    throw new Error('Distributed Moleculer heartbeat timeout must be greater than heartbeat interval');
  }
  if (heartbeatInterval * 2 > heartbeatTimeout) {
    throw new Error('Distributed Moleculer heartbeat interval must be at most half of heartbeat timeout');
  }
  if (heartbeatTimeout > MAX_DISTRIBUTED_HEARTBEAT_TIMEOUT) {
    throw new Error(
      `Distributed Moleculer heartbeat timeout must be <= ${MAX_DISTRIBUTED_HEARTBEAT_TIMEOUT}s to preserve the frozen 30s recovery ceiling`
    );
  }

  return { heartbeatInterval, heartbeatTimeout };
}

function resolveServicePatterns(group) {
  if (group === GROUP_POD_CELL) {
    // A complete service cell, excluding helpers under services/utils.
    // Moleculer CLI interprets each entry as a glob. Loading utilities as
    // service schemas breaks startup because they have no service name.
    // Keep root service files and every non-utils subdirectory recursively.
    return ['services/*.js', 'services/!(utils)/**/*.js'];
  }
  return ['p1-fixtures/services/*.service.js'];
}

function createMoleculerFabricConfig(env = process.env) {
  const mode = parseMode(env.SEMAPPS_MOLECULER_MODE);
  const serviceGroup = parseServiceGroup(env.SEMAPPS_MOLECULER_SERVICE_GROUP);
  const nodeID = resolveNodeId(mode, env.SEMAPPS_MOLECULER_NODE_ID);
  const namespace = resolveNamespace(mode, env.SEMAPPS_MOLECULER_NAMESPACE);
  const transporterUrl = validateRedisTransporterUrl(env.SEMAPPS_REDIS_TRANSPORTER_URL);
  const heartbeat = resolveHeartbeatPolicy(mode, env);

  if (mode === MODE_DISTRIBUTED && !transporterUrl) {
    throw new Error('Distributed Moleculer mode requires SEMAPPS_REDIS_TRANSPORTER_URL in ADSP Phase 1');
  }

  return {
    mode,
    serviceGroup,
    nodeID,
    namespace,
    transporter: transporterUrl,
    heartbeatInterval: heartbeat.heartbeatInterval,
    heartbeatTimeout: heartbeat.heartbeatTimeout,
    // Pin Moleculer's local-first routing contract explicitly. Tightly coupled
    // services that exist inside the same Pod/SemApps cell must never take a
    // remote hop merely because another cell advertises the same action.
    registry: {
      preferLocal: true
    },
    // Keep RDF/JSON-LD serialization semantics identical regardless of whether
    // this broker currently has a transporter. Phase 1 must not couple semantic
    // behavior to the selected transporter technology.
    serializer: new RdfJSONSerializer(),
    servicePatterns: resolveServicePatterns(serviceGroup)
  };
}

module.exports = {
  DEFAULT_DISTRIBUTED_HEARTBEAT_INTERVAL,
  DEFAULT_DISTRIBUTED_HEARTBEAT_TIMEOUT,
  MAX_DISTRIBUTED_HEARTBEAT_TIMEOUT,
  MODE_SINGLE,
  MODE_DISTRIBUTED,
  GROUP_POD_CELL,
  GROUP_P1_PROBE,
  createMoleculerFabricConfig,
  resolveHeartbeatPolicy,
  resolveServicePatterns,
  validateRedisTransporterUrl
};

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { ServiceBroker } = require('moleculer');
const RdfJSONSerializer = require('../RdfJSONSerializer');

const DEFAULT_TRANSPORTER_URL = 'redis://redis:6379/12';
const DEFAULT_READY_TIMEOUT_MS = 120000;
const DEFAULT_TRACE_TIMEOUT_MS = 900000;
const ROOT_ACTION = 'activitypub.outbox.post';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function positiveInteger(value, label) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

function percentile(values, fraction) {
  if (!Array.isArray(values) || values.length === 0) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(fraction * sorted.length) - 1));
  return sorted[index];
}

function summarize(values) {
  return {
    count: values.length,
    p50: percentile(values, 0.5),
    p95: percentile(values, 0.95),
    p99: percentile(values, 0.99),
    min: values.length ? Math.min(...values) : undefined,
    max: values.length ? Math.max(...values) : undefined
  };
}

function readJsonLines(filePath) {
  if (!fs.existsSync(filePath)) return [];
  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split(/\r?\n/u);

  // Trace writers append one complete JSON object followed by a newline. A
  // concurrent reader can observe the final append between the object bytes
  // and its newline, so an unterminated trailing segment is not yet a
  // committed JSONL record. Ignore only that final segment until a later poll.
  // Any malformed newline-terminated record remains a hard evidence failure.
  if (content.length > 0 && !content.endsWith('\n')) lines.pop();

  return lines
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => JSON.parse(line));
}

function traceFilesFromEnv() {
  return String(process.env.ADSP_P2_TRACE_FILES || '')
    .split(',')
    .map(value => value.trim())
    .filter(Boolean)
    .map(value => path.resolve(value));
}

function executorName(traceFile) {
  const base = path.basename(traceFile);
  const match = base.match(/-(r\d+)\.jsonl$/u);
  return match ? match[1] : base;
}

function expectedExecutors(replicaCount) {
  return Array.from({ length: replicaCount }, (_, index) => `r${index + 1}`);
}

function assertExecutorCoverage(executorCounts, replicaCount, requestCount) {
  const expected = expectedExecutors(replicaCount);
  const actual = Object.keys(executorCounts || {}).sort();
  const total = Object.values(executorCounts || {}).reduce((sum, value) => sum + Number(value || 0), 0);
  if (total !== requestCount) throw new Error(`Executor accounting mismatch: expected ${requestCount}, observed ${total}`);
  const unexpected = actual.filter(name => !expected.includes(name));
  if (unexpected.length > 0) throw new Error(`Unexpected executor identity: ${unexpected.join(', ')}`);
  for (const executor of expected) {
    if (!Number.isInteger(Number(executorCounts[executor])) || Number(executorCounts[executor]) <= 0) {
      throw new Error(`Replica ${executor} executed no measured work`);
    }
  }
}

function findTraceMatches(traceFiles, requestId) {
  const matches = [];
  for (const traceFile of traceFiles) {
    for (const record of readJsonLines(traceFile)) {
      if (record?.requestId === requestId) matches.push({ traceFile, record });
    }
  }
  return matches;
}

async function waitForUniqueTrace(traceFiles, requestId, recipientCount, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const matches = findTraceMatches(traceFiles, requestId);
    if (matches.length > 1) {
      throw new Error(`Request ${requestId} produced duplicate measurement traces in ${matches.map(m => m.traceFile).join(', ')}`);
    }
    if (matches.length === 1) {
      const { traceFile, record } = matches[0];
      if (record.phase !== 'APDM-P8-A') throw new Error(`Request ${requestId} produced non-Phase-8 trace`);
      if (Number(record.recipientCount) !== recipientCount) {
        throw new Error(`Request ${requestId} trace recipient count ${record.recipientCount} != ${recipientCount}`);
      }
      if (Array.isArray(record.errors) && record.errors.length > 0) {
        throw new Error(`Request ${requestId} trace contains errors: ${JSON.stringify(record.errors)}`);
      }
      return { traceFile, record };
    }
    await sleep(50);
  }
  throw new Error(`Timed out waiting for unique completed trace for ${requestId}`);
}

function endpointCount(broker, actionName) {
  return broker.registry.getActionEndpoints(actionName)?.count?.() ?? 0;
}

async function waitForReplicaEndpoints(broker, expectedCount, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (endpointCount(broker, ROOT_ACTION) === expectedCount) return;
    await sleep(100);
  }
  throw new Error(`Expected ${expectedCount} ${ROOT_ACTION} endpoints, observed ${endpointCount(broker, ROOT_ACTION)}`);
}

function createRequestId(runLabel, index) {
  return `adsp-p2-${runLabel}-${index}-${crypto.randomBytes(6).toString('hex')}`;
}

function barrierPath(barrierDir, name) {
  return path.join(barrierDir, name);
}

function signalBarrier(barrierDir, name) {
  if (!barrierDir) return;
  fs.mkdirSync(barrierDir, { recursive: true });
  const target = barrierPath(barrierDir, name);
  const temporary = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${Date.now()}\n`, 'utf8');
  fs.renameSync(temporary, target);
}

async function waitForBarrier(barrierDir, name, timeoutMs) {
  if (!barrierDir) return;
  const target = barrierPath(barrierDir, name);
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(target)) return;
    await sleep(25);
  }
  throw new Error(`Timed out waiting for ADSP P2 barrier ${name}`);
}

async function runWindow({
  manifest,
  recipientCount,
  replicaCount,
  requestCount,
  concurrency,
  traceFiles,
  transporterUrl,
  namespace,
  readyTimeoutMs,
  traceTimeoutMs,
  runLabel,
  barrierDir
}) {
  if (!namespace) throw new Error('ADSP P2 load driver requires SEMAPPS_MOLECULER_NAMESPACE or ADSP_P2_NAMESPACE');
  if (traceFiles.length !== replicaCount) {
    throw new Error(`Expected ${replicaCount} trace files, got ${traceFiles.length}`);
  }
  if (requestCount < replicaCount) {
    throw new Error(`request count ${requestCount} cannot prove measured execution across ${replicaCount} replicas`);
  }
  if (!manifest?.sender?.outbox || !manifest?.sender?.webId || !manifest?.sender?.username) {
    throw new Error('Actor manifest is missing sender authority fields');
  }
  if (!Array.isArray(manifest.recipients) || manifest.recipients.length < recipientCount) {
    throw new Error(`Actor manifest contains fewer than ${recipientCount} recipients`);
  }
  if (concurrency > requestCount) concurrency = requestCount;

  for (const traceFile of traceFiles) fs.rmSync(traceFile, { force: true });
  if (barrierDir) {
    fs.mkdirSync(barrierDir, { recursive: true });
    for (const name of ['ready', 'go', 'done', 'release']) fs.rmSync(barrierPath(barrierDir, name), { force: true });
  }

  const recipients = manifest.recipients.slice(0, recipientCount).map(recipient => recipient.webId);
  if (recipients.some(value => typeof value !== 'string' || !value)) throw new Error('Recipient manifest contains invalid WebIDs');

  const broker = new ServiceBroker({
    nodeID: `adsp-p2-load-${process.pid}-${Date.now()}`,
    namespace,
    transporter: transporterUrl,
    serializer: new RdfJSONSerializer(),
    logger: false,
    requestTimeout: traceTimeoutMs,
    retryPolicy: { enabled: false },
    registry: { preferLocal: true }
  });

  await broker.start();
  try {
    await waitForReplicaEndpoints(broker, replicaCount, readyTimeoutMs);
    if (barrierDir) {
      signalBarrier(barrierDir, 'ready');
      await waitForBarrier(barrierDir, 'go', readyTimeoutMs);
    }

    const results = new Array(requestCount);
    let cursor = 0;
    const startedPerfMs = performance.now();

    // eslint-disable-next-line no-inner-declarations -- Block-scoped functions are supported by the required modern Node runtime.
    async function worker(workerIndex) {
      for (;;) {
        const index = cursor;
        cursor += 1;
        if (index >= requestCount) return;
        const requestId = createRequestId(runLabel, index + 1);
        const requestStarted = performance.now();
        const result = await broker.call(
          ROOT_ACTION,
          {
            collectionUri: manifest.sender.outbox,
            type: 'Create',
            actor: manifest.sender.webId,
            to: recipients,
            object: {
              type: 'Note',
              content: `ADSP P2 horizontal Redis ${runLabel} request ${index + 1}`
            }
          },
          {
            meta: { webId: manifest.sender.webId, dataset: manifest.sender.username },
            requestID: requestId,
            timeout: traceTimeoutMs
          }
        );
        const actionReturnedMs = performance.now() - requestStarted;
        if (!result?.id) throw new Error(`Request ${requestId} did not persist an Activity`);

        const traced = await waitForUniqueTrace(traceFiles, requestId, recipientCount, traceTimeoutMs);
        const completedMs = performance.now() - requestStarted;
        results[index] = {
          requestId,
          workerIndex,
          activityId: result.id,
          executor: executorName(traced.traceFile),
          actionReturnedMs,
          completedMs,
          traceElapsedMs: Number(traced.record.elapsedMs),
          traceCpuMs: Number(traced.record.cpuUserMs || 0) + Number(traced.record.cpuSystemMs || 0),
          traceHeapUsedEnd: Number(traced.record.heapUsedEnd),
          traceHeapTotalEnd: Number(traced.record.heapTotalEnd),
          traceRssEnd: Number(traced.record.rssEnd),
          actionCount: Number(traced.record.actionCount),
          fusekiRequestCount: Number(traced.record.fuseki?.requestCount || 0)
        };
      }
    }

    await Promise.all(Array.from({ length: concurrency }, (_, index) => worker(index + 1)));
    const wallMs = performance.now() - startedPerfMs;

    const requestIds = new Set(results.map(result => result.requestId));
    const activityIds = new Set(results.map(result => result.activityId));
    if (requestIds.size !== requestCount) throw new Error('Duplicate request IDs in completed window');
    if (activityIds.size !== requestCount) throw new Error('Duplicate persisted Activity IDs in completed window');

    const executorCounts = Object.create(null);
    for (const result of results) executorCounts[result.executor] = (executorCounts[result.executor] || 0) + 1;
    assertExecutorCoverage(executorCounts, replicaCount, requestCount);

    const windowResult = {
      version: 1,
      phase: 'ADSP-P2-A',
      fixture: 'tier1-horizontal-local-fanout',
      runLabel,
      namespace,
      transporter: 'redis',
      replicaCount,
      recipientCount,
      requestCount,
      concurrency,
      successfulOutcomes: requestCount,
      failedOutcomes: 0,
      duplicateRequestIds: 0,
      duplicateActivityIds: 0,
      wallMs,
      throughputPerSecond: requestCount / (wallMs / 1000),
      actionReturnedMs: summarize(results.map(result => result.actionReturnedMs)),
      completedMs: summarize(results.map(result => result.completedMs)),
      traceElapsedMs: summarize(results.map(result => result.traceElapsedMs)),
      executorCounts,
      results
    };

    if (barrierDir) {
      signalBarrier(barrierDir, 'done');
      await waitForBarrier(barrierDir, 'release', readyTimeoutMs);
    }
    return windowResult;
  } finally {
    await broker.stop().catch(() => undefined);
  }
}

async function main(argv = process.argv.slice(2)) {
  const manifestPath = path.resolve(argv[0] || '');
  const recipientCount = positiveInteger(argv[1], 'recipient count');
  const replicaCount = positiveInteger(argv[2], 'replica count');
  const requestCount = positiveInteger(argv[3], 'request count');
  const concurrency = positiveInteger(argv[4], 'concurrency');
  const outputPath = path.resolve(argv[5] || '');
  if (!argv[0] || !argv[5]) {
    throw new Error('Usage: adsp-p2-horizontal-load.js <manifest> <recipientCount> <replicas> <requests> <concurrency> <output.json>');
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const traceFiles = traceFilesFromEnv();
  const namespace = process.env.SEMAPPS_MOLECULER_NAMESPACE || process.env.ADSP_P2_NAMESPACE;
  const barrierDir = process.env.ADSP_P2_BARRIER_DIR ? path.resolve(process.env.ADSP_P2_BARRIER_DIR) : undefined;
  const result = await runWindow({
    manifest,
    recipientCount,
    replicaCount,
    requestCount,
    concurrency,
    traceFiles,
    transporterUrl: process.env.SEMAPPS_REDIS_TRANSPORTER_URL || DEFAULT_TRANSPORTER_URL,
    namespace,
    readyTimeoutMs: positiveInteger(process.env.ADSP_P2_READY_TIMEOUT_MS || DEFAULT_READY_TIMEOUT_MS, 'ready timeout'),
    traceTimeoutMs: positiveInteger(process.env.ADSP_P2_TRACE_TIMEOUT_MS || DEFAULT_TRACE_TIMEOUT_MS, 'trace timeout'),
    runLabel: process.env.ADSP_P2_RUN_LABEL || `${replicaCount}r-${recipientCount}n`,
    barrierDir
  });

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({ ok: true, outputPath, throughputPerSecond: result.throughputPerSecond, executorCounts: result.executorCounts })}\n`);
}

if (require.main === module) {
  main().catch(error => {
    console.error(`[ADSP-P2] ${error.stack || error.message || String(error)}`);
    process.exit(1);
  });
}

module.exports = {
  assertExecutorCoverage,
  barrierPath,
  executorName,
  expectedExecutors,
  findTraceMatches,
  percentile,
  readJsonLines,
  runWindow,
  signalBarrier,
  summarize,
  waitForBarrier,
  waitForUniqueTrace
};

'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const { AsyncLocalStorage } = require('async_hooks');
const { performance } = require('perf_hooks');

const DEFAULT_ROOT_ACTION = 'activitypub.outbox.post';
const DEFAULT_OUTPUT = path.resolve(process.cwd(), 'apdm-phase8-tier1.jsonl');
const PATCH_MARKER = Symbol.for('semapps-atproto.apdm-p8.http-probe');
const LOCAL_DELIVERY_OBSERVER_SYMBOL_KEY = 'semapps-atproto.apdm-p8.local-delivery-observer';
const LOCAL_DELIVERY_RESULT_OBSERVER_SYMBOL_KEY = 'semapps-atproto.apdm-p8.local-delivery-result-observer';

function normalizeUrl(value) {
  if (!value) return undefined;
  try {
    return new URL(value);
  } catch (_error) {
    return undefined;
  }
}

function classifyAction(name) {
  if (!name) return 'unknown';
  if (name.startsWith('webacl.')) return 'webacl';
  if (name.startsWith('ldp.')) return 'ldp';
  if (name.startsWith('triplestore.') || name.startsWith('sparqlEndpoint.')) return 'triplestore';
  if (name.startsWith('activitypub.')) return 'activitypub';
  if (name.startsWith('auth.')) return 'auth';
  return 'other';
}

function increment(map, key, amount = 1) {
  map[key] = (map[key] || 0) + amount;
}

function createTrace({ requestId, recipientCount, caseLabel }) {
  const memory = process.memoryUsage();
  return {
    version: 1,
    phase: 'APDM-P8-A',
    requestId,
    caseLabel,
    recipientCount: Number.isFinite(recipientCount) ? recipientCount : undefined,
    startedAt: new Date().toISOString(),
    startedPerfMs: performance.now(),
    cpuStart: process.cpuUsage(),
    heapUsedStart: memory.heapUsed,
    heapTotalStart: memory.heapTotal,
    rssStart: memory.rss,
    actionCount: 0,
    actionCounts: Object.create(null),
    categoryCounts: Object.create(null),
    actionDurationsMs: Object.create(null),
    pendingDetachedLocalDeliveries: 0,
    rootSettled: false,
    rootError: undefined,
    finalized: false,
    fuseki: {
      requestCount: 0,
      methodCounts: Object.create(null),
      statusCounts: Object.create(null),
      pathCounts: Object.create(null),
      requestKeyCounts: Object.create(null),
      totalDurationMs: 0
    },
    errors: []
  };
}

function finishTrace(trace, error) {
  const memory = process.memoryUsage();
  const cpu = process.cpuUsage(trace.cpuStart);
  const elapsedMs = performance.now() - trace.startedPerfMs;
  if (error) {
    trace.errors.push({
      source: 'root-action',
      name: error.name || 'Error',
      message: error.message || String(error)
    });
  }

  return {
    version: trace.version,
    phase: trace.phase,
    requestId: trace.requestId,
    caseLabel: trace.caseLabel,
    recipientCount: trace.recipientCount,
    startedAt: trace.startedAt,
    finishedAt: new Date().toISOString(),
    elapsedMs,
    cpuUserMs: cpu.user / 1000,
    cpuSystemMs: cpu.system / 1000,
    heapUsedStart: trace.heapUsedStart,
    heapUsedEnd: memory.heapUsed,
    heapUsedDelta: memory.heapUsed - trace.heapUsedStart,
    heapTotalStart: trace.heapTotalStart,
    heapTotalEnd: memory.heapTotal,
    rssStart: trace.rssStart,
    rssEnd: memory.rss,
    actionCount: trace.actionCount,
    actionCounts: trace.actionCounts,
    categoryCounts: trace.categoryCounts,
    actionDurationsMs: trace.actionDurationsMs,
    fuseki: trace.fuseki,
    errors: trace.errors
  };
}

function writeJsonLine(outputPath, record) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.appendFileSync(outputPath, `${JSON.stringify(record)}\n`, 'utf8');
}

function tryWriteJsonLine(outputPath, record, onInstrumentationError = () => {}) {
  try {
    writeJsonLine(outputPath, record);
    return true;
  } catch (error) {
    try {
      onInstrumentationError(error);
    } catch (_ignored) {
      // Measurement reporting is not allowed to affect delivery semantics.
    }
    return false;
  }
}

function getRequestTarget(args, protocol) {
  if (args.length === 0) return undefined;
  const [first] = args;

  if (first instanceof URL) return first;
  if (typeof first === 'string') return normalizeUrl(first);

  if (first && typeof first === 'object') {
    if (first.href) return normalizeUrl(first.href);
    let hostname = first.hostname || first.host;
    if (!hostname) return undefined;
    hostname = String(hostname);
    const portAlreadyIncluded = !first.hostname && first.port && hostname.endsWith(`:${first.port}`);
    if (hostname.includes(':') && !hostname.startsWith('[') && !portAlreadyIncluded) hostname = `[${hostname}]`;
    const scheme = first.protocol || `${protocol}:`;
    const port = first.port && !portAlreadyIncluded ? `:${first.port}` : '';
    const requestPath = first.path || first.pathname || '/';
    return normalizeUrl(`${scheme}//${hostname}${port}${requestPath}`);
  }

  return undefined;
}

function getRequestMethod(args) {
  // Node supports request(url, options), request(URL, options), and
  // request(options). A legacy URL/options descriptor can itself be an object,
  // so taking the first object argument can accidentally ignore a later explicit
  // { method: 'DELETE' } and misclassify it as the default GET. Prefer the first
  // non-URL object that actually declares a method; otherwise HTTP defaults GET.
  const explicitMethodOptions = args.find(
    value =>
      value &&
      typeof value === 'object' &&
      !(value instanceof URL) &&
      typeof value.method === 'string' &&
      value.method.length > 0
  );
  return String((explicitMethodOptions && explicitMethodOptions.method) || 'GET').toUpperCase();
}

function targetMatchesFuseki(target, fusekiTargets) {
  if (!target) return false;
  return fusekiTargets.some(candidate => {
    if (!candidate) return false;
    if (candidate.origin !== target.origin) return false;
    const prefix = candidate.pathname.replace(/\/$/u, '');
    if (prefix === '') return true;
    return target.pathname === prefix || target.pathname.startsWith(`${prefix}/`);
  });
}

function installFusekiHttpProbe({ storage, fusekiUrls = [] }) {
  const targets = fusekiUrls.map(normalizeUrl).filter(Boolean);
  if (targets.length === 0) return () => {};

  const restorers = [];
  for (const transport of [http, https]) {
    if (transport[PATCH_MARKER]) continue;
    const originalRequest = transport.request;

    // eslint-disable-next-line no-inner-declarations -- Block-scoped functions are supported by the required modern Node runtime.
    function instrumentedRequest(...args) {
      const trace = storage.getStore();
      const target = getRequestTarget(args, transport === https ? 'https' : 'http');
      if (!trace || !targetMatchesFuseki(target, targets)) {
        return originalRequest.apply(this, args);
      }

      const method = getRequestMethod(args);
      const started = performance.now();
      trace.fuseki.requestCount += 1;
      increment(trace.fuseki.methodCounts, method);
      increment(trace.fuseki.pathCounts, target.pathname);
      increment(trace.fuseki.requestKeyCounts, `${method} ${target.pathname}`);

      const request = originalRequest.apply(this, args);
      request.once('response', response => {
        increment(trace.fuseki.statusCounts, String(response.statusCode || 'unknown'));
        response.once('end', () => {
          trace.fuseki.totalDurationMs += performance.now() - started;
        });
      });
      request.once('error', error => {
        trace.fuseki.totalDurationMs += performance.now() - started;
        trace.errors.push({ source: 'fuseki-http', name: error.name || 'Error', message: error.message || String(error) });
      });
      return request;
    }

    transport.request = instrumentedRequest;
    transport[PATCH_MARKER] = { originalRequest };
    restorers.push(() => {
      const state = transport[PATCH_MARKER];
      if (state && transport.request === instrumentedRequest) transport.request = state.originalRequest;
      delete transport[PATCH_MARKER];
    });
  }

  return () => {
    for (const restore of restorers.reverse()) restore();
  };
}

function createPhase8Tier1Instrumentation(options = {}) {
  const enabled = options.enabled === true;
  if (!enabled) {
    return {
      middleware: null,
      dispose() {}
    };
  }

  const storage = new AsyncLocalStorage();
  const rootAction = options.rootAction || DEFAULT_ROOT_ACTION;
  const outputPath = path.resolve(options.outputPath || DEFAULT_OUTPUT);
  const defaultRecipientCount = Number(options.recipientCount);
  const caseLabel = options.caseLabel || undefined;
  const onInstrumentationError =
    typeof options.onInstrumentationError === 'function' ? options.onInstrumentationError : () => {};
  const restoreHttp = installFusekiHttpProbe({
    storage,
    fusekiUrls: [options.fusekiBase, options.sparqlEndpoint].filter(Boolean)
  });

  function reportInstrumentationError(error) {
    try {
      onInstrumentationError(error);
    } catch (_ignored) {
      // Instrumentation callbacks must never block the real delivery path.
    }
  }

  function maybeFinalizeTrace(trace) {
    if (!trace || trace.finalized || !trace.rootSettled || trace.pendingDetachedLocalDeliveries > 0) return false;
    trace.finalized = true;
    try {
      const record = finishTrace(trace, trace.rootError);
      tryWriteJsonLine(outputPath, record, reportInstrumentationError);
    } catch (error) {
      reportInstrumentationError(error);
    }
    return true;
  }

  const observerKey = Symbol.for(LOCAL_DELIVERY_OBSERVER_SYMBOL_KEY);
  const resultObserverKey = Symbol.for(LOCAL_DELIVERY_RESULT_OBSERVER_SYMBOL_KEY);
  const previousLocalDeliveryObserver = globalThis[observerKey];
  const previousLocalDeliveryResultObserver = globalThis[resultObserverKey];

  const localDeliveryObserver = (phase, _activity, error) => {
    const trace = storage.getStore();
    if (!trace) return;

    if (phase === 'start') {
      trace.pendingDetachedLocalDeliveries += 1;
      return;
    }

    if (phase === 'finish') {
      if (error) {
        trace.errors.push({
          source: 'detached-local-delivery',
          name: error.name || 'Error',
          message: error.message || String(error)
        });
      }
      trace.pendingDetachedLocalDeliveries = Math.max(0, trace.pendingDetachedLocalDeliveries - 1);
      maybeFinalizeTrace(trace);
    }
  };

  const localDeliveryResultObserver = (_activity, result) => {
    const trace = storage.getStore();
    if (!trace || !result) return;

    const successes = Array.isArray(result.success) ? result.success : [];
    const failures = Array.isArray(result.failures) ? result.failures : [];

    if (failures.length > 0) {
      trace.errors.push({
        source: 'detached-local-delivery-partial',
        failureCount: failures.length,
        failures: [...failures]
      });
    }

    if (Number.isInteger(trace.recipientCount) && trace.recipientCount > 0 && successes.length !== trace.recipientCount) {
      trace.errors.push({
        source: 'detached-local-delivery-count-mismatch',
        expectedRecipientCount: trace.recipientCount,
        successfulRecipientCount: successes.length,
        failureCount: failures.length
      });
    }
  };

  globalThis[observerKey] = localDeliveryObserver;
  globalThis[resultObserverKey] = localDeliveryResultObserver;

  const middleware = {
    name: 'APDMPhase8Tier1Instrumentation',
    localAction(next, action) {
      const actionName = action && action.name;
      return async function apdmPhase8InstrumentedAction(ctx) {
        const currentTrace = storage.getStore();
        const isRoot = actionName === rootAction && !currentTrace;
        let trace = currentTrace;

        if (isRoot) {
          try {
            trace = createTrace({
              requestId: (ctx && (ctx.requestID || ctx.id)) || `apdm-p8-${Date.now()}`,
              recipientCount: defaultRecipientCount,
              caseLabel
            });
          } catch (error) {
            reportInstrumentationError(error);
            return next(ctx);
          }
        }

        if (!trace) return next(ctx);

        const started = performance.now();
        trace.actionCount += 1;
        increment(trace.actionCounts, actionName || 'unknown');
        increment(trace.categoryCounts, classifyAction(actionName));

        const invoke = async () => {
          try {
            return await next(ctx);
          } catch (error) {
            trace.errors.push({
              source: 'moleculer-action',
              action: actionName || 'unknown',
              name: error.name || 'Error',
              message: error.message || String(error)
            });
            throw error;
          } finally {
            increment(trace.actionDurationsMs, actionName || 'unknown', performance.now() - started);
          }
        };

        if (!isRoot) return invoke();

        try {
          return await storage.run(trace, invoke);
        } catch (error) {
          trace.rootError = error;
          throw error;
        } finally {
          trace.rootSettled = true;
          maybeFinalizeTrace(trace);
        }
      };
    }
  };

  return {
    middleware,
    outputPath,
    dispose() {
      restoreHttp();
      if (globalThis[observerKey] === localDeliveryObserver) {
        if (previousLocalDeliveryObserver === undefined) delete globalThis[observerKey];
        else globalThis[observerKey] = previousLocalDeliveryObserver;
      }
      if (globalThis[resultObserverKey] === localDeliveryResultObserver) {
        if (previousLocalDeliveryResultObserver === undefined) delete globalThis[resultObserverKey];
        else globalThis[resultObserverKey] = previousLocalDeliveryResultObserver;
      }
      storage.disable();
    }
  };
}

module.exports = {
  DEFAULT_ROOT_ACTION,
  DEFAULT_OUTPUT,
  LOCAL_DELIVERY_OBSERVER_SYMBOL_KEY,
  LOCAL_DELIVERY_RESULT_OBSERVER_SYMBOL_KEY,
  classifyAction,
  createTrace,
  finishTrace,
  createPhase8Tier1Instrumentation,
  getRequestMethod,
  installFusekiHttpProbe,
  normalizeUrl,
  targetMatchesFuseki,
  tryWriteJsonLine,
  writeJsonLine
};

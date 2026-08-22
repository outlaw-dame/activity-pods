'use strict';

const crypto = require('crypto');
const { ServiceBroker } = require('moleculer');
const {
  awaitActorBootstrap,
  normalizeRunId,
  signupWithCandidateRetries
} = require('./apdm-phase8-real-measure');
const { validateDeliveryPlanV1 } = require('../utils/activitypub-delivery-plan');

const DEFAULT_BASE_URL = 'http://127.0.0.1:3000';
const DEFAULT_TRANSPORTER_URL = 'redis://127.0.0.1:6379/12';
const DEFAULT_READY_TIMEOUT_MS = 120_000;
const MAX_PROOF_SUMMARY_BYTES = 64 * 1024;
const REMOTE_DELIVERY_PLANNED_EVENT = 'activitypub.outbox.remote-delivery.handoff-queued';

function normalizeEntityId(value) {
  if (typeof value === 'string' && value.length > 0) return value;
  if (value && typeof value === 'object' && !Array.isArray(value)) return value.id || value['@id'] || null;
  return null;
}

function validateRemoteActorUri(value) {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error('remote actor URI must be a non-empty, whitespace-free HTTP(S) URL');
  }
  const parsed = new URL(value);
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) {
    throw new Error('remote actor URI must be a credential-free HTTP(S) URL without a fragment');
  }
  return parsed.toString();
}

function positiveInteger(value, fallback, label) {
  const parsed = Number(value === undefined ? fallback : value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

function boundedNonNegativeInteger(value, fallback, maximum, label) {
  const parsed = Number(value === undefined ? fallback : value);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > maximum) {
    throw new Error(`${label} must be an integer between 0 and ${maximum}`);
  }
  return parsed;
}

function createProofSummary(bytes) {
  if (bytes === 0) return undefined;
  const seed = 'activitypods-sidecar-compression-proof|';
  return seed.repeat(Math.ceil(bytes / seed.length)).slice(0, bytes);
}

function createRunnerBroker(transporterUrl, runId) {
  return new ServiceBroker({
    nodeID: `ap-federation-follow-${normalizeRunId(runId)}-${process.pid}`,
    logger: false,
    transporter: transporterUrl,
    requestTimeout: DEFAULT_READY_TIMEOUT_MS,
    retryPolicy: { enabled: false }
  });
}

function createExternalHandoffLatch(broker, senderRef, remoteActorUri, timeoutMs) {
  let resolvePromise;
  let rejectPromise;
  let timer;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  broker.createService({
    name: `ap-federation-follow-evidence-${crypto.randomBytes(6).toString('hex')}`,
    events: {
      [REMOTE_DELIVERY_PLANNED_EVENT]: {
        handler(ctx) {
          const activity = ctx?.params?.activity;
          if (!senderRef.value || normalizeEntityId(activity?.actor) !== senderRef.value || activity?.type !== 'Follow') return;
          const objectId = normalizeEntityId(activity?.object);
          if (objectId !== remoteActorUri) return;
          if (timer) clearTimeout(timer);
          resolvePromise(ctx.params);
        }
      }
    }
  });

  return {
    promise,
    arm() {
      timer = setTimeout(
        () => rejectPromise(new Error(`Timed out waiting for ${REMOTE_DELIVERY_PLANNED_EVENT}`)),
        timeoutMs
      );
    },
    cancel() {
      if (timer) clearTimeout(timer);
    }
  };
}

function extractExternalDeliveryTarget({ handoff, postResult, senderWebId, remoteActorUri }) {
  const deliveryPlan = handoff?.deliveryPlan;
  if (!validateDeliveryPlanV1(deliveryPlan)) {
    throw new Error('external mode did not emit a valid authoritative ap.delivery-plan.v1');
  }
  if (
    deliveryPlan.activityId !== postResult.id ||
    deliveryPlan.activity?.id !== postResult.id ||
    normalizeEntityId(handoff?.activity?.id) !== postResult.id
  ) {
    throw new Error('external Delivery Plan does not match the persisted Follow activity');
  }
  if (
    deliveryPlan.actorUri !== senderWebId ||
    normalizeEntityId(deliveryPlan.activity?.actor) !== senderWebId ||
    normalizeEntityId(handoff?.activity?.actor) !== senderWebId
  ) {
    throw new Error('external Delivery Plan does not match the sender authority');
  }
  if (!Array.isArray(deliveryPlan.localRecipients) || deliveryPlan.localRecipients.length !== 0) {
    throw new Error('external federation proof unexpectedly planned local recipients');
  }
  if (!Array.isArray(deliveryPlan.remoteRecipients) || deliveryPlan.remoteRecipients.length !== 1) {
    throw new Error('external federation proof requires exactly one authoritative remote recipient');
  }
  const target = deliveryPlan.remoteRecipients[0];
  if (target.actorUri !== remoteActorUri) {
    throw new Error('external Delivery Plan recipient does not match the requested remote actor');
  }
  if (
    !Array.isArray(handoff?.remoteRecipients) ||
    handoff.remoteRecipients.length !== 1 ||
    handoff.remoteRecipients[0] !== remoteActorUri
  ) {
    throw new Error('external handoff recipient evidence does not match the authoritative Delivery Plan');
  }

  return {
    actorUri: target.actorUri,
    inboxUrl: target.inboxUrl,
    ...(target.sharedInboxUrl ? { sharedInboxUrl: target.sharedInboxUrl } : {}),
    targetDomain: target.targetDomain,
    deliveryUrl: target.sharedInboxUrl || target.inboxUrl
  };
}

async function run({ remoteActorUri, mode, runId }) {
  const normalizedRemoteActorUri = validateRemoteActorUri(remoteActorUri);
  if (!['native', 'external'].includes(mode)) throw new Error(`unsupported mode ${mode}`);

  const baseUrl = process.env.AP_FEDERATION_BACKEND_BASE_URL || DEFAULT_BASE_URL;
  const transporterUrl = process.env.SEMAPPS_REDIS_TRANSPORTER_URL || DEFAULT_TRANSPORTER_URL;
  const readyTimeoutMs = positiveInteger(
    process.env.AP_FEDERATION_READY_TIMEOUT_MS,
    DEFAULT_READY_TIMEOUT_MS,
    'ready timeout'
  );
  const proofSummaryBytes = boundedNonNegativeInteger(
    process.env.AP_FEDERATION_PROOF_SUMMARY_BYTES,
    0,
    MAX_PROOF_SUMMARY_BYTES,
    'proof summary bytes'
  );
  const proofSummary = createProofSummary(proofSummaryBytes);
  const broker = createRunnerBroker(transporterUrl, runId);
  const senderRef = { value: null };
  const latch = createExternalHandoffLatch(broker, senderRef, normalizedRemoteActorUri, readyTimeoutMs);

  await broker.start();
  try {
    await broker.waitForServices(['auth', 'activitypub.outbox', 'activitypub.actor'], readyTimeoutMs);
    const password = `${crypto.randomBytes(24).toString('base64url')}A1!`;
    const sender = await signupWithCandidateRetries({
      baseUrl,
      password,
      runId,
      role: `federation-${mode}`
    });
    await awaitActorBootstrap(broker, sender, 'outbox', readyTimeoutMs);
    senderRef.value = sender.webId;

    if (mode === 'external') latch.arm();

    const postPromise = broker.call(
      'activitypub.outbox.post',
      {
        collectionUri: sender.outbox,
        type: 'Follow',
        actor: sender.webId,
        object: normalizedRemoteActorUri,
        to: [normalizedRemoteActorUri],
        ...(proofSummary === undefined ? {} : { summary: proofSummary })
      },
      {
        meta: { webId: sender.webId, dataset: sender.username },
        requestID: `ap-federation-follow-${crypto.randomBytes(12).toString('hex')}`
      }
    );

    const [postResult, handoff] = mode === 'external'
      ? await Promise.all([postPromise, latch.promise])
      : [await postPromise, null];

    if (
      !postResult ||
      typeof postResult.id !== 'string' ||
      normalizeEntityId(postResult.actor) !== sender.webId ||
      normalizeEntityId(postResult.object) !== normalizedRemoteActorUri
    ) {
      throw new Error('ActivityPods outbox did not persist the expected Follow activity');
    }
    if (proofSummary !== undefined && postResult.summary !== proofSummary) {
      throw new Error('ActivityPods outbox did not persist the exact federation proof summary');
    }

    let remoteDeliveryTarget;
    if (mode === 'external') {
      if (handoff?.deliveryMode !== 'external' || handoff?.durableHandoffQueued !== true) {
        throw new Error('external mode did not prove durable sidecar handoff');
      }
      if (handoff?.suppressedNativeRemotePostCount !== 1) {
        throw new Error('external mode did not suppress exactly one native remotePost');
      }
      remoteDeliveryTarget = extractExternalDeliveryTarget({
        handoff,
        postResult,
        senderWebId: sender.webId,
        remoteActorUri: normalizedRemoteActorUri
      });
    }

    return {
      schema: 'activitypods.activitypub.federation-follow-proof.v1',
      ok: true,
      mode,
      activityId: postResult.id,
      actorUri: sender.webId,
      senderUsername: sender.username,
      senderOutbox: sender.outbox,
      remoteActorUri: normalizedRemoteActorUri,
      proofSummaryBytes,
      durableHandoffQueued: mode === 'external',
      nativeRemotePostSuppressed: mode === 'external',
      ...(remoteDeliveryTarget ? { remoteDeliveryTarget } : {})
    };
  } finally {
    latch.cancel();
    await broker.stop();
  }
}

async function main(argv = process.argv.slice(2)) {
  if (argv.length !== 2) {
    throw new Error('Usage: node scripts/activitypub-federation-follow-proof.js <native|external> <remoteActorUri>');
  }
  const [mode, remoteActorUri] = argv;
  const runId = process.env.AP_FEDERATION_RUN_ID || `${Date.now()}-${mode}`;
  const result = await run({ mode, remoteActorUri, runId });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (require.main === module) {
  main().catch(error => {
    console.error(`[AP-FEDERATION] ${error.stack || error.message || String(error)}`);
    process.exit(1);
  });
}

module.exports = {
  boundedNonNegativeInteger,
  createProofSummary,
  createRunnerBroker,
  extractExternalDeliveryTarget,
  normalizeEntityId,
  run,
  validateRemoteActorUri
};

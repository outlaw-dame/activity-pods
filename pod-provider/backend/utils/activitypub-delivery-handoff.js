'use strict';

const { readBoundedAcknowledgement } = require('./activitypub-webhook-ack');
const DELIVERY_HANDOFF_QUEUE = 'deliveryHandoff';
const DELIVERY_HANDOFF_JOB_NAME = 'apdm-delivery-handoff-v1';

const DELIVERY_HANDOFF_QUEUE_OPTIONS =
  process.env.NODE_ENV === 'test'
    ? {}
    : {
        removeOnComplete: { age: 259200 },
        attempts: 12,
        backoff: { type: 'exponential', delay: 30000 }
      };

function assertDurableHandoffConfigured(settings) {
  if (!settings || typeof settings.queueServiceUrl !== 'string' || settings.queueServiceUrl.trim().length === 0) {
    throw new Error('APDM external delivery requires SEMAPPS_QUEUE_SERVICE_URL for durable handoff');
  }
  if (typeof settings.deliveryHandoffUrl !== 'string' || settings.deliveryHandoffUrl.trim().length === 0) {
    throw new Error('APDM external delivery requires a sidecar durable outbox handoff URL');
  }
  let url;
  try {
    url = new URL(settings.deliveryHandoffUrl);
  } catch {
    throw new Error('APDM sidecar durable outbox handoff URL must be valid HTTP(S)');
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('APDM sidecar durable outbox handoff URL must be valid HTTP(S)');
  }
  if (url.username || url.password || url.hash || url.href !== settings.deliveryHandoffUrl) {
    throw new Error('APDM handoff URL must be canonical and contain no embedded credentials or fragment');
  }
  if (typeof settings.deliveryHandoffToken !== 'string' || settings.deliveryHandoffToken.length === 0) {
    throw new Error('APDM external delivery requires SIDECAR_TOKEN for authenticated durable handoff');
  }
}

function toSidecarOutboxPayload(deliveryPlan) {
  const apdmAuthority = {
    schema: deliveryPlan.schema,
    intentId: deliveryPlan.intentId
  };

  return {
    actorUri: deliveryPlan.actorUri,
    activityId: deliveryPlan.activityId,
    activity: deliveryPlan.activity,
    remoteTargets: deliveryPlan.remoteRecipients.map(target => ({
      inboxUrl: target.inboxUrl,
      ...(target.sharedInboxUrl ? { sharedInboxUrl: target.sharedInboxUrl } : {}),
      targetDomain: target.targetDomain,
      // Phase 6 wire proof: the sidecar target normalizer rejects legacy raw
      // routing submissions that do not carry one consistent Delivery Plan
      // authority marker across every target. This is transport metadata only;
      // it is not added to ap.delivery-plan.v1 itself.
      apdmAuthority
    })),
    meta: {
      ...deliveryPlan.meta,
      deliveryPlanIntentId: deliveryPlan.intentId,
      deliveryPlanSchema: deliveryPlan.schema
    }
  };
}

async function enqueueDeliveryHandoff(service, deliveryPlan) {
  assertDurableHandoffConfigured(service.settings);
  if (!deliveryPlan || typeof deliveryPlan.intentId !== 'string' || deliveryPlan.intentId.length === 0) {
    throw new Error('Durable ActivityPub handoff requires a Delivery Plan intentId');
  }

  // moleculer-bull createJob(queue, name, data, opts) passes the second
  // argument to Bull as the job *name*. Dedupe/uniqueness is controlled by
  // opts.jobId, so the deterministic Delivery Plan ID must live there.
  const options = {
    ...DELIVERY_HANDOFF_QUEUE_OPTIONS,
    jobId: deliveryPlan.intentId
  };
  const result = service.createJob(
    DELIVERY_HANDOFF_QUEUE,
    DELIVERY_HANDOFF_JOB_NAME,
    { deliveryPlan },
    options
  );
  await Promise.resolve(result);
  return deliveryPlan.intentId;
}

async function processDeliveryHandoffJob(service, job, fetchImpl = fetch) {
  assertDurableHandoffConfigured(service.settings);
  const deliveryPlan = job?.data?.deliveryPlan;
  const intentId = deliveryPlan?.intentId;
  if (typeof intentId !== 'string' || intentId.length === 0) {
    throw new Error('Delivery handoff job is missing deliveryPlan.intentId');
  }

  const response = await fetchImpl(service.settings.deliveryHandoffUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${service.settings.deliveryHandoffToken}`,
      'X-APDM-Intent-Id': intentId
    },
    body: JSON.stringify(toSidecarOutboxPayload(deliveryPlan)),
    signal: AbortSignal.timeout(service.settings.deliveryHandoffTimeoutMs || 5000)
  });

  if (response.status !== 202) {
    throw new Error(`Sidecar durable outbox handoff returned ${response.status}; expected durable 202 acceptance`);
  }

  // The Fedify sidecar returns the X-APDM-Intent-Id as the durable queue
  // intentId in external mode. Do not report success for another request.
  const acknowledgement = await readBoundedAcknowledgement(response);
  if (acknowledgement.accepted !== true ||
      acknowledgement.intentId !== intentId ||
      !Number.isSafeInteger(acknowledgement.jobCount) ||
      acknowledgement.jobCount < 0 ||
      !Array.isArray(deliveryPlan.remoteRecipients) ||
      acknowledgement.jobCount > deliveryPlan.remoteRecipients.length ||
      (deliveryPlan.remoteRecipients.length > 0 && acknowledgement.jobCount === 0)) {
    throw new Error('Sidecar durable outbox handoff acknowledgement did not confirm Redis acceptance for this intent');
  }

  if (typeof job.progress === 'function') job.progress(100);
  return {
    status: 'accepted',
    deliveryPlanIntentId: intentId,
    sidecarIntentId: acknowledgement.intentId,
    jobCount: acknowledgement.jobCount
  };
}

module.exports = {
  DELIVERY_HANDOFF_JOB_NAME,
  DELIVERY_HANDOFF_QUEUE,
  DELIVERY_HANDOFF_QUEUE_OPTIONS,
  assertDurableHandoffConfigured,
  enqueueDeliveryHandoff,
  processDeliveryHandoffJob,
  toSidecarOutboxPayload
};
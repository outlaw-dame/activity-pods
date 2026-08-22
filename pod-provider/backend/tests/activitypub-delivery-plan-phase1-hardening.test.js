'use strict';

const fixture = require('../contracts/ap.delivery-plan.v1.fixture.json');
const {
  canonicalize,
  validateDeliveryPlanV1
} = require('../utils/activitypub-delivery-plan');
const {
  buildDeliveryPlanV1,
  determineVisibility,
  resolveRemoteDeliveryTarget
} = require('../utils/activitypub-delivery-planner');

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function remoteCtx() {
  return {
    async call(action, params) {
      if (action === 'activitypub.actor.get') {
        expect(params.webId).toBe('https://pods.example/alice');
        return {
          id: params.actorUri,
          inbox: `${params.actorUri}/inbox`
        };
      }
      throw new Error(`Unexpected call ${action}`);
    }
  };
}

describe('APDM Phase 1 contract hardening', () => {
  test('producer rejects searchConsent arrays to match the mirrored schema and Fedify consumer', () => {
    const plan = clone(fixture);
    plan.meta.searchConsent = [];
    expect(validateDeliveryPlanV1(plan)).toBe(false);
  });

  test('delivery endpoints reject fragments including a bare empty fragment and normalization whitespace', () => {
    const fragmented = clone(fixture);
    fragmented.remoteRecipients[0].sharedInboxUrl = 'https://remote.example/inbox#fragment';
    expect(validateDeliveryPlanV1(fragmented)).toBe(false);

    const emptyFragment = clone(fixture);
    emptyFragment.remoteRecipients[0].sharedInboxUrl = 'https://remote.example/inbox#';
    expect(validateDeliveryPlanV1(emptyFragment)).toBe(false);

    const padded = clone(fixture);
    padded.remoteRecipients[0].sharedInboxUrl = ' https://remote.example/inbox';
    expect(validateDeliveryPlanV1(padded)).toBe(false);
  });

  test('local dataset authority rejects whitespace/control-character ambiguity', () => {
    const padded = clone(fixture);
    padded.localRecipients[0].dataset = ' bob ';
    expect(validateDeliveryPlanV1(padded)).toBe(false);

    const controlled = clone(fixture);
    controlled.localRecipients[0].dataset = 'bob\nadmin';
    expect(validateDeliveryPlanV1(controlled)).toBe(false);
  });

  test('targetDomain must use canonical lowercase hostname without trailing-dot aliases', () => {
    const aliased = clone(fixture);
    aliased.remoteRecipients[0].sharedInboxUrl = 'https://remote.example./inbox';
    aliased.remoteRecipients[0].targetDomain = 'remote.example.';
    expect(validateDeliveryPlanV1(aliased)).toBe(false);

    const canonical = clone(fixture);
    canonical.remoteRecipients[0].sharedInboxUrl = 'https://remote.example./inbox';
    canonical.remoteRecipients[0].targetDomain = 'remote.example';
    expect(validateDeliveryPlanV1(canonical)).toBe(true);
  });

  test('remote target resolution canonicalizes a trailing-dot hostname before policy keys are created', async () => {
    const ctx = {
      async call(action) {
        expect(action).toBe('activitypub.actor.get');
        return {
          id: 'https://remote.example/users/carol',
          inbox: 'https://remote.example./users/carol/inbox',
          endpoints: { sharedInbox: 'https://remote.example./inbox' }
        };
      }
    };

    const target = await resolveRemoteDeliveryTarget(
      ctx,
      'https://remote.example/users/carol',
      'https://pods.example/alice'
    );
    expect(target.targetDomain).toBe('remote.example');
    expect(target.sharedInboxUrl).toBe('https://remote.example./inbox');
  });

  test.each([undefined, '', 'system'])('remote target resolution rejects missing or system sender authority (%p)', async authority => {
    const ctx = { call: jest.fn() };
    await expect(
      resolveRemoteDeliveryTarget(ctx, 'https://remote.example/users/carol', authority)
    ).rejects.toThrow(/requires a concrete sender authority/u);
    expect(ctx.call).not.toHaveBeenCalled();
  });

  test('only the sender own followers collection is classified as followers visibility', () => {
    const actor = 'https://pods.example/alice';
    expect(determineVisibility({ actor, to: [`${actor}/followers`], cc: [] })).toBe('followers');
    expect(determineVisibility({ actor, to: ['https://remote.example/users/followers'], cc: [] })).toBe('direct');
  });

  test('planner allows a legitimate actor URI whose path happens to end in /followers', async () => {
    const actorUri = 'https://pods.example/alice';
    const recipientUri = 'https://remote.example/users/followers';
    const plan = await buildDeliveryPlanV1(remoteCtx(), {
      activity: {
        id: `${actorUri}/activities/direct-followers-name`,
        actor: actorUri,
        type: 'Create',
        to: [recipientUri],
        cc: []
      },
      remoteRecipientUris: [recipientUri]
    });

    expect(plan.meta.visibility).toBe('direct');
    expect(plan.remoteRecipients[0].actorUri).toBe(recipientUri);
  });

  test('validator rejects a plan that omits an explicitly addressed visible actor', () => {
    const omitted = clone(fixture);
    omitted.activity.cc = [...omitted.activity.cc, 'https://remote.example/users/missing'];
    expect(validateDeliveryPlanV1(omitted)).toBe(false);

    const included = clone(fixture);
    included.activity.cc = [...included.activity.cc, 'https://remote.example/users/carol'];
    expect(validateDeliveryPlanV1(included)).toBe(true);
  });

  test('planner uses blind addresses for routing but strips bto/bcc recursively from the outbound payload', async () => {
    const actorUri = 'https://pods.example/alice';
    const hiddenRecipient = 'https://remote.example/users/hidden';
    const plan = await buildDeliveryPlanV1(remoteCtx(), {
      activity: {
        id: `${actorUri}/activities/blind`,
        actor: actorUri,
        type: 'Create',
        to: [],
        bcc: [hiddenRecipient],
        object: {
          id: `${actorUri}/objects/blind`,
          type: 'Note',
          content: 'private routing',
          bto: [hiddenRecipient]
        }
      },
      remoteRecipientUris: [hiddenRecipient]
    });

    expect(plan.remoteRecipients.map(target => target.actorUri)).toContain(hiddenRecipient);
    expect(JSON.stringify(plan.activity)).not.toContain('"bcc"');
    expect(JSON.stringify(plan.activity)).not.toContain('"bto"');
    expect(validateDeliveryPlanV1(plan)).toBe(true);
  });

  test('validator fails closed if a hand-crafted outbound plan still discloses blind addressing', () => {
    const leaked = clone(fixture);
    leaked.activity.bcc = ['https://remote.example/users/carol'];
    expect(validateDeliveryPlanV1(leaked)).toBe(false);
  });

  test('concrete audience recipients must be planned and sender-followers audience fails closed until authoritative expansion exists', async () => {
    const actorUri = 'https://pods.example/alice';
    const audienceRecipient = 'https://remote.example/users/audience';

    await expect(buildDeliveryPlanV1(remoteCtx(), {
      activity: {
        id: `${actorUri}/activities/audience-missing`,
        actor: actorUri,
        type: 'Create',
        to: [],
        audience: [audienceRecipient]
      },
      remoteRecipientUris: []
    })).rejects.toThrow(/omitted explicitly addressed recipient/u);

    await expect(buildDeliveryPlanV1(remoteCtx(), {
      activity: {
        id: `${actorUri}/activities/audience-followers`,
        actor: actorUri,
        type: 'Create',
        to: [],
        audience: [`${actorUri}/followers`]
      },
      remoteRecipientUris: []
    })).rejects.toThrow(/authoritative audience expansion/u);
  });

  test('contract fingerprint canonicalization rejects non-JSON and sparse-array values', () => {
    expect(() => canonicalize([undefined])).toThrow(/unsupported undefined/u);
    expect(() => canonicalize({ value: Number.NaN })).toThrow(/non-finite/u);
    expect(() => canonicalize(new Date())).toThrow(/non-JSON object/u);
    expect(() => canonicalize(new Array(1))).toThrow(/sparse array/u);
  });
});

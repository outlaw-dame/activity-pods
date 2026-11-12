'use strict';
const { assertNotificationPgCanRun } = require('../utils/notification-pg-release-gate');

jest.mock('../config/config', () => ({ BASE_URL:'https://paper.example.test/' }));
const api = require('../services/internal-bridge-canonical-notification-api.service');
const worker = require('../services/internal-notification-delivery-worker.service');
const { validateBatch, createCanonicalNotificationLedger, MAX_RECIPIENTS } =
  require('../utils/canonical-notification-pg-ledger');

const params = {
  canonicalIntentId:'canonical-test-1',kind:'FollowAdd',
  sourceProtocol:'activitypub',
  actor:{activityPubActorUri:'https://remote.example.test/alice'},
  createdAt:'2026-11-12T00:00:00.000Z'
};
const recipient='https://paper.example.test/alice';

function host() {
  return {
    settings:{pgLedgerEnabled:true,baseUrl:'https://paper.example.test/'},
    notificationLedger:{
      enqueue:jest.fn(async()=>({accepted:true,duplicate:false,recipients:1}))
    },
    ...api.methods,
    resolveActorUri:jest.fn(async()=>params.actor.activityPubActorUri),
    resolveLocalRecipients:jest.fn(async()=>[recipient]),
    buildBridgeActivity:jest.fn(()=>({
      id:'https://paper.example.test/_bridge/canonical/1#event',
      type:'Follow',actor:params.actor.activityPubActorUri
    })),
    logger:{info:jest.fn(),error:jest.fn(),warn:jest.fn(),debug:jest.fn()}
  };
}
test('production release gate denies notification ledgers and workers independently', () => {
  expect(() => assertNotificationPgCanRun({
    NODE_ENV:'production',APODS_NOTIFICATION_LEDGER_ENABLED:'true'
  })).toThrow(/not released/u);
  expect(() => assertNotificationPgCanRun({
    NODE_ENV:'production',APODS_NOTIFICATION_LEDGER_WORKER_ENABLED:'true'
  })).toThrow(/not released/u);
  expect(() => assertNotificationPgCanRun({
    NODE_ENV:'test', APODS_NOTIFICATION_LEDGER_ENABLED:'true',
    APODS_NOTIFICATION_PG_DISPOSABLE:'confirmed'
  })).not.toThrow();
  expect(() => assertNotificationPgCanRun({
    NODE_ENV:'production',APODS_NOTIFICATION_LEDGER_ENABLED:'false'
  })).not.toThrow();
});

test('durable notification bridge acknowledges only after successful PG commit', async () => {
  const h=host(),ctx={params,meta:{}};
  const result=await api.actions.ingest.handler.call(h,ctx);
  expect(result).toEqual({
    ok:true,durable:true,duplicate:false,delivered:false,queuedRecipients:1
  });
  expect(ctx.meta.$statusCode).toBe(202);
  expect(h.notificationLedger.enqueue).toHaveBeenCalledWith({
    intentId:params.canonicalIntentId,kind:params.kind,
    protocol:'activitypub',
    recipients:[expect.objectContaining({recipient,actorUri:params.actor.activityPubActorUri})]
  });
});

test('duplicate manifest returns idempotent HTTP 409', async()=>{
  const h=host();h.notificationLedger.enqueue.mockResolvedValue({
    accepted:true,duplicate:true,recipients:1
  });
  const ctx={params,meta:{}};
  expect((await api.actions.ingest.handler.call(h,ctx)).duplicate).toBe(true);
  expect(ctx.meta.$statusCode).toBe(409);
});
test('failed PostgreSQL write never produces success or caches a processed ID',async()=>{
  const h=host();h.notificationLedger.enqueue.mockRejectedValue(new Error('connection terminated'));
  const ctx={params,meta:{}};
  await expect(api.actions.ingest.handler.call(h,ctx))
    .rejects.toMatchObject({code:503});
  expect(ctx.meta.$statusCode).toBeUndefined();
});
test('a changed payload under the same intent returns conflict',async()=>{
  const h=host();const e=new Error('conflict');e.code='PG_NOTIFY_INTENT_CONFLICT';
  h.notificationLedger.enqueue.mockRejectedValue(e);
  await expect(api.actions.ingest.handler.call(h,{params,meta:{}}))
    .rejects.toMatchObject({code:409});
});
test('ledger refuses oversized and duplicate recipients before any database query',()=>{
  const p={
    intentId:'x',kind:'FollowAdd',protocol:'activitypub',
    recipients:[{
      recipient,actorUri:'https://remote.example.test/alice',
      activity:{actor:'https://remote.example.test/alice',type:'Follow'}
    }]
  };
  expect(validateBatch(p).entries).toHaveLength(1);
  expect(()=>validateBatch({...p,recipients:Array(MAX_RECIPIENTS+1).fill(p.recipients[0])}))
    .toThrow();
  expect(()=>validateBatch({...p,recipients:[p.recipients[0],p.recipients[0]]}))
    .toThrow(/rejected/u);
  expect(()=>createCanonicalNotificationLedger({})).toThrow(/rejected/u);
});

test('worker advances only after authorized local inbox post and durable PG finish', async()=>{
  const token='a'.repeat(8)+'-'+'a'.repeat(4)+'-4aaa-8aaa-'+'a'.repeat(12);
  const item={
    intent_key:'a'.repeat(64),recipient_key:'b'.repeat(64),
    recipient_webid:recipient,workerToken:token,
    activity_json:{actorUri:params.actor.activityPubActorUri,
      activity:{actor:params.actor.activityPubActorUri,id:'https://paper.example.test/test#event'}}
  };
  const ledger={claim:jest.fn(async()=>[item]),finish:jest.fn(async()=>({delivered:true})),
    fail:jest.fn(async()=>({dead:false}))};
  const broker={call:jest.fn(async(name)=>{
    if(name==='activitypub.actor.get')return{inbox:recipient+'/inbox'};
    return undefined;
  })};
  const h={
    notificationWorker:{ledger,stopping:false},
    settings:{baseUrl:'https://paper.example.test'},
    broker,logger:{error:jest.fn()}
  };
  await expect(worker.methods.pollCanonicalNotifications.call(h)).resolves.toBe(1);
  expect(ledger.finish).toHaveBeenCalledTimes(1);
  expect(ledger.fail).not.toHaveBeenCalled();
  expect(broker.call.mock.calls[1][1].collectionUri).toBe(recipient+'/inbox');
});
test('untrusted redirect inbox never reaches federation and stays retryable',async()=>{
  const item={
    intent_key:'a'.repeat(64),recipient_key:'b'.repeat(64),
    recipient_webid:recipient,
    activity_json:{actorUri:params.actor.activityPubActorUri,
      activity:{actor:params.actor.activityPubActorUri}}
  };
  const ledger={claim:jest.fn(async()=>[item]),finish:jest.fn(),
    fail:jest.fn(async()=>({dead:false}))};
  const broker={call:jest.fn(async()=>({inbox:'https://evil.example.test/steal/inbox'}))};
  const h={
    notificationWorker:{ledger,stopping:false},
    settings:{baseUrl:'https://paper.example.test'},
    broker,logger:{error:jest.fn()}
  };
  await worker.methods.pollCanonicalNotifications.call(h);
  expect(broker.call).toHaveBeenCalledTimes(1);
  expect(ledger.fail).toHaveBeenCalledTimes(1);
  expect(ledger.finish).not.toHaveBeenCalled();
});

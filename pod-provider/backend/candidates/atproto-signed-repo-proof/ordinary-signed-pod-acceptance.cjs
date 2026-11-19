'use strict';
const assert = require('node:assert/strict');
const { ServiceBroker } = require('moleculer');

async function provePodData(dataset) {
  const schema = require('../../services/core/triplestore');
  assert.equal(schema.settings.dataset, false);
  const broker = new ServiceBroker({ logger:false, requestTimeout:5000, retryPolicy:{ enabled:false } });
  try {
    // ASK and INSERT use the native triplestore directly. The parser action
    // is never called for these operations.
    broker.createService({ name:'jsonld.parser' });
    broker.createService(schema);
    await broker.start();
    const triple = '<urn:paper:ordinary-readback> <urn:paper:private> true';
    await broker.call('triplestore.update',{dataset,webId:'system',query:'INSERT DATA { '+triple+' }'});
    for (const [webId, expected] of [['system',true],['anon',false],['https://paper.example.org/other',false]]) {
      assert.equal(await broker.call('triplestore.query',{dataset,webId,query:'ASK { '+triple+' }'}),expected);
    }
    await assert.rejects(broker.call('triplestore.dataset.exist',{dataset:'protected-proof'}));
  } finally { await broker.stop(); }
}
module.exports = { provePodData };

'use strict';

const http = require('node:http');
const WebSocket = require('ws');
const mixin = require('../mixins/websocket');

async function fixture() {
  const accepted = [];
  const logger = { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() };
  const server = http.createServer((_req, res) => res.writeHead(404).end());
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const {port} = server.address();
  const origin = `http://127.0.0.1:${port}`;
  const handlers = {
    onConnection: connection => accepted.push(connection),
    onMessage: () => {},
    onClose: () => {},
    onError: () => {}
  };
  const service = {
    settings: { baseUrl: origin },
    server, logger,
    httpHandler(req, response) {
      // Exercise the actual mixin handshake, registration and shutdown
      // methods, without requiring a Moleculer or Fuseki database.
      req.$ctx = {meta: {}};
      req.$params = {};
      req.baseUrl = '/live';
      req.originalUrl = req.url;
      req.parsedUrl = '/live';
      return mixin.methods.handleWsRequest.call(
        service, req, response, () => {}, handlers
      );
    }
  };
  service.upgradeHandler = mixin.methods.upgradeHandler.bind(service);
  mixin.created.call(service);
  mixin.started.call(service);
  return {service,server,accepted,origin};
}
function connect(origin, headerOrigin=origin, target='/live?token=private') {
  const ws = new WebSocket(origin.replace(/^http/u, 'ws') + target, {
    origin: headerOrigin,perMessageDeflate:false,handshakeTimeout:3000
  });
  return new Promise((resolve,reject) => {
    ws.once('open',()=>resolve(ws));
    ws.once('error',reject);
    ws.once('unexpected-response',(_req,res)=>{
      res.resume();
      reject(Object.assign(new Error('WebSocket HTTP rejection'),{status:res.statusCode}));
    });
  });
}
function closed(ws) {
  return new Promise(resolve => {
    if(ws.readyState===WebSocket.CLOSED)return resolve();
    ws.once('close',resolve);
    ws.terminate();
  });
}
async function waitForServerClose(service) {
  const start = Date.now();
  while (service.connections.length !== 0 || service.wss.clients.size !== 0) {
    if (Date.now() - start > 3000) {
      throw new Error('Server WebSocket did not release its connection state');
    }
    await new Promise(resolve=>setTimeout(resolve,10));
  }
}

describe('live ws gateway handshake and lifecycle', () => {
  let f;
  beforeEach(async()=>{f=await fixture()});
  afterEach(async()=>{
    if (!f) return;
    mixin.stopped.call(f.service);
    await new Promise(resolve=>f.server.close(resolve));
    f = undefined;
  });

  test('only the configured browser origin upgrades, and the query token is never logged',async()=>{
    await expect(connect(f.origin,'https://evil.example.test')).rejects.toMatchObject({status:403});
    const ws=await connect(f.origin);
    expect(f.accepted).toHaveLength(1);
    expect(f.service.connections).toHaveLength(1);
    expect(f.service.connectionIndexes.size).toBe(1);
    const connection=f.accepted[0];
    expect(connection.server).toBe(f.service.wss);
    expect(connection.requestUrl).toContain('token=private');
    expect(f.service.logger.debug.mock.calls.flat().join(' ')).not.toContain('token=private');
    await closed(ws);
    await waitForServerClose(f.service);
    expect(f.service.connections).toHaveLength(0);
    expect(f.service.connectionIndexes.size).toBe(0);
  });

  test('cross-origin Solid capabilities are limited to the exact channel route',async()=>{
    await expect(connect(f.origin,'https://reader.example.test'))
      .rejects.toMatchObject({status:403});
    const capability='/.notifications/WebSocketChannel2023/socket/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    const ws=await connect(f.origin,'https://reader.example.test',capability);
    expect(f.service.connections).toHaveLength(1);
    await closed(ws);
    await waitForServerClose(f.service);
  });

  test('a payload above 256 KiB is rejected by the actual ws parser',async()=>{
    const ws=await connect(f.origin);
    const finished=new Promise(resolve=>ws.once('close',(code)=>resolve(code)));
    ws.send(Buffer.alloc(256*1024+1));
    await expect(finished).resolves.toBe(1009);
  });

  test('repeated connections are removed without accumulating retained socket records',async()=>{
    for(let i=0;i<16;i++){
      const ws=await connect(f.origin);
      await closed(ws);
      await waitForServerClose(f.service);
    }
    expect(f.service.connections).toHaveLength(0);
    expect(f.service.connectionIndexes.size).toBe(0);
    expect(f.service.wss.clients.size).toBe(0);
  });

  test('shutdown detaches upgrade handlers and closes live WebSockets',async()=>{
    const ws=await connect(f.origin);
    expect(f.server.listenerCount('upgrade')).toBe(1);
    mixin.stopped.call(f.service);
    expect(f.server.listenerCount('upgrade')).toBe(0);
    await new Promise(resolve=>ws.once('close',resolve));
    expect(f.service.connections).toHaveLength(0);
  });
});

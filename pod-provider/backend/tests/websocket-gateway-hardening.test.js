'use strict';

const { EventEmitter } = require('node:events');
const { WebSocket, WebSocketServer } = require('ws');
const mixin = require('../mixins/websocket');

function setup(origins = ['https://paper.example.test', 'https://app.example.test']) {
  const gateway = {
    settings: {baseUrl:'https://paper.example.test',wsAllowedOrigins:origins},
    server:new EventEmitter(),
    logger:{debug:jest.fn(),error:jest.fn(),info:jest.fn()},
    httpHandler:jest.fn(),
    ...mixin.methods
  };
  gateway.upgradeHandler = gateway.upgradeHandler.bind(gateway);
  mixin.created.call(gateway);
  return gateway;
}
function fakeSocket() {
  const s=new EventEmitter();
  s.destroyed=false;
  s.writes=[];
  s.end=jest.fn(value=>{s.writes.push(value);s.destroyed=true;s.emit('close')});
  s.destroy=jest.fn(()=>{s.destroyed=true;s.emit('close')});
  return s;
}
function fakeWs() {
  const socket=new EventEmitter();
  socket.readyState=WebSocket.OPEN;
  socket.bufferedAmount=0;
  socket.sent=[];
  socket.closed=[];
  socket.addEventListener=(name,handler)=>socket.on(name,handler);
  socket.send=jest.fn(function(...args){
    if(this!==socket)throw Error('The send method lost its WebSocket receiver');
    socket.sent.push(args);
  });
  socket.close=jest.fn(function(code,reason){
    socket.closed.push([code,reason]);
    socket.readyState=WebSocket.CLOSING;
    socket.emit('close',{code});
  });
  socket.terminate=jest.fn(()=>{socket.readyState=WebSocket.CLOSED;socket.emit('close',{code:1006})});
  return socket;
}
async function connect(gateway,ws,handlers={}) {
  gateway.wss=new WebSocketServer({noServer:true,maxPayload:64*1024,perMessageDeflate:false});
  const request={
    baseUrl:'/socket', originalUrl:'/socket?access_token=private-secret',
    parsedUrl:'/socket',$params:{},
    $ctx:{meta:{}},webSocketRequestHandler:async()=>ws
  };
  const next=jest.fn();
  const callbacks={
    onConnection:jest.fn(),onClose:jest.fn(),onMessage:jest.fn(),
    onError:jest.fn(),...handlers
  };
  await gateway.handleWsRequest(request,{},next,callbacks);
  const connection=request.$ctx.meta.connection;
  return {connection,next,callbacks,request};
}

test('one shared ws server, bounded payloads, disabled compression and clean shutdown',()=>{
  const gateway=setup();
  mixin.started.call(gateway);
  expect(gateway.wss.options.maxPayload).toBe(65536);
  expect(gateway.wss.options.perMessageDeflate).toBe(false);
  expect(gateway.server.listenerCount('upgrade')).toBe(1);
  expect(gateway.wsHeartbeat).toBeTruthy();
  mixin.stopped.call(gateway);
  expect(gateway.server.listenerCount('upgrade')).toBe(0);
  expect(gateway.wsHeartbeat).toBe(null);
  expect(gateway.wss).toBe(null);
});
test('rejects untrusted browser origins before allocating an HTTP response or hitting a route',()=>{
  const gateway=setup();
  gateway.wss=new WebSocketServer({noServer:true});
  for(const origin of ['https://evil.example.test','null','https://app.example.test.evil','https://app.example.test/']){
    const raw=fakeSocket();
    gateway.upgradeHandler({headers:{origin}},raw,Buffer.alloc(0));
    expect(raw.end).toHaveBeenCalledWith(expect.stringContaining('403 Forbidden'));
  }
  expect(gateway.httpHandler).not.toHaveBeenCalled();
  gateway.wss.close();
});
test('prevents excessive pending upgrades and oversized coalesced frames',()=>{
  const gateway=setup();
  gateway.wss=new WebSocketServer({noServer:true});
  gateway.pendingUpgrades=2048;
  const full=fakeSocket();
  gateway.upgradeHandler({headers:{origin:'https://app.example.test'}},full,Buffer.alloc(0));
  expect(full.end).toHaveBeenCalledWith(expect.stringContaining('503 Service Unavailable'));
  gateway.pendingUpgrades=0;
  const large=fakeSocket();
  gateway.upgradeHandler({headers:{origin:'https://app.example.test'}},large,Buffer.alloc(65537));
  expect(large.end).toHaveBeenCalledWith(expect.stringContaining('413 Content Too Large'));
  gateway.wss.close();
});
test('preserves a working bound send and does not log token-bearing request URLs',async()=>{
  const gateway=setup();
  const ws=fakeWs();
  const {connection,next}=await connect(gateway,ws);
  expect(connection.server).toBe(gateway.wss);
  expect(gateway.connections.has(connection)).toBe(true);
  connection.send('hello');
  expect(ws.send).toHaveBeenCalledWith('hello');
  expect(next).toHaveBeenCalledTimes(1);
  expect(JSON.stringify(gateway.logger.debug.mock.calls)).not.toContain('private-secret');
  ws.emit('close',{code:1000});
  expect(gateway.connections.size).toBe(0);
  gateway.wss.close();
});
test('stops buffering outgoing events for stalled WebSocket clients',async()=>{
  const gateway=setup();
  const ws=fakeWs();
  const {connection}=await connect(gateway,ws);
  ws.bufferedAmount=1024*1024+1;
  connection.send(Buffer.from('hello'));
  expect(ws.send).not.toHaveBeenCalled();
  expect(ws.close).toHaveBeenCalledWith(1013,'Slow client');
  expect(gateway.connections.size).toBe(0);
  gateway.wss.close();
});
test('caps async inbound message processing instead of accumulating unbounded work',async()=>{
  const gateway=setup();
  const ws=fakeWs();
  let release;
  const pending=new Promise(resolve=>{release=resolve});
  const handler=jest.fn(()=>pending);
  await connect(gateway,ws,{onMessage:handler});
  for(let i=0;i<9;i++)ws.emit('message',{data:'test'});
  expect(handler).toHaveBeenCalledTimes(8);
  expect(ws.close).toHaveBeenCalledWith(1008,'Message rate exceeded');
  release();
  await Promise.resolve();
  gateway.wss.close();
});
test('close handlers reject safely without retaining the connection',async()=>{
  const gateway=setup();
  const ws=fakeWs();
  await connect(gateway,ws,{onClose:()=>{throw Error('deliberate client handler error')}});
  expect(()=>ws.emit('close',{code:1000})).not.toThrow();
  expect(gateway.connections.size).toBe(0);
  gateway.wss.close();
});
test('rejects unsafe production origin configuration',()=>{
  const original=process.env.NODE_ENV;
  process.env.NODE_ENV='production';
  try {
    expect(()=>setup(['http://insecure.example.test'])).toThrow(/trusted HTTP/);
    expect(()=>setup(['https://a.example.test','https://evil.example.test/path?token=secret'])).toThrow();
  }finally{
    if(original===undefined)delete process.env.NODE_ENV;
    else process.env.NODE_ENV=original;
  }
});
test('server socket close resolves in-flight WebSocket call without listeners left attached',async()=>{
  const gateway=setup();
  const socket=new EventEmitter();socket.destroyed=false;
  const pending=gateway.delayConnectionClosing({webSocketRequestHandler:()=>{}},{socket});
  expect(socket.listenerCount('close')).toBe(1);
  socket.emit('close');
  await pending;
  expect(socket.listenerCount('close')).toBe(0);
  expect(socket.listenerCount('error')).toBe(0);
});

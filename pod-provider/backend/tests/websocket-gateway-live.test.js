'use strict';

const http=require('node:http');
const {performance}=require('node:perf_hooks');
const {WebSocket}=require('ws');
const mixin=require('../mixins/websocket');

let server,gateway,url;
function beginConnection(origin) {
  return new Promise((resolve,reject)=>{
    const client=new WebSocket(url,{
      origin,handshakeTimeout:4000,perMessageDeflate:false
    });
    const fail=e=>reject(e);
    client.once('error',fail);
    client.once('open',()=>{
      client.off('error',fail);
      resolve(client);
    });
  });
}
function sendEcho(client,text) {
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('WebSocket echo timed out')),4000);
    const onMessage=data=>{
      clearTimeout(timer);
      client.off('error',onError);
      resolve(data.toString());
    };
    const onError=e=>{
      clearTimeout(timer);
      client.off('message',onMessage);
      reject(e);
    };
    client.once('message',onMessage);
    client.once('error',onError);
    client.send(text);
  });
}
async function disconnect(client) {
  if(client.readyState===WebSocket.CLOSED)return;
  await new Promise(resolve=>{
    const timer=setTimeout(()=>{client.terminate();resolve()},1500);
    client.once('close',()=>{clearTimeout(timer);resolve()});
    if(client.readyState===WebSocket.OPEN)client.close();
    else client.terminate();
  });
}
beforeAll(async()=>{
  server=http.createServer((_req,res)=>{res.writeHead(404);res.end()});
  gateway={
    settings:{
      baseUrl:'http://127.0.0.1:39871',
      wsAllowedOrigins:['https://trusted.example.test']
    },
    server,
    logger:{debug:()=>{},info:()=>{},error:()=>{}},
    ...mixin.methods
  };
  gateway.upgradeHandler=gateway.upgradeHandler.bind(gateway);
  mixin.created.call(gateway);
  gateway.httpHandler=(request,response)=>{
    request.baseUrl='/ws';
    request.originalUrl=request.url;
    request.parsedUrl='/ws';
    request.$params={};
    request.$ctx={meta:{}};
    return gateway.handleWsRequest(request,response,()=>{},{
      onConnection:()=>{},
      onMessage:(message,connection)=>connection.send(message),
      onClose:()=>{},
      onError:()=>{}
    });
  };
  mixin.started.call(gateway);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  url='ws://127.0.0.1:'+server.address().port+'/ws';
});
afterAll(async()=>{
  mixin.stopped.call(gateway);
  await new Promise(resolve=>server.close(()=>resolve()));
});

test('real RFC6455 handshake, message echo and clean socket close',async()=>{
  const client=await beginConnection('https://trusted.example.test');
  expect(await sendEcho(client,'real-ws-smoke')).toBe('real-ws-smoke');
  await disconnect(client);
});

test('untrusted origin is rejected at the actual HTTP upgrade boundary',async()=>{
  const result=await new Promise((resolve,reject)=>{
    const client=new WebSocket(url,{
      origin:'https://evil.example.test',handshakeTimeout:4000
    });
    client.once('unexpected-response',(_request,response)=>{
      const status=response.statusCode;
      response.resume();
      client.terminate();
      resolve(status);
    });
    client.once('open',()=>reject(Error('Untrusted browser origin was accepted')));
    client.once('error',reject);
  });
  expect(result).toBe(403);
});

test('real ws receiver closes a frame larger than the 64-KiB budget',async()=>{
  const client=await beginConnection('https://trusted.example.test');
  const status=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{
      client.terminate();
      reject(Error('Oversized frame was not rejected'));
    },5000);
    client.once('close',code=>{
      clearTimeout(timer);
      resolve(code);
    });
    client.send(Buffer.alloc(65537,65));
  });
  expect(status).toBe(1009);
});

test('measures repeated real loopback handshake, echo p95/p99 and RSS',async()=>{
  const concurrent=8,total=128;
  let cursor=0;
  const latency=[];
  const before=process.memoryUsage().rss;
  const start=performance.now();
  await Promise.all(Array.from({length:concurrent},async()=>{
    while(cursor<total){
      const id=cursor++;
      const t=performance.now();
      const ws=await beginConnection('https://trusted.example.test');
      try{
        expect(await sendEcho(ws,'echo-'+id)).toBe('echo-'+id);
      }finally{
        await disconnect(ws);
      }
      latency.push(performance.now()-t);
    }
  }));
  const elapsedMs=performance.now()-start;
  latency.sort((a,b)=>a-b);
  const percentile=p=>Number(latency[Math.ceil(p*latency.length)-1].toFixed(3));
  expect(latency).toHaveLength(total);
  const report={
    scope:'disposable-loopback-rfc6455-gateway',
    count:total,concurrency:concurrent,
    perConnectionHandshakeAndEchoMs:{
      p50:percentile(0.5),p95:percentile(0.95),p99:percentile(0.99)
    },
    completedConnectionsPerSecond:Number((total*1000/elapsedMs).toFixed(2)),
    rssChangeBytes:process.memoryUsage().rss-before,
    caveat:'Single process loopback; excludes TLS proxy, auth, Redis and WAN'
  };
  console.log(JSON.stringify(report));
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { NeverLauncherAPI, ApiError } from '../dist/client.js';

async function withServer(callback) {
 const server = createServer((req, res) => {
  if (req.url === '/api/v1/bytes') {
   res.writeHead(200, {'Content-Type':'image/png'});
   res.end(Buffer.from([137, 80, 78, 71, 0, 255, 254])); return;
  }
  if (req.url === '/metrics') {
   res.writeHead(200, {'Content-Type':'text/plain'});
   res.end('launcher_jobs_total 2\n'); return;
  }
  if (req.url === '/api/v1/stream') {
   res.writeHead(200, {'Content-Type':'application/zip'});
   for(let i=0;i<32;i++) res.write(Buffer.alloc(4096, i));
   res.end(); return;
  }
  if (req.url === '/api/v1/error') {
   res.writeHead(403, {'Content-Type':'application/json','X-Correlation-ID':'forbidden-1'});
   res.end('{"code":"denied","message":"not authorized"}'); return;
  }
  if (req.url === '/api/v1/redirect') {
   res.writeHead(302, {'Location':'https://attacker.example/auth'});res.end();return;
  }
  res.writeHead(200, {'Content-Type':'application/json'});res.end('{"ok":true}');
 });
 await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
 try { await callback(new NeverLauncherAPI(`http://127.0.0.1:${server.address().port}`,'secret')); }
 finally { server.closeAllConnections();await new Promise(resolve => server.close(resolve)); }
}

test('production HTTP client preserves binary responses and text without JSON decoding', async () => {
 await withServer(async client => {
  const result=await client.request('GET','/api/v1/bytes',{responseType:'bytes'});
  assert.deepEqual(Array.from(result),[137,80,78,71,0,255,254]);
  assert.equal(await client.request('GET','/metrics',{responseType:'text'}), 'launcher_jobs_total 2\n');
  assert.deepEqual(await client.request('GET','/api/v1/test'),{ok:true});
  await assert.rejects(client.request('GET','/api/v1/bytes'),/invalid JSON API response|encoded data/);
 });
});

test('streaming download is consumable incrementally and bounded', async () => {
 await withServer(async client => {
  const s=await client.request('GET','/api/v1/stream',{responseType:'stream'});
  const reader=s.getReader();let total=0;
  while(true){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;}
  assert.equal(total,32*4096);
  const limited=await client.request('GET','/api/v1/stream',{responseType:'stream',maxResponseBytes:1024});
  await assert.rejects(async()=>{for await(const _ of limited){}},/size limit/);
  await assert.rejects(client.request('GET','/api/v1/stream',{responseType:'bytes',maxResponseBytes:1024}),/size limit/);
 });
});

test('HTTP errors, unauthorized redirects, invalid limits and cancellation retain protection', async () => {
 await withServer(async client => {
  await assert.rejects(client.request('GET','/api/v1/error',{responseType:'bytes'}),
    e=>e instanceof ApiError && e.status===403 && e.code==='denied' && e.requestId==='forbidden-1');
  await assert.rejects(client.request('GET','/api/v1/redirect',{responseType:'stream'}),e=>e instanceof ApiError && e.status===302);
  await assert.rejects(client.request('GET','/api/v1/test',{maxResponseBytes:0}), /invalid response size/);
  const ac=new AbortController();ac.abort();
  await assert.rejects(client.request('GET','/api/v1/test',{signal:ac.signal}));
 });
});

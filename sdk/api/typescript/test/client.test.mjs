import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { LauncherAPI, ApiError, resolvePath, OPERATIONS } from '../dist/client.js';

test('Настоящий HTTP, авторизация, статусы и ошибки, совместимость со старой версией и экранирование путей', async () => {
 const server = createServer((req,res) => {
  if (req.url === '/ready') { res.end('{"version":"0.45.11"}'); return; }
  assert.equal(req.headers.authorization, 'Bearer token');
  if (req.url === '/api/v1/projects/a%20b') {res.setHeader('content-type','application/json');res.end('{"id":"a b"}');return;}
  res.statusCode = 403; res.setHeader('X-Correlation-ID','test-123');res.end('{"code":"denied","message":"forbidden"}');
 });
 await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
 try {
  const c=new LauncherAPI(`http://127.0.0.1:${server.address().port}`, 'token');
  await c.checkCompatibility();
  assert.deepEqual(await c.call('get_projects_by_projectId',{params:{projectId:'a b'}}),{id:'a b'});
  await assert.rejects(c.call('get_projects'), e=>e instanceof ApiError && e.status === 403 && e.code === 'denied' && e.requestId === 'test-123');
  assert.throws(()=>resolvePath('/a/{id}',{id:'../../evil'}));
  assert.throws(()=>new LauncherAPI('http://example.org','token'));
  assert.ok(Object.keys(OPERATIONS).length >= 450);
 } finally { await new Promise(resolve=>server.close(resolve)); }
});

 test('Русское пояснение HTTP при отсутствии сообщения сервера', async () => {
  const c = new LauncherAPI('https://example.test', '', async () => new Response('unavailable', {status:503, statusText:'Service Unavailable', headers:{'X-Correlation-ID':'fallback-1'}}));
  await assert.rejects(c.call('get_projects'), e => e instanceof ApiError && e.status === 503 && e.requestId === 'fallback-1' && e.message === 'HTTP 503: Сервис временно недоступен');
  const original = new LauncherAPI('https://example.test', '', async () => new Response(JSON.stringify({code:'custom',message:'Original server message'}), {status:403}));
  await assert.rejects(original.call('get_projects'), e => e instanceof ApiError && e.code === 'custom' && e.message === 'Original server message');
 });

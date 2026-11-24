import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {ChatError, byteLength, buildPrompt, emptyHistory, fetchUsage, gatewayBase, historyKey, loadHistory, MAX_ANSWER_BYTES, MAX_HISTORY_BYTES, MAX_PROMPT_BYTES, MAX_QUESTION_BYTES, newId, nativeStream, nativeUsage, projectContext, readChatStream, saveHistory, streamChat} from '../build-tests/ai_chat.js';

const ID = 'a'.repeat(32), DIALOG = 'b'.repeat(32), TURN = 'c'.repeat(32);
const base = 'https://launcher.example.com';
const terminal = {requestId: ID, state: 'completed', inputTokens: 5, outputTokens: 2, chargedMicroUsd: 17};
const event = (name, data, sep = '\n') => `event: ${name}${sep}data: ${JSON.stringify(data)}${sep}${sep}`;
const start = event('start', {requestId: ID});
const done = event('done', terminal);
const encode = text => new TextEncoder().encode(text);
const fromChunks = chunks => new ReadableStream({start(controller) {for (const c of chunks) controller.enqueue(c); controller.close();}});
const parse = (text, cb = () => {}) => readChatStream(fromChunks([encode(text)]), cb);
const expectCode = code => error => error instanceof ChatError && error.code === code;
const complete = (question, answer) => ({id: newId(), question, answer, state:'completed', at:1, receipt:terminal});
const storage = () => {const map = new Map(); return {getItem: k => map.get(k) ?? null, setItem: (k, v) => map.set(k,v), removeItem: k => map.delete(k)};};

test('SSE reconstructs split UTF-8, CRLF, comments, and multiline JSON with exact usage', async () => {
  const wire = ': keep-alive\r\n\r\n' + event('start', {requestId:ID}, '\r\n') + 'event: delta\r\ndata: {\r\ndata: "delta":"Привет 🌍"}\r\n\r\n' + event('delta',{delta:'\n<script>plain text</script>'}) + done;
  const bytes = encode(wire); let output = '';
  const result = await readChatStream(fromChunks(Array.from(bytes, b => Uint8Array.of(b))), d => {output += d;});
  assert.equal(output, 'Привет 🌍\n<script>plain text</script>');
  assert.deepEqual(result, {requestId:ID,inputTokens:5,outputTokens:2,chargedMicroUsd:17});
});
test('zero-valued Go omitempty counters are accepted', async () => {
  assert.deepEqual(await parse(start + event('done',{requestId:ID,state:'completed'})), {requestId:ID,inputTokens:0,outputTokens:0,chargedMicroUsd:0});
});
test('EOF without done is not success even when partial text was received', async () => {
  let answer = '';
  await assert.rejects(parse(start + event('delta',{delta:'partial'}), d => answer += d), expectCode('interrupted'));
  assert.equal(answer, 'partial');
  await assert.rejects(parse(start + done.trimEnd()), expectCode('interrupted'));
});
test('terminal errors are distinct and never passed as successful receipts', async () => {
  for (const [code,expected] of [['access_revoked','revoked'],['accounting_unavailable','accounting'],['stream_cancelled','cancelled'],['provider_incomplete','provider']]) {
    await assert.rejects(parse(start + event('error',{code,state:'uncertain'})), expectCode(expected));
  }
});
test('reject missing start, duplicate start, bad receipt IDs, non-completed state and invalid JSON', async () => {
  for (const wire of [done, start+start+done, event('delta',{delta:'x'})+done, start+event('done',{...terminal,requestId:'d'.repeat(32)}), start+event('done',{...terminal,state:'uncertain'}), start+event('done',{...terminal,inputTokens:-1}), start+'event: delta\ndata: [garbage\n\n', start+event('delta',{delta:3}), start+event('other',{})]) {
    await assert.rejects(parse(wire), expectCode('protocol'));
  }
});
test('stream cancels the reader after the terminal event and on output overflow', async () => {
  let cancelled = false;
  const body = new ReadableStream({start(c) {c.enqueue(encode(start+done));},cancel(){cancelled=true;}});
  await readChatStream(body,()=>{}); assert.equal(cancelled,true);
  await assert.rejects(parse(start+event('delta',{delta:'x'.repeat(MAX_ANSWER_BYTES+1)})),expectCode('too_large'));
});
test('prompt keeps current question, includes only recent completed turns, and never exceeds UTF-8 limit', () => {
  const turns = [complete('ancient','x'.repeat(12000)), complete('recent','Ответ 🌍'), {...complete('failed-secret','partial'),state:'failed'}, {...complete('interrupted-secret','partial'),state:'interrupted'}];
  const context = {projectId:'p',profileId:'fabric'};
  const result = buildPrompt('Как настроить Java?',turns,context);
  assert.equal(result.included,2); assert.ok(byteLength(result.prompt)<=MAX_PROMPT_BYTES);
  const doc = JSON.parse(result.prompt.split('\n')[1]);
  assert.deepEqual(doc.project,context); assert.equal(doc.question,'Как настроить Java?'); assert.equal(doc.previous.at(-1).assistant,'Ответ 🌍');
  assert.ok(!result.prompt.includes('failed-secret') && !result.prompt.includes('interrupted-secret'));
  const bounded = buildPrompt('Привет',[complete('first','a'.repeat(16000)),complete('second','b'.repeat(8000))],null);
  assert.equal(bounded.included,1); assert.ok(!bounded.prompt.includes('first'));
  assert.equal(buildPrompt('plain',[],null).prompt,'plain');
  assert.equal(buildPrompt('"'.repeat(11000),[],null).prompt.length,11000);
  assert.throws(()=>buildPrompt('я'.repeat(MAX_QUESTION_BYTES),[],null),expectCode('too_large'));
});
test('project context uses allowlisted fields only and excludes a stale manifest or channel', () => {
  const manifest = {projectId:'p',profileId:'f',channel:'stable',version:'v1',minecraft:{version:'1.21.1',loader:'Fabric',gameArgs:['token']},runtime:{java:{majorVersion:21},jvmArgs:['secret']},files:[{path:'/home/private',url:'https://secret'}]};
  assert.deepEqual(projectContext('p','f','stable',manifest),{projectId:'p',profileId:'f',channel:'stable',release:'v1',minecraft:'1.21.1',loader:'Fabric',javaMajor:21});
  assert.deepEqual(projectContext('p','f','beta',manifest),{projectId:'p',profileId:'f',channel:'beta'});
  assert.deepEqual(projectContext('other','f','stable',manifest),{projectId:'other',profileId:'f',channel:'stable'});
  assert.equal(projectContext('','f','stable',manifest),null);
  assert.equal(projectContext('https://example.com','f','stable',manifest),null);
  assert.equal(projectContext('p','f','stable',{...manifest,version:'../private'}).release,undefined);
});
test('history isolates backend, canonical account, project and profile; pending records become interrupted', () => {
  const s = storage(), key = historyKey(base,'user-1','project','profile');
  assert.equal(key,historyKey(base+'///','user-1','project','profile'));
  const record = {version:1,dialogs:[{id:DIALOG,createdAt:1,turns:[{id:TURN,question:'private',answer:'partial',state:'pending',at:2}]}]};
  saveHistory(s,key,record);
  assert.equal(loadHistory(s,key).dialogs[0].turns[0].state,'interrupted');
  assert.equal(loadHistory(s,key).dialogs[0].turns[0].answer,'partial');
  for (const other of [historyKey('https://other.example','user-1','project','profile'), historyKey(base,'user-2','project','profile'),historyKey(base,'user-1','other','profile'),historyKey(base,'user-1','project','other')]) assert.deepEqual(loadHistory(s,other),emptyHistory());
  saveHistory(s,key,emptyHistory()); assert.equal(s.getItem(key),null);
});
test('storage rejects corrupted history, duplicated IDs, missing receipt and excessive size without silent deletion', () => {
  const s=storage(), key='history';
  for (const raw of ['not json', JSON.stringify({version:2,dialogs:[]}),JSON.stringify({version:1,dialogs:[{id:DIALOG,createdAt:1,turns:[{id:TURN,question:'x',answer:'x',state:'completed',at:1}]}]}),JSON.stringify({version:1,dialogs:[{id:DIALOG,createdAt:1,turns:[]},{id:DIALOG,createdAt:2,turns:[]}]}),'x'.repeat(MAX_HISTORY_BYTES+1)]) {
    s.setItem(key,raw); assert.throws(()=>loadHistory(s,key)); assert.equal(s.getItem(key),raw);
  }
  assert.throws(()=>saveHistory({setItem(){throw Error('quota');},removeItem(){}},key,{version:1,dialogs:[{id:DIALOG,createdAt:1,turns:[]}]}));
});
test('transport accepts only HTTPS with no userinfo, query or fragments', () => {
  assert.equal(gatewayBase(base+'/path/'),base+'/path');
  for (const bad of ['http://localhost:8080','file:///etc/passwd','https://name:pass@example.com','https://example.com?token=foo','https://example.com/#x','relative']) assert.throws(()=>gatewayBase(bad),expectCode('invalid'));
  assert.throws(()=>historyKey(base,'','p','f'),expectCode('unauthorized'));
});
test('gateway HTTP failures and invalid content type are sanitized; no paid retry', async () => {
  const signal = new AbortController().signal;
  for (const [status,code] of [[400,'invalid'],[401,'unauthorized'],[403,'forbidden'],[429,'limit'],[503,'unavailable']]) {
    let calls=0; const f=async()=>{calls++;return new Response('raw secret provider error',{status});};
    await assert.rejects(streamChat(base,'access','hello',signal,()=>{},f),expectCode(code)); assert.equal(calls,1);
    await assert.rejects(fetchUsage(base,'access',signal,f),expectCode(code)); assert.equal(calls,2);
  }
  await assert.rejects(streamChat(base,'access','hello',signal,()=>{},async()=>new Response('html',{headers:{'Content-Type':'text/html'}})),expectCode('protocol'));
  await assert.rejects(fetchUsage(base,'access',signal,async()=>Response.json({model:'x',month:'2026-11',budgetMicroUsd:-1,usage:{}})),expectCode('protocol'));
});
test('actual HTTP fixture: request body, bearer, SSE deltas, usage and cancellation without replay', async t => {
  const calls=[]; let interrupted;
  const server=createServer(async(req,res)=>{
    if(req.url==='/api/v1/ai/usage') {calls.push(req.method+' '+req.url); res.setHeader('Content-Type','application/json'); res.end(JSON.stringify({model:'test',month:'2026-11',budgetMicroUsd:100,usage:{requests:1,chargedMicroUsd:17,uncertainRequests:0,inputTokens:5,outputTokens:2}})); return;}
    let body='';for await(const part of req)body+=part;calls.push({body:JSON.parse(body),bearer:req.headers.authorization,method:req.method,url:req.url});
    res.setHeader('Content-Type','text/event-stream; charset=utf-8');res.flushHeaders();res.write(start);res.write(event('delta',{delta:'Первый'}));
    if(JSON.parse(body).prompt==='cancel'){res.on('close',()=>interrupted?.());return;}
    setTimeout(()=>res.end(event('delta',{delta:' ответ'})+done),5);
  });
  server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>{server.closeAllConnections();server.close();});
  const local=`http://127.0.0.1:${server.address().port}`;
  // Only this test adapter rewrites the HTTPS address to the loopback HTTP fixture; production uses fetch directly.
  const fetcher=(url,options)=>{assert.ok(String(url).startsWith(base+'/'));assert.equal(options.redirect,'error');assert.equal(options.credentials,'omit');assert.equal(options.cache,'no-store');return fetch(local+String(url).slice(base.length),options);};
  const signal=new AbortController().signal;const usage=await fetchUsage(base,'test-access',signal,fetcher);assert.equal(usage.usage.chargedMicroUsd,17);
  let text='';const r=await streamChat(base,'test-access','hello',signal,d=>text+=d,fetcher);assert.equal(text,'Первый ответ');assert.equal(r.chargedMicroUsd,17);
  assert.deepEqual(calls[1],{body:{prompt:'hello'},bearer:'Bearer test-access',method:'POST',url:'/api/v1/ai/responses'});
  const cancel=new AbortController();const closed=new Promise(resolve=>{interrupted=resolve;});
  await assert.rejects(streamChat(base,'test-access','cancel',cancel.signal,()=>cancel.abort(),fetcher));
  await Promise.race([closed,new Promise((_,reject)=>{const timer=setTimeout(()=>reject(Error('server not cancelled')),2000);timer.unref();})]);
  assert.equal(calls.length,3);
});

const packet = bytes => ({kind:'chunk',data:Buffer.from(bytes).toString('base64')});
const validUsage = {model:'fixture',month:'2026-11',budgetMicroUsd:1000,usage:{requests:1,chargedMicroUsd:17,uncertainRequests:0,inputTokens:5,outputTokens:2}};
test('native channel packets use the actual parser, preserve UTF-8 and tolerate delayed final IPC delivery', async () => {
  const calls=[]; const wire=encode(start+event('delta',{delta:'Привет 🌍'})+done);
  const bridge={begin:async id=>{calls.push(['begin',id]);},cancel:async id=>{calls.push(['cancel',id]);},usage:async()=>validUsage,run:async(id,prompt,emit)=>{calls.push(['run',id,prompt]);setTimeout(()=>{for(const b of wire)emit(packet([b]));emit({kind:'end'});},5);}};
  let answer='';const signal=new AbortController().signal;
  assert.deepEqual(await nativeUsage(bridge,signal),validUsage);
  const result=await nativeStream(bridge,'question',signal,d=>answer+=d);
  assert.equal(answer,'Привет 🌍');assert.equal(result.chargedMicroUsd,17);
  assert.equal(calls[0][0],'begin');assert.deepEqual(calls[1],['run',calls[0][1],'question']);assert.deepEqual(calls[2],['cancel',calls[0][1]]);assert.equal(calls.length,3);
});
test('native cancellation during reservation never dispatches a paid request', async () => {
  const c=new AbortController();let release;let runs=0;let reserved;const cancelled=[];
  const bridge={begin:id=>{reserved=id;return new Promise(r=>{release=r;});},cancel:async id=>{cancelled.push(id);},usage:async()=>validUsage,run:async()=>{runs++;}};
  const work=nativeStream(bridge,'question',c.signal,()=>{});c.abort();release();
  await assert.rejects(work,expectCode('cancelled'));assert.equal(runs,0);assert.deepEqual(cancelled,[reserved]);
});
test('native cancellation after a delta, channel truncation, invalid packet and native error are not success', async () => {
  const c=new AbortController();let cancels=0;
  const defaults={begin:async()=>{},cancel:async()=>{cancels++;},usage:async()=>validUsage};
  const bridge={...defaults,run:async(id,prompt,emit)=>{emit(packet(encode(start+event('delta',{delta:'part'}))));}};
  await assert.rejects(nativeStream(bridge,'question',c.signal,()=>c.abort()),expectCode('cancelled'));assert.equal(cancels,1);
  const signal=new AbortController().signal;
  await assert.rejects(nativeStream({...defaults,run:async(id,prompt,emit)=>{emit(packet(encode(start)));emit({kind:'end'});}},'q',signal,()=>{}),expectCode('interrupted'));
  await assert.rejects(nativeStream({...defaults,run:async(id,prompt,emit)=>emit({kind:'chunk',data:'***'})},'q',signal,()=>{}),expectCode('protocol'));
  await assert.rejects(nativeStream({...defaults,run:async()=>{throw 'forbidden';}},'q',signal,()=>{}),expectCode('forbidden'));
  await assert.rejects(nativeUsage({...defaults,usage:async()=>{throw 'unauthorized';}},signal),expectCode('unauthorized'));
  const usageAbort=new AbortController();const pending=nativeUsage({...defaults,usage:()=>new Promise(()=>{})},usageAbort.signal);usageAbort.abort();await assert.rejects(pending,expectCode('cancelled'));
});
test('Credential preflight rejects new secrets and excludes contaminated previous turns',async()=>{
 assert.throws(()=>buildPrompt('password=example-secret',[],null),expectCode('sensitive'));
 const result=buildPrompt('normal question',[complete('password=example-secret','old')],null);assert.equal(result.included,0);assert.equal(result.prompt,'normal question');
 let calls=0;await assert.rejects(streamChat(base,'session','sk-proj-'+ 'x'.repeat(32),new AbortController().signal,()=>{},async()=>{calls++;throw Error('unexpected');}),expectCode('sensitive'));assert.equal(calls,0);
 await assert.rejects(parse(start+event('error',{requestId:ID,code:'provider_rate_limited'})),expectCode('limit'));
});

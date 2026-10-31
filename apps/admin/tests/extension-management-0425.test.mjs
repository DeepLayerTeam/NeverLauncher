import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ExtensionManagement0425, lifecyclePayload0425, verifyLifecycle0425 } from '../src/admin/extension_management_0425.ts';
const globalScope = {scope: 'global', scopeId: ''};
test('scope, version and channel are validated before a privileged request', () => {
  assert.deepEqual(lifecyclePayload0425('install', globalScope, '1.2.3'), {scope:'global', scopeId:'', version:'1.2.3'});
  assert.throws(() => lifecyclePayload0425('install', globalScope), /верси/);
  assert.throws(() => lifecyclePayload0425('update', globalScope, '1.2.3','stable'), /версию или канал/);
  assert.throws(() => lifecyclePayload0425('enable', {scope:'project',scopeId:''}), /область/);
  assert.throws(() => lifecyclePayload0425('update', globalScope, '', 'bad/channel'), /канал/);
});
test('lifecycle posts exact server action and checks response envelope', async () => {
  const old = globalThis.fetch;
  try {
    globalThis.fetch = async (url, options) => {
      assert.equal(url, 'https://backend.test/api/v1/admin/extension-installs/org.example.ext/update');
      assert.equal(options.method, 'POST');
      assert.equal(options.cache, 'no-store');
      assert.equal(options.headers.Authorization, 'Bearer admin-token');
      assert.deepEqual(JSON.parse(options.body), {scope:'global',scopeId:'',channel:'stable'});
      return {ok:true, json:async()=>({data:{status:'updated',install:{extensionId:'org.example.ext',generation:5}}})};
    };
    const manager = new ExtensionManagement0425('https://backend.test', 'admin-token');
    assert.equal((await manager.lifecycle('update', 'org.example.ext', globalScope,'','stable')).status,'updated');
  } finally { globalThis.fetch = old; }
});
test('backend errors, missing data and stale inventory fail closed', async () => {
  const old = globalThis.fetch;
  const mgr = new ExtensionManagement0425('https://backend.test', 'token');
  try {
    globalThis.fetch = async () => ({ok:false,status:409,statusText:'Conflict',json:async()=>({error:'quarantined package'})});
    await assert.rejects(mgr.lifecycle('enable','org.example.ext',globalScope), /quarantined package/);
    globalThis.fetch = async () => ({ok:true,json:async()=>({accepted:true})});
    await assert.rejects(mgr.installs(), /без data/);
  } finally {globalThis.fetch=old;}
  const before = [{extensionId:'org.example.ext', scope:'global', currentState:'disabled',currentVersion:'1.0.0', generation:4}];
  const after = [{...before[0],currentState:'enabled',generation:5}];
  assert.equal(verifyLifecycle0425('enable','org.example.ext',globalScope,before,after,{install:after[0]}),'enabled');
  assert.throws(()=>verifyLifecycle0425('enable','org.example.ext',globalScope,before,before,{install:after[0]}), /не подтверждено/);
});
test('quarantine release and emergency clear go to protected real endpoints',async()=>{
  const old=globalThis.fetch; const calls=[];
  try {
    globalThis.fetch = async (url, opts)=>{calls.push([url,opts.method,opts.body]);return {ok:true,json:async()=>({data:{status:'ok'}})};};
    const mgr=new ExtensionManagement0425('https://backend.test','secret');
    await mgr.releaseQuarantine('one/two');
    await mgr.emergencyClear('org.example.ext',globalScope);
    assert.match(calls[0][0], /quarantine\/one%2Ftwo\/release$/);
    assert.equal(calls[0][1], 'POST');
    assert.match(calls[1][0], /emergency-disable\?scope=global&scopeId=/);
    assert.equal(calls[1][1], 'DELETE');
  } finally {globalThis.fetch=old;}
});
test('installation, updates, rollback, removal require observed inventory transitions', () => {
  const before=[{extensionId:'org.example.ext',scope:'global',scopeId:'',currentState:'disabled',currentVersion:'1.0.0',generation:8}];
  const updated=[{...before[0],currentVersion:'1.1.0',generation:9}];
  assert.equal(verifyLifecycle0425('update','org.example.ext',globalScope,before,updated,{install:updated[0]}),'disabled');
  const rolled=[{...before[0],generation:10}];
  assert.equal(verifyLifecycle0425('rollback','org.example.ext',globalScope,updated,rolled,{install:rolled[0]}),'disabled');
  assert.equal(verifyLifecycle0425('uninstall','org.example.ext',globalScope,rolled,[],{install:{...rolled[0],currentState:'absent'}}),'absent');
  assert.equal(verifyLifecycle0425('install','org.example.ext',globalScope,[],before,{install:before[0]}),'disabled');
  assert.throws(()=>verifyLifecycle0425('install','org.example.ext',globalScope,before,before,{install:before[0]}),/не подтверждено/);
});

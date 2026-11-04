import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const root=new URL('../../../',import.meta.url);
const read=(name)=>readFileSync(new URL(name,root),'utf8');
const conf=JSON.parse(read('apps/desktop/src-tauri/tauri.conf.json'));
const capability=JSON.parse(read('apps/desktop/src-tauri/capabilities/desktop-main-0356.json'));
test('production CSP has no dev backend/socket or arbitrary native origins',()=>{
 const csp=conf.app.security.csp;
 for(const directive of ["script-src 'self'", "connect-src 'self' ipc: http://ipc.localhost https:","object-src 'none'","worker-src 'none'","form-action 'none'","frame-ancestors 'none'"])
  assert.ok(csp.includes(directive),directive);
 assert.doesNotMatch(csp,/http:\/\/localhost|http:\/\/127\.0\.0\.1|ws:|unsafe-eval|unsafe-inline'; object-src/);
 assert.match(conf.app.security.devCsp,/localhost:1420/);
});
test('Tauri exposes only minimal local core event capabilities',()=>{
 assert.deepEqual(conf.app.security.capabilities,['desktop-main-0356']);
 assert.deepEqual(capability.windows,['main']);
 assert.ok(!capability.remote);
 assert.deepEqual(capability.permissions,['core:event:allow-listen','core:event:allow-unlisten']);
});
test('native path opening is bounded to saved game directory and external navigation uses system browser',()=>{
 const rust=read('apps/desktop/src-tauri/src/main.rs');
 assert.match(rust,/async fn open_external_https_0356/);
 assert.match(rust,/url\.scheme\(\) != "https"/);
 assert.match(rust,/requested != safe/);
 const component=read('apps/desktop/src/extensions_0209.tsx');
 assert.match(component,/sandbox="allow-scripts"/);
 assert.doesNotMatch(component,/sandbox="allow-scripts allow-same-origin"/);
 assert.match(component,/bridge\.authorize/);
});

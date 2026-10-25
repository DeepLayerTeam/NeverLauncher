import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
test('desktop Sentry error redaction and opted-in report tests execute',()=>{
 const args=['src/sentry_diagnostics_0309.ts','--module','es2020','--target','es2020','--strict','--skipLibCheck','--lib','es2020,dom','--outDir','build-tests'];
 const compile=spawnSync('tsc',args,{cwd:'apps/desktop',encoding:'utf8',timeout:30000});
 assert.equal(compile.status,0,compile.stderr+compile.stdout);
 const env={...process.env}; delete env.NODE_TEST_CONTEXT;
 const result=spawnSync('node',['--test','tests/sentry_diagnostics_0309.test.mjs'],{cwd:'apps/desktop',encoding:'utf8',timeout:30000,env});
 assert.equal(result.status,0,result.stderr+result.stdout);
 assert.match(result.stdout,/# pass 2/);
});

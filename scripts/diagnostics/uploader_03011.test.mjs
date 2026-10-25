import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
test('Sentry JVM mapping and JS source map uploader executes three actual regression tests',()=>{
 const run=spawnSync('python3',['scripts/diagnostics/test_upload_release_0309.py'],{encoding:'utf8',timeout:30000});
 assert.equal(run.status,0,run.stderr);
 assert.match(run.stderr,/Ran 3 tests/);
 assert.match(run.stderr,/OK/);
});

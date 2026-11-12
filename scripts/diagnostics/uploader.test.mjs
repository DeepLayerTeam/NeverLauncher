import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
test('Загрузчик карт JVM и исходных карт JS для Sentry выполняет четыре реальных регрессионных теста',()=>{
 const run=spawnSync('python3',['scripts/diagnostics/test_upload_release.py'],{encoding:'utf8',timeout:30000});
 assert.equal(run.status,0,run.stderr);
 assert.match(run.stderr,/Ran 4 tests/);
 assert.match(run.stderr,/OK/);
});

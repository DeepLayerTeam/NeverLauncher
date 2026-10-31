import test from 'node:test';
import assert from 'node:assert/strict';
import {startupStatus0427} from '../src/startup_screen_0427.ts';

test('startup screen reports actual state without synthetic progress',()=>{
  const waiting = startupStatus0427('java','ru');
  assert.equal(waiting.active,true);
  assert.match(waiting.message,/Java/);
  assert.equal(waiting.failed,false);
  const ready=startupStatus0427('ready','en');
  assert.equal(ready.active,false);
  assert.match(ready.message,/ready/);
});
test('failed startup exposes retry state; it is never shown as ready',()=>{
  const failed=startupStatus0427('failed','ru');
  assert.equal(failed.failed,true);
  assert.equal(failed.active,false);
  assert.doesNotMatch(failed.message,/клиент готов/i);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {bytes0354, duration0354, progress0354, recovery0354} from '../build-tests/download_experience_0354.js';
const sample = (props = {}) => ({operationId:'op',phase:'downloading',totalFiles:2,queued:0,active:1,completed:1,
  failed:0,skipped:0,bytesExpected: 1000,bytesTransferred:1700,bytesVerified:500,
  speedBytesPerSecond:250,etaSeconds:2,cacheHits:0,bytesReused:0,...props});
test('verified bytes, not duplicate wire bytes, drive truthful percentage', () => {
  assert.equal(progress0354(sample()).percent, 50);
  assert.equal(progress0354(sample({phase:'staged',bytesVerified:1000})).completed, false);
  assert.equal(progress0354(sample({phase:'publishing'})).canInterrupt, false);
  assert.equal(progress0354(sample({phase:'completed'})).percent, 100);
});
test('unknown ETA never becomes zero, and numeric output is bounded', () => {
  assert.equal(progress0354(sample({etaSeconds:null,speedBytesPerSecond:0})).eta, 'рассчитывается');
  assert.equal(progress0354(sample({bytesExpected:0,bytesVerified:0})).percent, 0);
  assert.equal(progress0354(sample({bytesExpected:100,bytesVerified:999})).percent, 100);
  assert.equal(duration0354(75), '1 мин 15 с');
  assert.equal(bytes0354(1048576), '1.0 МиБ');
});
test('security errors never recommend bypassing trust or retrying insecure bundles', () => {
  const error = recovery0354('saved download public key differs from Desktop pinned trust key');
  assert.equal(error.action,'none');
  assert.match(error.instruction,/подписанный bundle/);
});
test('disk, network, integrity, and player-owned conflicts yield one concrete recovery', () => {
  assert.equal(recovery0354('insufficient free space').action,'retry');
  assert.equal(recovery0354('[retry:300] HTTP 503').action,'retry');
  assert.equal(recovery0354('staged client file failed SHA-256').action,'repair');
  assert.equal(recovery0354('untracked user file conflicts with new managed path').action,'repair');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { automaticCheckDue, DEFAULT_UPDATE_PREFERENCES as defaults, isUpdateBusy, progressPercent, readUpdatePreferences, updateFailure, previousInstallFailed } from '../build-tests/native_update_experience.js';
const hour = 3600000;
test('missing or malformed preferences use safe defaults; no automatic install/download', () => {
  for (const input of [null, 'bad json', 'null', '42', '{}']) assert.deepEqual(readUpdatePreferences(input), defaults);
});
test('valid preferences roundtrip and reject unsupported intervals or types', () => {
  const prefs = {autoCheck:true,autoDownload:true,intervalHours:6};
  assert.deepEqual(readUpdatePreferences(JSON.stringify(prefs)), prefs);
  assert.deepEqual(readUpdatePreferences('{"autoCheck":false,"autoDownload":true,"intervalHours":1}'), {autoCheck:false,autoDownload:false,intervalHours:24});
  assert.deepEqual(readUpdatePreferences('{"autoCheck":"false","autoDownload":"true","intervalHours":"6"}'), defaults);
});
test('startup and every configured interval, including weekly', () => {
  for (const intervalHours of [6,24,168]) {
    const prefs={...defaults,intervalHours};
    assert.equal(automaticCheckDue(prefs,'idle',null,100),true);
    assert.equal(automaticCheckDue(prefs,'available',100,100+intervalHours*hour-1),false);
    assert.equal(automaticCheckDue(prefs,'available',100,100+intervalHours*hour),true);
  }
});
test('automatic check disabled and no concurrent checks or invalidation of ready package', () => {
  assert.equal(automaticCheckDue({...defaults,autoCheck:false},'idle',null,100),false);
  for (const phase of ['checking','downloading','verifying','installing','scheduled','ready','disabled']) assert.equal(automaticCheckDue(defaults,phase,null,100),false,phase);
  assert.equal(isUpdateBusy('ready'),false);
  assert.equal(isUpdateBusy('scheduled'),true);
});
test('network failure uses 15 minute backoff, system clock rollback recovers', () => {
  assert.equal(automaticCheckDue(defaults,'error',100,100+900000-1),false);
  assert.equal(automaticCheckDue(defaults,'error',100,100+900000),true);
  assert.equal(automaticCheckDue(defaults,'current',100,99),true);
});
test('known, unknown and malformed download sizes', () => {
  const p=(downloaded,total)=>progressPercent({stage:'download',downloaded,total});
  assert.equal(p(0,10),0); assert.equal(p(1,3),33); assert.equal(p(10,10),100); assert.equal(p(11,10),100);
  for (const total of [null,0,-1,Infinity,NaN]) assert.equal(p(1,total),null);
  assert.equal(p(-1,10),null); assert.equal(p(Infinity,10),null);
});

test('recoverable interruptions and rejected packages have distinct states and backoff', () => {
  assert.deepEqual(updateFailure('retry: interrupted'), {phase:'retry',message:'interrupted'});
  assert.deepEqual(updateFailure('rejected: invalid signature'), {phase:'rejected',message:'invalid signature'});
  assert.deepEqual(updateFailure('expired: recheck'), {phase:'error',message:'recheck'});
  assert.equal(automaticCheckDue(defaults,'retry',0,900000),true);
  assert.equal(automaticCheckDue(defaults,'rejected',0,900000),false);
  assert.equal(automaticCheckDue(defaults,'rejected',0,24*hour),true);
});
test('unconfirmed install suppresses automatic download of the same release', () => {
  const offer={status:'available',currentVersion:'1.1.3',version:'1.1.4',notes:null};
  assert.equal(previousInstallFailed('1.1.4',offer),true);
  assert.equal(previousInstallFailed('1.1.2',offer),false);
  assert.equal(previousInstallFailed(null,offer),false);
  assert.equal(previousInstallFailed('1.1.4',{...offer,status:'current',currentVersion:'1.1.4',version:null}),false);
});

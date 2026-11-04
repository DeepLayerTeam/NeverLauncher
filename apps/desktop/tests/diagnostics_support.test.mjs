import test from 'node:test';
import assert from 'node:assert/strict';
import { ensureReviewedDiagnostic03510 } from '../build-tests/diagnostics_support_03510.js';

const report={schemaVersion:'1.1',launcherVersion:'0.35.10',generatedAtUnix:12345,os:'linux',arch:'x86_64',stage:'failed',events:[{code:'download',count:1}]};
const preview={reviewToken:'a'.repeat(48),report};
test('no report upload without explicit consent and authenticated session',()=>{
  assert.throws(()=>ensureReviewedDiagnostic03510(preview,false,'access-token'),/подтвердите/);
  assert.throws(()=>ensureReviewedDiagnostic03510(preview,true,undefined),/войдите/);
  assert.throws(()=>ensureReviewedDiagnostic03510(null,true,'access-token'),/предпросмотр/);
});
test('only reviewed native report categories are accepted',()=>{
  assert.equal(ensureReviewedDiagnostic03510(preview,true,'access-token'),report);
  assert.throws(()=>ensureReviewedDiagnostic03510({...preview,report:{...report,events:[{code:'Bearer SECRET',count:1}]}},true,'access-token'),/неподдерживаемые/);
  assert.throws(()=>ensureReviewedDiagnostic03510({...preview,report:{...report,stage:'file:///private'}},true,'access-token'),/безопасному/);
  assert.throws(()=>ensureReviewedDiagnostic03510({...preview,reviewToken:'bad'},true,'access-token'),/предпросмотр/);
});

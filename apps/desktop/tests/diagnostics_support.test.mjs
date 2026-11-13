import test from 'node:test';
import assert from 'node:assert/strict';
import { ensureReviewedDiagnostic03510 } from '../build-tests/diagnostics_support.js';

const report={schemaVersion:'1.1',launcherVersion:'0.35.10',generatedAtUnix:12345,os:'linux',arch:'x86_64',stage:'failed',events:[{code:'download',count:1}]};
const preview={reviewToken:'a'.repeat(48),report};
test('Отчёт не отправляется без явного согласия и авторизованного сеанса',()=>{
  assert.throws(()=>ensureReviewedDiagnostic03510(preview,false,'access-token'),/подтвердите/);
  assert.throws(()=>ensureReviewedDiagnostic03510(preview,true,undefined),/войдите/);
  assert.throws(()=>ensureReviewedDiagnostic03510(null,true,'access-token'),/предпросмотр/);
});
test('Принимаются только проверенные категории нативных отчётов',()=>{
  assert.equal(ensureReviewedDiagnostic03510(preview,true,'access-token'),report);
  assert.throws(()=>ensureReviewedDiagnostic03510({...preview,report:{...report,events:[{code:'Bearer SECRET',count:1}]}},true,'access-token'),/неподдерживаемые/);
  assert.throws(()=>ensureReviewedDiagnostic03510({...preview,report:{...report,stage:'file:///private'}},true,'access-token'),/безопасному/);
  assert.throws(()=>ensureReviewedDiagnostic03510({...preview,reviewToken:'bad'},true,'access-token'),/предпросмотр/);
});

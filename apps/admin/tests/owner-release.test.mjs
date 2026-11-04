import test from 'node:test';
import assert from 'node:assert/strict';
import {requireValidatedPackage0390} from '../src/admin/package-validation-0390.ts';
import {observeOwnerOperation} from '../src/admin/owner-lifecycle-03513.ts';
import {ReleaseApi} from '../src/api/release.ts';

const expected={projectId:'alpha',profileId:'main',channel:'stable',revision:5,releaseId:'old'};
const intent={kind:'channel-rollback',projectId:'alpha',profileId:'main',channel:'stable',toVersion:'1.0',idempotencyKey:'same-key'};
const pending={intent,before:expected,jobId:'job-1'};
test('HTTP 200 invalid Validate is NEVER a success (including quick Admin workflow)',()=>{
 assert.throws(()=>requireValidatedPackage0390({status:'invalid',blockers:[{reasonCode:'package-files-empty',resource:'files.present',message:'empty',action:'upload'}]}),/package-files-empty.*upload/);
 assert.throws(()=>requireValidatedPackage0390({status:'valid',checks:[{id:'file',status:'failed',message:'wrong hash'}]}),/wrong hash/);
 assert.throws(()=>requireValidatedPackage0390({status:'valid'}),/нет подтверждения/);
 assert.equal(requireValidatedPackage0390({status:'valid',checks:[{id:'file',status:'ok'}]}).status,'valid');
});
test('rollback cannot observe a job for another channel even with identical project/kind',async()=>{
 const old=globalThis.fetch;
 try{
  globalThis.fetch=async()=>({ok:true,status:200,json:async()=>({data:{id:'job-1',kind:'channel-rollback',projectId:'alpha',resourceId:'beta',status:'succeeded',result:{status:'rolled-back-as-new-validated-immutable-release',packageId:'new'}}})});
  await assert.rejects(observeOwnerOperation(new ReleaseApi('https://example.test','token'),pending),/не соответствует/);
 }finally{globalThis.fetch=old}
});
test('rollback cannot observe another job id even when resource is identical',async()=>{
 const old=globalThis.fetch;
 try{
  globalThis.fetch=async()=>({ok:true,status:200,json:async()=>({data:{id:'other-job',kind:'channel-rollback',projectId:'alpha',resourceId:'stable',status:'succeeded'}})});
  await assert.rejects(observeOwnerOperation(new ReleaseApi('https://example.test','token'),pending),/не соответствует/);
 }finally{globalThis.fetch=old}
});

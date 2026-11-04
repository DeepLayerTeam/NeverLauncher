import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError } from '../src/api/client.ts';
import { ReleaseApi } from '../src/api/release.ts';

test('Admin preserves exact backend publish refusal with per-file repair actions',async()=>{
 const original=globalThis.fetch;
 const blockers=[{reasonCode:'file-integrity-mismatch',resource:'mods/broken.jar',message:'SHA-256 differs',action:'Replace this file and revalidate'},
 {reasonCode:'stable-runtime-target-blocked',resource:'linux-amd64',message:'missing attestation',action:'Run real target'}];
 try {
  globalThis.fetch=async()=>({ok:false,status:409,statusText:'Conflict',json:async()=>({error:{reasonCode:'publish-blocked',message:'publish blocked',blockers}})});
  const api=new ReleaseApi('https://backend.test','token');
  await assert.rejects(api.validateOperation({kind:'package-publish',resourceId:'p1',projectId:'demo'}),err=>{
   assert.ok(err instanceof ApiError);assert.equal(err.status,409);assert.equal(err.reasonCode,'publish-blocked');assert.deepEqual(err.blockers,blockers);return true;
  });
 } finally{globalThis.fetch=original}
});

test('Admin obtains live readiness from existing validations endpoint',async()=>{
 const original=globalThis.fetch;const calls=[];
 try {
  globalThis.fetch=async(url,init)=>{calls.push([url,init]);return {ok:true,status:200,json:async()=>({data:{integrity:null,runtime:[],policy:{requiredLevel:'integrity',requireServerJoin:false},publishReadiness:{packageId:'pkg-385',eligible:false,finalRecheckRequired:true,blockers:[{reasonCode:'package-files-empty',resource:'files.present',message:'empty',action:'upload'}]}}})}};
  const api=new ReleaseApi('https://backend.test/','token');const report=await api.validations('pkg-385');
  assert.equal(report.publishReadiness.eligible,false);assert.equal(report.publishReadiness.blockers[0].reasonCode,'package-files-empty');
  assert.equal(new URL(calls[0][0]).pathname,'/api/v1/packages/pkg-385/validations');assert.equal(calls[0][1].headers.get('Authorization'),'Bearer token');
 }finally{globalThis.fetch=original}
});

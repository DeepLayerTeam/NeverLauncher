import test from 'node:test';
import assert from 'node:assert/strict';
import { durableOwnerKey, findOriginalOwnerJob } from '../src/admin/owner-recovery-0388.ts';
import { ReleaseApi } from '../src/api/release.ts';
import { readOwnerPending, saveOwnerPending } from '../src/admin/owner-lifecycle-03513.ts';

const intent={kind:'package-publish',projectId:'p1',profileId:'fabric',channel:'stable',resourceId:'pkg1',idempotencyKey:'lost-response-0388'};
const record={intent,before:{projectId:'p1',profileId:'fabric',channel:'stable',revision:4,releaseId:'old'}};
function storage(){const map=new Map();return {getItem:k=>map.get(k)||null,setItem:(k,v)=>map.set(k,v),removeItem:k=>map.delete(k)};}
const key=()=>durableOwnerKey('https://api.example/','actor-1','p1');
test('rotation of session does not orphan pending owner intent, but actor and backend remain isolated',()=>{
 const s=storage();saveOwnerPending(s,key(),record);
 assert.deepEqual(readOwnerPending(s,durableOwnerKey('https://api.example','actor-1','p1'),'p1'),record);
 assert.equal(readOwnerPending(s,durableOwnerKey('https://api.example','actor-2','p1'),'p1'),null);
 assert.equal(readOwnerPending(s,durableOwnerKey('https://other.example','actor-1','p1'),'p1'),null);
 assert.notEqual(key(),durableOwnerKey('https://api.example','actor-1','p1','operations'));
 assert.throws(()=>durableOwnerKey('https://api.example','','p1'));
});
test('lost ACK is resolved with GET and exact stored key, without replaying a POST',async()=>{
 const old=globalThis.fetch;
 const calls=[];
 try{
  globalThis.fetch=async(url,init)=>{calls.push([url,init]);return {ok:true,status:200,json:async()=>({data:{id:'job-original',projectId:'p1',kind:'package-publish',resourceId:'pkg1',status:'pending'}})}};
  const job=await findOriginalOwnerJob(new ReleaseApi('https://api.example','bearer'),record);
  assert.equal(job?.id,'job-original');assert.equal(calls.length,1);assert.equal(calls[0][1].method,undefined);
  assert.match(calls[0][0],/operations\/recover\?projectId=p1&kind=package-publish&idempotencyKey=lost-response-0388/);
 }finally{globalThis.fetch=old}
});
test('missing journal entry is not permission to create another job; mismatch fails closed',async()=>{
 const old=globalThis.fetch;
 try{
  globalThis.fetch=async()=>({ok:false,status:404,statusText:'Not Found',json:async()=>({error:{message:'not found'}})});
  assert.equal(await findOriginalOwnerJob(new ReleaseApi('https://api.example','bearer'),record),null);
  globalThis.fetch=async()=>({ok:true,status:200,json:async()=>({data:{id:'job-foreign',projectId:'other',kind:'package-publish',resourceId:'pkg1'}})});
  await assert.rejects(findOriginalOwnerJob(new ReleaseApi('https://api.example','bearer'),record),/does not match/);
 }finally{globalThis.fetch=old}
});

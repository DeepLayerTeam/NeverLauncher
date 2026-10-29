import {test} from 'node:test';
import assert from 'node:assert/strict';
import {channelHistory0386} from '../src/admin/release-history-0386.ts';
import {observeOwnerOperation} from '../src/admin/owner-lifecycle-03513.ts';
import {ReleaseApi} from '../src/api/release.ts';
const before={projectId:'p',profileId:'fabric',channel:'dev',revision:3,releaseId:'old'};
const entries=[{id:'old',version:'1.0',profileId:'fabric',channel:'dev',status:'published',publishedAt:'2026-09-01T10:00:00Z'},
 {id:'new',version:'2.0',profileId:'fabric',channel:'dev',status:'published',publishedAt:'2026-10-01T10:00:00Z'},
 {id:'draft',version:'3.0',profileId:'fabric',channel:'dev',status:'draft'},
 {id:'elsewhere',version:'3.0',profileId:'other',channel:'dev',status:'published'}];
test('history is scoped, date-sorted and excludes current head from rollback',()=>{
 const a=channelHistory0386(entries,'p','fabric','dev',{...before,revision:4,releaseId:'new'});
 assert.deepEqual(a.history.map(x=>x.id),['new','old']);
 assert.deepEqual(a.rollbackTargets.map(x=>x.id),['old']);
});
test('missing, mismatched or erroneous head blocks rollback selection',()=>{
 for (const head of [null,{...before,profileId:'other'},{...before,revision:-1}])
  assert.equal(channelHistory0386(entries,'p','fabric','dev',head).rollbackTargets.length,0);
 assert.equal(channelHistory0386(entries,'p','fabric','dev',before,'network error').rollbackTargets.length,0);
});
test('successful durable job requires exact release id, result and one channel revision',async()=>{
 const intent={kind:'package-publish',projectId:'p',profileId:'fabric',channel:'dev',resourceId:'new',idempotencyKey:'k'};
 const oldFetch=globalThis.fetch;
 let nextHead={...before,revision:4,releaseId:'new'};
 let nextResult={status:'published',releaseId:'new'};
 try{
   globalThis.fetch=async url=>({ok:true,json:async()=>({data:new URL(url).pathname.includes('/operations/')?
     {id:'job',kind:'package-publish',projectId:'p',resourceId:'new',status:'succeeded',result:nextResult}:nextHead})});
   const api=new ReleaseApi('https://example.test','token');
   assert.equal((await observeOwnerOperation(api,{intent,before,jobId:'job'})).phase,'confirmed');
   nextHead={...nextHead,revision:5};
   assert.equal((await observeOwnerOperation(api,{intent,before,jobId:'job'})).phase,'unconfirmed');
   nextHead={...nextHead,revision:4};nextResult={status:'published',releaseId:'impostor'};
   assert.equal((await observeOwnerOperation(api,{intent,before,jobId:'job'})).phase,'unconfirmed');
 }finally{globalThis.fetch=oldFetch;}
});

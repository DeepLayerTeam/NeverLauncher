import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canSeeSection } from '../src/admin/permissions.ts';
import { endpointForSection } from '../src/admin/sections.ts';
import { requestJSON, ApiError } from '../src/api/client.ts';

const admin = {user:{id:'u1',email:'owner@example.test',roleId:'admin'}, permissions:['settings:manage','audit:read'], projectPermissions:{}};
const viewer = {user:{id:'u2',email:'viewer@example.test',roleId:'viewer'}, permissions:[], projectPermissions:{a:['project:read']}};
test('configuration workspace is global settings:manage only; audit read is separate',()=>{
 assert.equal(canSeeSection(admin,'config',''),true);
 assert.equal(canSeeSection(viewer,'config','a'),false);
 assert.equal(canSeeSection(admin,'audit',''),true);
 assert.equal(canSeeSection(viewer,'audit','a'),false);
 assert.equal(endpointForSection('config','a'),'/api/v1/admin/config');
});
test('config CAS request and audit query use authorized Backend and preserve reasonCode', async()=>{
 const old = globalThis.fetch;
 try {
   globalThis.fetch = async (url, init) => {
     assert.equal(url,'https://backend.example/api/v1/admin/config/validate');
     assert.equal(init.headers.get('Authorization'),'Bearer admin-token');
     const body=JSON.parse(init.body);
     assert.equal(body.expectedRevision,4);
     assert.equal(body.settings.auditLookbackDays,90);
     return { ok:false, status:409, statusText:'Conflict',json:async()=>({error:{code:409,reasonCode:'revision_conflict',message:'Reload the revision'}}) };
   };
   await assert.rejects(requestJSON('https://backend.example','/api/v1/admin/config/validate','admin-token',{method:'POST',body:JSON.stringify({expectedRevision:4,reason:'extend search period',settings:{auditLookbackDays:90}})}),e=> e instanceof ApiError && e.status===409 && e.reasonCode==='revision_conflict');
 } finally {globalThis.fetch=old;}
});

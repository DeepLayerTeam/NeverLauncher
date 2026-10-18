import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ReleaseApi} from '../src/api/release.ts';
import {canSeeSection} from '../src/admin/permissions.ts';
import {endpointForSection} from '../src/admin/sections.ts';

const subject={user:{id:'id1',email:'test@example.test',roleId:'release-manager'}, permissions:[],projectPermissions:{alpha:['project:read','release:prepare','release:publish'],beta:['project:read']}};
test('Release Workspace UI navigation depends on actual scoped permission',()=>{
 assert.equal(canSeeSection(subject,'release-workspace','alpha'),true);
 assert.equal(canSeeSection(subject,'release-workspace','beta'),false);
 assert.equal(canSeeSection(subject,'job-monitor','beta'),true);
 assert.equal(endpointForSection('release-workspace','alpha'),'/api/v1/release-drafts');
});
test('Release API sends typed draft updates, user-authenticated validation and durable operations',async()=>{
 const visited=[];const original=globalThis.fetch;
 try {
  globalThis.fetch=async (url,init)=>{visited.push([url,init]);return {ok:true,json:async()=>({data:{id:'draft-1',projectId:'alpha',revision:2,items:[]}})};};
  const api=new ReleaseApi('https://example.test/','secret');
  const fields={projectId:'alpha',profileId:'vanilla',channel:'stable',version:'1.0',minecraftVersion:'1.21.1',loader:'vanilla',packageId:'',jobId:'',step:'build'};
  await api.create(fields);
  await api.save({id:'draft-1',ownerId:'me',revision:1,createdAt:'',updatedAt:'',...fields});
  await api.packageAction('package-one','sign');
  await api.validateOperation({kind:'package-publish',projectId:'alpha',resourceId:'package-one',idempotencyKey:'key-one'});
  await api.executeOperation({kind:'package-publish',projectId:'alpha',resourceId:'package-one',idempotencyKey:'key-one'});
  assert.deepEqual(visited.map(([url,req])=>[new URL(url).pathname,req.method]),[
   ['/api/v1/release-drafts','POST'],['/api/v1/release-drafts/draft-1','PUT'],['/api/v1/packages/package-one/sign','POST'],['/api/v1/operations/validate','POST'],['/api/v1/operations/execute','POST']]);
  for(const [,req] of visited){assert.equal(req.headers.get('Authorization'),'Bearer secret');assert.equal(req.cache,'no-store');}
  assert.equal(JSON.parse(visited[1][1].body).revision,1);
 } finally{globalThis.fetch=original;}
});

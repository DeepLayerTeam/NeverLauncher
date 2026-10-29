import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nodeForContext0383, profileNodes0383, nodeState0383 } from '../src/admin/server-selection-0383.ts';
import { parseAdminRoute, adminHref } from '../src/admin/route-links-0381.ts';
import { resolveProjectContext, readSavedContext, saveContext } from '../src/admin/project-context-0381.ts';
const now=Date.now();
const identity={runtimeId:'b'.repeat(64),runtimeEpoch:3,protocolVersion:3,status:'active',fresh:true,lastHeartbeatAt:new Date(now-1000).toISOString()};
const nodes=[{...identity,id:'a-server',projectId:'alpha',profileId:'a-profile',telemetry:{sampledAtUnixMillis:now-1500,runtimeId:'b'.repeat(64),runtimeEpoch:3}},
  {...identity,id:'b-server',projectId:'beta',profileId:'b-profile',lastHeartbeatAt:new Date(now-200_000).toISOString()}];
const catalog={projects:[{id:'alpha'},{id:'beta'}],profiles:[{id:'a-profile',projectId:'alpha'},{id:'b-profile',projectId:'beta'}],channels:[{id:'stable',projectId:'alpha'},{id:'beta',projectId:'beta'}],servers:nodes};
test('server deep links round-trip with owner context and cannot cross projects',()=>{
  const ctx={projectId:'alpha',profileId:'a-profile',channelId:'stable',serverId:'a-server'};
  for(const section of ['server-bridge','profiles','release-workspace'])assert.deepEqual(parseAdminRoute(adminHref(section,ctx)),{section,...ctx});
  assert.deepEqual(resolveProjectContext(ctx,ctx,catalog),ctx);
  assert.equal(resolveProjectContext({...ctx,serverId:'b-server'},ctx,catalog).serverId,undefined);
  assert.deepEqual(resolveProjectContext({projectId:'beta',profileId:'b-profile',channelId:'beta'},ctx,catalog),{projectId:'beta',profileId:'b-profile',channelId:'beta'});
  assert.equal(resolveProjectContext({...ctx,profileId:'b-profile'},ctx,catalog).profileId,'');
  assert.equal(resolveProjectContext({...ctx,serverId:'\u0000hijack'},ctx,catalog).serverId,undefined);
});
test('server hint persists only as a preference and is always revalidated against live inventory',()=>{
  const store=new Map();const storage={getItem:k=>store.get(k)??null,setItem:(k,v)=>store.set(k,v)};
  saveContext(storage,'x',{projectId:'alpha',profileId:'a-profile',channelId:'stable',serverId:'a-server'});
  const cached=readSavedContext(storage,'x');assert.equal(cached.serverId,'a-server');
  assert.equal(resolveProjectContext(cached,cached,{...catalog,servers:[]}).serverId,undefined);
  assert.equal(nodeForContext0383(nodes,'alpha','b-server'),null);
  assert.equal(nodeForContext0383(nodes,'alpha','a-server').profileId,'a-profile');
  assert.deepEqual(profileNodes0383(nodes,'alpha','a-profile').map(n=>n.id),['a-server']);
});
test('node status distinguishes backend outage, signed heartbeat, control readiness and telemetry',()=>{
  assert.equal(nodeState0383(nodes[0],true,now).status,'available');
  assert.equal(nodeState0383(nodes[0],false,now).status,'unknown');
  assert.equal(nodeState0383(nodes[1],true,now).status,'unavailable');
  assert.equal(nodeState0383({...nodes[0],protocolVersion:2},true,now).status,'unavailable');
  assert.equal(nodeState0383({...nodes[0],telemetry:undefined},true,now).telemetry,'unknown');
  assert.equal(nodeState0383({...nodes[0],fresh:false},true,now).status,'unavailable');
});

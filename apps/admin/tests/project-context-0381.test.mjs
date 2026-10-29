import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adminHref, parseAdminRoute } from '../src/admin/route-links-0381.ts';
import { contextStorageKey, readSavedContext, resolveProjectContext, saveContext } from '../src/admin/project-context-0381.ts';

const catalog = {
  projects:[{id:'alpha',name:'Alpha'},{id:'beta',name:'Beta'}],
  profiles:[{id:'a-main',projectId:'alpha'},{id:'b-main',projectId:'beta'}],
  channels:[{id:'stable',projectId:'alpha'},{id:'test',projectId:'beta'}],
};
const empty = {projectId:'',profileId:'',channelId:''};
const fakeStorage = () => {
  const data = new Map();
  return {getItem:k=>data.get(k)??null,setItem:(k,v)=>data.set(k,v),removeItem:k=>data.delete(k)};
};

test('real Admin resource routes are addressable and survive hash-based reload/back/forward', () => {
  const state={projectId:'alpha',profileId:'a-main',channelId:'stable'};
  for(const section of ['projects','profiles','channels','packages','release-workspace','server-bridge']) {
    const href=adminHref(section,state);
    assert.deepEqual(parseAdminRoute(href),{section,...state});
  }
  assert.deepEqual(parseAdminRoute(adminHref('profiles',{projectId:'a b/ä',profileId:'é&/ profile'})),{
    section:'profiles',projectId:'a b/ä',profileId:'é&/ profile',
  });
  assert.equal(parseAdminRoute('#/unknown').section,'dashboard');
  assert.equal(parseAdminRoute('#/%E0%A4%A').section,'dashboard');
});

test('only an authenticated owner and backend share their own persisted context', () => {
  const storage=fakeStorage();
  const alice=contextStorageKey('https://api.test:443/','alice');
  const other=contextStorageKey('https://api.test/','bob');
  const otherBackend=contextStorageKey('https://other.test/','alice');
  assert.notEqual(alice,other);
  assert.notEqual(alice,otherBackend);
  saveContext(storage,alice,{projectId:'alpha',profileId:'a-main',channelId:'stable'});
  assert.deepEqual(readSavedContext(storage,alice),{projectId:'alpha',profileId:'a-main',channelId:'stable'});
  assert.deepEqual(readSavedContext(storage,other),empty);
});

test('changing projects discards stale profile/channel IDs and forbids cross-project selection', () => {
  const saved={projectId:'alpha',profileId:'a-main',channelId:'stable'};
  assert.deepEqual(resolveProjectContext({projectId:'beta'},saved,catalog),{projectId:'beta',profileId:'',channelId:''});
  assert.deepEqual(resolveProjectContext({projectId:'alpha'},saved,catalog),{projectId:'alpha',profileId:'',channelId:''}); // explicit clearing works
  assert.deepEqual(resolveProjectContext({projectId:'beta',profileId:'a-main',channelId:'stable'},saved,catalog),{projectId:'beta',profileId:'',channelId:''});
  assert.deepEqual(resolveProjectContext({projectId:'beta',profileId:'b-main',channelId:'test'},saved,catalog),{projectId:'beta',profileId:'b-main',channelId:'test'});
});

test('unknown/inaccessible project and deleted resources are removed by the live catalog', () => {
  const saved={projectId:'alpha',profileId:'a-main',channelId:'stable'};
  assert.deepEqual(resolveProjectContext({projectId:'forbidden',profileId:'invisible'},saved,catalog),saved);
  assert.deepEqual(resolveProjectContext(saved,saved,{...catalog,profiles:[],channels:[]}),{projectId:'alpha',profileId:'',channelId:''});
  assert.deepEqual(resolveProjectContext(saved,saved,{projects:[],profiles:[],channels:[]}),empty);
  assert.deepEqual(resolveProjectContext({},empty,catalog),{projectId:'alpha',profileId:'',channelId:''});
});

test('malformed, oversized and control-character context does not become trusted navigation', () => {
  const storage=fakeStorage();
  storage.setItem('bad','{unclosed');
  assert.deepEqual(readSavedContext(storage,'bad'),empty);
  storage.setItem('oversize',JSON.stringify({projectId:'x'.repeat(2000),profileId:'foo\u0000bar'}));
  assert.deepEqual(readSavedContext(storage,'oversize'),empty);
  assert.equal(parseAdminRoute('#/projects?project='+('x'.repeat(2000))).projectId,undefined);
});

import {test} from 'node:test';
import assert from 'node:assert/strict';
import {OfficialMinecraftClient0257} from '../build-tests/official_minecraft_0257.js';

function mockResponse(data, status = 200, headers = {}) {
 return {ok: status >= 200 && status < 300, status, headers: {get: key => headers[key] || null}, json: async () => ({data})};
}

test('official device authorization, selected account, refresh, and isolation', async () => {
 const originalFetch = globalThis.fetch;
 const originalDate = Date.now;
 const requests = [];
 let count = 0;
 globalThis.fetch = async (url, options) => {
  requests.push({url, options});
  const path = new URL(url).pathname;
  if (path.endsWith('/device/start')) return mockResponse({flow:'flow-0', userCode:'ABCD', verificationUri:'https://microsoft.com/link', intervalSeconds:5, expiresIn:900});
  if (path.endsWith('/device/poll')) return count++ === 0
   ? mockResponse({status:'pending', flow:'flow-1', intervalSeconds:5},202)
   : mockResponse({session:'encrypted-official-session',profile:{id:'123456781234123412341234567890ab',name:'Owner',skins:[],capes:[]}});
  if (path.endsWith('/profile')) return mockResponse({profile:{id:'123456781234123412341234567890ab',name:'Owner',skins:[],capes:[]}},200,{'X-Official-Minecraft-Session':'rotated-official-session'});
  if (path.endsWith('/launch-credentials')) return mockResponse({realm:'official-minecraft',username:'Owner',uuid:'123456781234123412341234567890ab',accessToken:'official-jwt',userType:'msa',authServerBaseUrl:''});
  throw new Error(`unexpected request: ${path}`);
 };
 try {
  const c=new OfficialMinecraftClient0257('https://never.example','never-jwt');
  const device=await c.begin();assert.equal(device.userCode,'ABCD');
  Date.now=()=>originalDate()+10000;
  assert.equal((await c.poll()).pending,true);
  Date.now=()=>originalDate()+20000;
  const p=await c.poll();assert.equal(p.profile.name,'Owner');
  const profile=await c.profile();assert.equal(profile.name,'Owner');
  const creds=await c.credentials();assert.equal(creds.userType,'msa');
  assert.equal(creds.authServerBaseUrl,'');
  assert.equal(requests.at(-1).options.headers['X-Official-Minecraft-Session'],'rotated-official-session');
  assert.equal(requests.at(-1).options.headers.Authorization,'Bearer never-jwt');
  c.clear();await assert.rejects(c.credentials(),/Подключите официальный аккаунт/);
 } finally {globalThis.fetch=originalFetch;Date.now=originalDate}
});

test('cannot accept local identities as official Minecraft credentials', async () => {
 const originalFetch=globalThis.fetch, originalDate=Date.now;
 globalThis.fetch=async (url) => url.endsWith('/device/start')
  ? mockResponse({flow:'flow',userCode:'A',verificationUri:'https://microsoft.com/link',intervalSeconds:0,expiresIn:100})
  : url.endsWith('/device/poll')
    ? mockResponse({session:'opaque',profile:{id:'aaa',name:'Someone',skins:[],capes:[]}})
    : mockResponse({realm:'local-project',username:'Someone',uuid:'aaa',accessToken:'local-token',userType:'mojang',authServerBaseUrl:'https://never.example'});
 try {
  const c=new OfficialMinecraftClient0257('https://never.example','never-jwt');await c.begin();
  Date.now=()=>originalDate()+10000;
  await c.poll();
  await assert.rejects(c.credentials(),/Некорректная официальная Minecraft identity/);
 } finally {globalThis.fetch=originalFetch;Date.now=originalDate}
});

import {test} from 'node:test';
import assert from 'node:assert/strict';
import {OfficialMinecraftClient0257} from '../build-tests/official_minecraft_0257.js';
const profile = {id:'123456781234123412341234567890ab',name:'Owner',skins:[],capes:[]};

test('official flow uses ONLY the native boundary; no tickets or game credentials in IPC results',async()=>{
  const requests=[];
  const invoke=async(command,args)=>{
    requests.push({command,args});
    switch(command){
      case 'official_identity_cancel_0262':return;
      case 'official_identity_begin_0262':return {verificationUri:'https://microsoft.com/devicelogin',userCode:'ABCD',intervalSeconds:5,expiresIn:900};
      case 'official_identity_poll_0262':return {pending:false,profile};
      case 'official_identity_status_0262':return profile;
      case 'official_identity_disconnect_0262':return;
      default:throw Error(command);
    }
  };
  const originalFetch=globalThis.fetch;
  globalThis.fetch=()=>{throw Error('renderer must not call official API')};
  const originalDate=Date.now;
  try{
    const c=new OfficialMinecraftClient0257('https://backend.example','never-access','never-session',invoke);
    assert.equal((await c.begin()).userCode,'ABCD');
    Date.now=()=>originalDate()+10000;
    assert.deepEqual((await c.poll()).profile,profile);
    assert.equal(c.linked,true);
    assert.equal((await c.profile()).name,'Owner');
    await assert.rejects(c.credentials(),/native manager/);
    assert.equal(requests.some(r=>r.command==='official_identity_poll_0262'&&r.args.context.neverSessionId==='never-session'),true);
    assert.equal(requests.some(r=>r.command==='official_identity_launch_credentials'),false);
    assert.equal(requests.some(r=>JSON.stringify(r.args).includes('official-jwt')),false);
    await c.disconnect();assert.equal(c.linked,false);
  }finally{globalThis.fetch=originalFetch;Date.now=originalDate;}
});

test('restoring native profile does not return a session ticket',async()=>{
  const commands=[];
  const c=new OfficialMinecraftClient0257('https://backend.example','never-token-123456789','session',async (cmd)=>{
    commands.push(cmd);return cmd==='official_identity_status_0262'?profile:undefined;
  });
  assert.equal(c.linked,false);
  assert.equal((await c.restore())?.id,profile.id);
  assert.equal(c.linked,true);
  assert.deepEqual(commands,['official_identity_status_0262']);
});

test('rejects early polling before native Device Code call',async()=>{
  const commands=[];
  const c=new OfficialMinecraftClient0257('https://backend.example','never-token-123456789','session',async cmd=>{
    commands.push(cmd);
    return cmd==='official_identity_begin_0262' ? {verificationUri:'https://microsoft.com/link',userCode:'A',intervalSeconds:5,expiresIn:900} : undefined;
  });
  await c.begin();
  await assert.rejects(c.poll(),/интервал/);
  assert.equal(commands.includes('official_identity_poll_0262'),false);
});

test('never forwards native account tickets or token fields to preview',async()=>{
 const calls=[];
 const c=new OfficialMinecraftClient0257('https://backend.example','never-platform-token','sid',async(cmd,args)=>{
   calls.push({cmd,args});
   if(cmd==='official_identity_texture_0262')return profile;
   if(cmd==='official_identity_cancel_0262')return;
   return profile;
 });
 await c.selectCape('cape1');await c.resetCape();await c.resetSkin();
 assert.ok(calls.filter(x=>x.cmd==='official_identity_texture_0262').every(x=>!('session' in x.args) && !('accessToken' in x.args)));
});


test('browser PKCE is a native-only command and returns profile metadata',async()=>{
  const calls=[];
  const client = new OfficialMinecraftClient0257('https://backend.example','platform-token','session-1',async(cmd,args)=>{
    calls.push({cmd,args});
    if(cmd==='official_identity_browser_login_0263')return profile;
    if(cmd==='official_identity_cancel_0262')return;
    throw Error('Unexpected command '+cmd);
  });
  assert.deepEqual(await client.browserLogin(),profile);
  assert.equal(client.linked,true);
  assert.deepEqual(calls.map(c=>c.cmd),['official_identity_cancel_0262','official_identity_browser_login_0263']);
  assert.ok(calls.every(c=> !JSON.stringify(c.args).includes('verifier') && !JSON.stringify(c.args).includes('code_challenge') && !JSON.stringify(c.args).includes('microsoftToken')));
});

test('cancelled browser flow cannot attach a late response to renderer',async()=>{
  let complete;
  const pending = new Promise(resolve=>{complete=resolve;});
  const client=new OfficialMinecraftClient0257('https://backend.example','platform-token','session-1',async cmd=>{
    if(cmd==='official_identity_cancel_0262')return;
    if(cmd==='official_identity_browser_login_0263')return pending;
    throw Error('Unexpected command '+cmd);
  });
  const login=client.browserLogin();
  await new Promise(resolve=>setImmediate(resolve));
  await client.cancel();
  complete(profile);
  await assert.rejects(login,/отменена/);
  assert.equal(client.linked,false);
});

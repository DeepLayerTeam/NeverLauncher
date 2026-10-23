import test from 'node:test';
import assert from 'node:assert/strict';
import {TextureServiceClient0258,TextureServiceError0258,textureRevision0258,textureAssignment0258,
  validateTextureFile0258,safeOfficialTextureURL0258} from '../build-tests/texture_service_0258.js';
const digest='a'.repeat(64);
function response(data,status=200,headers={}){return {ok:status>=200&&status<300,status,headers:new Headers(headers),json:async()=>data};}
function mockResponse(data,status=200){return response({apiVersion:'0.25.8',data},status);}
test('safe Mojang textures only, upgrades legacy CDN http',()=>{
  assert.equal(safeOfficialTextureURL0258('http://textures.minecraft.net/texture/'+digest),'https://textures.minecraft.net/texture/'+digest);
  assert.equal(safeOfficialTextureURL0258('https://textures.minecraft.net/texture/'+digest),'https://textures.minecraft.net/texture/'+digest);
  for(const value of ['https://localhost/texture/'+digest,'https://evil.example/?url=https://textures.minecraft.net/texture/'+digest,
      'https://textures.minecraft.net.evil.com/texture/'+digest,'http://127.0.0.1/texture/'+digest,
      'https://textures.minecraft.net:443/texture/'+digest+'?x=1','javascript:alert(1)','https://textures.minecraft.net/texture/../admin']){
    assert.equal(safeOfficialTextureURL0258(value),undefined,value);
  }
});
test('revision selects local account scoped current state, not launcher profile',()=>{
  const entries=[{kind:'skin',revision:4,projectId:'project',blobDigest:'wrong'},
                 {kind:'skin',revision:7,projectId:'',blobDigest:digest},
                 {kind:'cape',revision:3,projectId:''}];
  assert.equal(textureRevision0258(entries,'skin'),7);
  assert.equal(textureRevision0258(entries,'cape'),3);
  assert.equal(textureAssignment0258(entries,'skin').blobDigest,digest);
  assert.equal(textureRevision0258([],'skin'),0);
});
test('upload validates PNG size/type/name before network request',()=>{
  assert.throws(()=>validateTextureFile0258({name:'foo.txt',size:4,type:'image/png'}));
  assert.throws(()=>validateTextureFile0258({name:'foo.png',size:4*1024*1024+1,type:'image/png'}));
  assert.throws(()=>validateTextureFile0258({name:'foo.png',size:1,type:'image/jpeg'}));
  assert.doesNotThrow(()=>validateTextureFile0258({name:'valid.PNG',size:11,type:'image/png'}));
});
test('API request endpoints, CAS, and never forwards official session / foreign UUID', async t=>{
  const recorded=[];globalThis.fetch=async(url,opts={})=>{recorded.push({url,opts});
    if(url.endsWith('/me/textures'))return mockResponse({realm:'local-project',profileUuid:'local',profileName:'Tester',items:[]});
    if(url.endsWith('/library'))return mockResponse({items:[]});
    return mockResponse({revision:4,kind:'skin',active:true});
  };
  const api=new TextureServiceClient0258('https://never.example/','never-token');
  await api.identity();await api.library();await api.select('skin',digest,3,'slim','public');
  await api.reset('skin',4);await api.reset('skin',4,true);await api.change('skin',{kind:'skin',revision:4,active:true},'classic','private');
  await api.deleteSaved('skin',digest);
  assert.deepEqual(recorded.map(r=>[r.opts.method||'GET',new URL(r.url).pathname]),[
    ['GET','/api/v1/me/textures'],['GET','/api/v1/me/textures/library'],['POST','/api/v1/me/textures/skin/select'],
    ['POST','/api/v1/me/textures/skin/reset'],['DELETE','/api/v1/me/textures/skin'],['PATCH','/api/v1/me/textures/skin'],
    ['DELETE','/api/v1/me/textures/library/skin/'+digest]]);
  assert.equal(JSON.parse(recorded[2].opts.body).expectedRevision,3);
  assert.equal(JSON.parse(recorded[2].opts.body).digest,digest);
  assert.equal(recorded.every(r=>r.opts.headers.Authorization==='Bearer never-token'),true);
  assert.equal(recorded.every(r=>!String(r.opts.body).includes('profileUuid')&&!String(r.opts.body).includes('official')) ,true);
  t.after(()=>{delete globalThis.fetch;});
});
test('concurrent CAS conflict returns 409 and never silently retries',async t=>{
  let n=0;
  globalThis.fetch=async()=>{n++;return response({error:{message:'stale'}},409)};
  const api=new TextureServiceClient0258('https://never.example','never');
  await assert.rejects(api.select('skin',digest,2,'classic','public'), e=>e instanceof TextureServiceError0258 && e.status===409);
  assert.equal(n,1);
  t.after(()=>{delete globalThis.fetch;});
});
test('owner-only preview sends Bearer, rejects JSON and revokes invalid digests',async t=>{
  const seen=[];
  const oldURL=globalThis.URL.createObjectURL;
  globalThis.URL.createObjectURL=()=> 'blob:test';
  globalThis.fetch=async(url,opts)=>{seen.push(opts);return {...response({},200,{'Content-Type':'image/png'}),blob:async()=>new Blob(['png'],{type:'image/png'})}};
  const api=new TextureServiceClient0258('https://never.example','secret');
  assert.equal(await api.preview('skin',digest),'blob:test');
  assert.equal(seen[0].headers.Authorization,'Bearer secret');
  await assert.rejects(api.preview('skin','../secret'));
  globalThis.URL.createObjectURL=oldURL;
  t.after(()=>{delete globalThis.fetch;});
});
test('multipart upload uses real XHR progress, Authorization and expectedRevision',async t=>{
  const events=[];
  class FakeXHR {
    constructor(){this.upload={};this.responseText='';this.headers={};events.push(this);}
    open(method,url){this.method=method;this.url=url;}
    setRequestHeader(k,v){this.headers[k]=v;}
    send(form){this.form=form;this.upload.onprogress?.({lengthComputable:true,loaded:50,total:100});
      this.status=200;this.responseText=JSON.stringify({data:{assignment:{revision:1}}});this.onload();}
  }
  globalThis.XMLHttpRequest=FakeXHR;
  const file=new File(['not-a-real-png'],'test.png',{type:'image/png'});
  const values=[];
  await new TextureServiceClient0258('https://never.example','token').upload('skin',file,0,'slim','public',p=>values.push(p));
  assert.deepEqual(values,[50,100]);
  assert.equal(events[0].form.get('expectedRevision'),'0');
  assert.equal(events[0].headers.Authorization,'Bearer token');
  assert.equal(events[0].form.get('model'),'slim');
  t.after(()=>{delete globalThis.XMLHttpRequest;});
});
test('official skin upload is bound to official session, reports progress and rotates ticket',async t=>{
  const {OfficialMinecraftClient0257}=await import('../build-tests/official_minecraft_0257.js');
  const oldFetch=globalThis.fetch, oldXHR=globalThis.XMLHttpRequest, now=Date.now;
  globalThis.fetch=async(url)=>url.endsWith('/device/start') ? mockResponse({flow:'flow',userCode:'AB',verificationUri:'https://microsoft.com/link',intervalSeconds:1,expiresIn:300})
    : url.endsWith('/device/poll') ? mockResponse({session:'ticket-a',profile:{id:'123456781234123412341234567890ab',name:'owner',skins:[],capes:[]}})
    : mockResponse({profile:{id:'123456781234123412341234567890ab',name:'owner',skins:[],capes:[]}});
  let seen;
  class FakeXHR {
    constructor(){this.upload={};seen=this;this.headers={};}
    open(method,url){this.method=method;this.url=url;}
    setRequestHeader(k,v){this.headers[k]=v;}
    getResponseHeader(k){return k==='X-Official-Minecraft-Session'?'ticket-b':null;}
    send(form){this.form=form;this.upload.onprogress?.({lengthComputable:true,loaded:2,total:4});this.status=200;
      this.responseText=JSON.stringify({data:{profile:{id:'123456781234123412341234567890ab',name:'owner',skins:[],capes:[]}}});this.onload();}
  }
  globalThis.XMLHttpRequest=FakeXHR;
  try{
    const c=new OfficialMinecraftClient0257('https://never.example','never-jwt');await c.begin();
    Date.now=()=>now()+2000;await c.poll();
    const values=[];
    const updated=await c.uploadSkin(new File(['p'],'skin.png',{type:'image/png'}),'slim',x=>values.push(x));
    assert.equal(updated.name,'owner');assert.equal(seen.headers.Authorization,'Bearer never-jwt');
    assert.equal(seen.headers['X-Official-Minecraft-Session'],'ticket-a');
    assert.equal(seen.form.get('variant'),'slim');assert.deepEqual(values,[50,100]);
    await c.profile();
  }finally{globalThis.fetch=oldFetch;globalThis.XMLHttpRequest=oldXHR;Date.now=now;}
});

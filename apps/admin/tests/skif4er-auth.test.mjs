import {test} from 'node:test';
import assert from 'node:assert/strict';
import {issuer, callbackPath, pendingKey, prepare, consume, secureBackend, accessExpired} from '../src/admin/skif4er-auth.ts';
const origin = 'https://admin.example.test';
const backend = 'https://api.example.test';
const now = Date.now();
const state = 's'.repeat(43);
function begin(mode = 'login') {
  const url = new URL(issuer+'/protocol/openid-connect/auth');
  for (const [key,value] of Object.entries({client_id:'launcher',state,nonce:'n'.repeat(43),code_challenge:'c'.repeat(43),code_challenge_method:'S256',redirect_uri:origin+callbackPath,response_type:'code', ...(mode==='link'?{prompt:'login'}:{})})) url.searchParams.set(key,value);
  return {authorizationUrl:url.href,state,transaction:'sealed',expiresAt:new Date(now+600000).toISOString()};
}
function store(pending) { const m=new Map([[pendingKey,JSON.stringify(pending)]]); return {getItem:k=>m.get(k)??null,removeItem:k=>m.delete(k)}; }
const callback = origin+callbackPath+'?code=valid-code&state='+state+'&iss='+encodeURIComponent(issuer);
test('SkiF4er browser flow consumes a sealed transaction once',()=>{
 const p=prepare(begin(),backend,'login','',origin,now).pending;
 const s=store(p); assert.deepEqual(consume(s,callback,backend,'',now),{mode:'login',body:{code:'valid-code',state,transaction:'sealed',deviceId:'admin-browser'}});
 assert.throws(()=>consume(s,callback,backend,'',now));
});
test('callback rejects wrong state, duplicate parameters, issuer, expiry, cancellation and backend switch',()=>{
 const p=prepare(begin(),backend,'login','',origin,now).pending;
 for(const href of [callback.replace(state,'other'),callback+'&state='+state,callback+'&code=other',callback+'&error=access_denied',callback.replace(encodeURIComponent(issuer),'https%3A%2F%2Fevil.example'),origin+callbackPath+'?error=access_denied&state='+state]){
  const s=store(p); assert.throws(()=>consume(s,href,backend,'',now)); assert.equal(s.getItem(pendingKey),null);
 }
 assert.throws(()=>consume(store(p),callback,'https://other.example','',now));
 assert.throws(()=>consume(store(p),callback,backend,'',now+600001));
 assert.throws(()=>consume(store(p),callback,backend,'unexpected-session',now));
});
test('link requires the same initiating session and forced provider reauthentication',()=>{
 const p=prepare(begin('link'),backend,'link','session-1',origin,now).pending;
 assert.throws(()=>consume(store(p),callback,backend,'session-2',now));
 assert.equal(consume(store(p),callback,backend,'session-1',now).mode,'link');
 assert.throws(()=>prepare(begin(),backend,'link','session-1',origin,now));
});
test('reject non-HTTPS backend, untrusted authorization URL, unsafe redirect and missing PKCE',()=>{
 for(const base of ['http://api.example.test','https://user@api.example.test','https://api.example.test/path','https://api.example.test/?x=1']) assert.throws(()=>secureBackend(base));
 for(const mutate of [u=>u.hostname='evil.example',u=>u.searchParams.delete('nonce'),u=>u.searchParams.append('redirect_uri','https://evil.example'),u=>u.searchParams.set('code_challenge_method','plain')]){
  const b=begin(); const u=new URL(b.authorizationUrl); mutate(u); b.authorizationUrl=u.href; assert.throws(()=>prepare(b,backend,'login','',origin,now));
 }
});
test('expired access token is only a rotation hint, malformed token fails closed',()=>{
 const jwt=exp=>'header.'+Buffer.from(JSON.stringify({exp})).toString('base64url')+'.sig';
 assert.equal(accessExpired(jwt(Math.floor(now/1000)-1),now),true);
 assert.equal(accessExpired(jwt(Math.floor(now/1000)+100),now),false);
 assert.equal(accessExpired('malformed',now),false);
});

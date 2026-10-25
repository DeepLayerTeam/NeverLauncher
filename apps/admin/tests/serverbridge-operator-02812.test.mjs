import test from 'node:test';
import assert from 'node:assert/strict';
import { parseBridgeEnrollment, ServerBridgeClient } from '../src/api/serverbridge.ts';
import { can } from '../src/admin/permissions.ts';

const sample = {schemaVersion:'1.0',id:'paper-prod',name:'Production Paper',kind:'paper',projectId:'project-a',profileId:'survival',keyAlgorithm:'ed25519',publicKey:'a'.repeat(43),keyFingerprint:'a'.repeat(64),backendUrl:'https://launcher.example.test',artifactFile:'bridge.jar',artifactSha256:'b'.repeat(64)};

test('0.28.12 accepts public enrollment for exact project only', () => {
  assert.equal(parseBridgeEnrollment(JSON.stringify(sample),'project-a').id,'paper-prod');
  assert.throws(()=>parseBridgeEnrollment(JSON.stringify(sample),'project-b'),/Проект/);
  assert.throws(()=>parseBridgeEnrollment(JSON.stringify({...sample, privateKeyPkcs8:'SECRET'}),'project-a'),/приватные/);
  assert.throws(()=>parseBridgeEnrollment(JSON.stringify({...sample, artifactSha256:'wrong'}),'project-a'),/SHA-256/);
});

test('0.28.12 project wildcard does not authorize settings:manage on the Backend', () => {
  const projectOnly = {permissions:[],projectPermissions:{'project-a':['*']}};
  assert.equal(can(projectOnly,'settings:manage'),false);
  assert.equal(can(projectOnly,'project:read','project-a'),true);
});

test('0.28.12 enrollment POST transmits public key and scope, never private material', async () => {
  const oldFetch=globalThis.fetch;
  let captured;
  globalThis.fetch=async (url, init)=> {
    captured={url,init,body:JSON.parse(init.body)};
    return new Response(JSON.stringify({data:{status:'registered',server:{id:sample.id,keyFingerprint:sample.keyFingerprint}}}),{status:201,headers:{'Content-Type':'application/json'}});
  };
  try {
    const client=new ServerBridgeClient('https://launcher.example.test','test-token');
    const result=await client.register(parseBridgeEnrollment(JSON.stringify(sample),'project-a'));
    assert.equal(result.server.id,'paper-prod');
    assert.match(captured.url,/\/api\/v1\/server-bridge\/servers\/register$/);
    assert.equal(captured.init.method,'POST');
    assert.equal(captured.init.headers.get('Authorization'),'Bearer test-token');
    assert.deepEqual(Object.keys(captured.body).sort(),['id','keyAlgorithm','kind','name','profileId','projectId','publicKey'].sort());
    assert.equal(captured.body.publicKey,sample.publicKey);
  } finally { globalThis.fetch=oldFetch; }
});

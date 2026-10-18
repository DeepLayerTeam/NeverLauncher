import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ServerBridgeClient, commandLifecycle, telemetryState, canControlNode, buildControlPayload } from '../src/api/serverbridge.ts';
import { canSeeSection, can } from '../src/admin/permissions.ts';
import { endpointForSection } from '../src/admin/sections.ts';

const now = Date.now();
const node = { id: 'paper-one', projectId: 'one', status: 'active', fresh: true, protocolVersion: 3,
  runtimeEpoch: 12, runtimeId: 'a'.repeat(64), lastHeartbeatAt: new Date(now-1000).toISOString(),
  telemetry: { sampledAtUnixMillis: now-2000, runtimeId: 'a'.repeat(64), runtimeEpoch: 12, playersOnline: 17, playersMax: 40 } };

test('project-scoped overview path and rights do not grant global access', () => {
  assert.equal(endpointForSection('server-bridge','a/b'), '/api/v1/server-bridge/projects/a%2Fb/overview');
  const actor = { user: { id:'one',email:'a',roleId:'player' }, permissions:[], projectPermissions:{ one:['project:read','serverbridge:control'],other:[] } };
  assert.equal(canSeeSection(actor,'server-bridge','one'), true);
  assert.equal(canSeeSection(actor,'server-bridge','other'), false);
  assert.equal(can(actor,'serverbridge:control','one'),true);
  assert.equal(can(actor,'serverbridge:console','one'),false);
});

test('control lifecycle preserves dispatch, delivery and execution distinctions', () => {
  assert.deepEqual(['pending','leased','delivered','succeeded','failed','indeterminate'].map(x=>commandLifecycle(x).lifecycle),
    ['queued','dispatched','delivered','executed','failed','indeterminate']);
  assert.equal(commandLifecycle('leased').deliveryConfirmed,false);
  assert.equal(commandLifecycle('succeeded').terminal,true);
  assert.equal(commandLifecycle('expired').terminal,true);
  assert.equal(commandLifecycle('indeterminate').deliveryConfirmed,false);
  assert.equal(commandLifecycle('unknown').terminal,false);
});

test('telemetry is withheld for unknown, stale and wrong runtime samples', () => {
  assert.equal(telemetryState(node,now).state,'fresh');
  assert.equal(telemetryState({...node,telemetry:undefined},now).state,'unknown');
  assert.equal(telemetryState({...node,telemetry:{...node.telemetry,runtimeEpoch:5}},now).state,'stale');
  assert.equal(telemetryState(node,now+200_000).state,'stale');
  assert.equal(canControlNode(node,now),true);
  assert.equal(canControlNode({...node,protocolVersion:2},now),false);
  assert.equal(canControlNode({...node,lastHeartbeatAt:new Date(now-200_000).toISOString()},now),false);
});

test('form builds only allowlisted payload without shell or unknown fields', () => {
  const form={username:'Notch',reason:'Reason',message:'Hello',enabled:true,command:'say Hello'};
  assert.deepEqual(buildControlPayload('player.kick',form),{username:'Notch',reason:'Reason'});
  assert.deepEqual(buildControlPayload('server.drain',form),{enabled:'true',reason:'Reason'});
  assert.deepEqual(buildControlPayload('server.save',form),{});
  assert.deepEqual(buildControlPayload('message.broadcast',form),{message:'Hello'});
  assert.throws(()=>buildControlPayload('server.console',{...form,command:'op Notch'}));
  assert.throws(()=>buildControlPayload('player.kick',{...form,username:'invalid player'}));
});

test('real API uses command endpoint, scoped overview and unchanged idempotency across retry', async () => {
  const previous=globalThis.fetch;
  const calls=[];
  try {
    globalThis.fetch=async (url,options)=>{
      calls.push({url,options});
      return {ok:true,json:async ()=>({data: url.endsWith('/overview') ? {nodes:[],control:[]} : url.endsWith('/control') ? {status:'pending',command:{id:'cmd-1',serverId:'node',status:'pending'},idempotentReplay:false} : {command:{id:'cmd-1',serverId:'node',status:'succeeded'}}})};
    };
    const client=new ServerBridgeClient('https://api.test','secret');
    await client.overview('a/b');
    const cmd={serverId:'node',type:'server.save',payload:{},idempotencyKey:'idempotency-fixed'};
    await client.send(cmd);await client.send(cmd);
    const result=await client.command('node','cmd-1');
    assert.equal(result.status,'succeeded');
    assert.equal(calls[0].url,'https://api.test/api/v1/server-bridge/projects/a%2Fb/overview');
    assert.equal(calls[1].url,'https://api.test/api/v1/server-bridge/servers/node/control');
    assert.equal(calls[1].options.headers.get('Authorization'),'Bearer secret');
    assert.equal(calls[1].options.headers.get('Idempotency-Key'),'idempotency-fixed');
    assert.equal(calls[2].options.headers.get('Idempotency-Key'),'idempotency-fixed');
    assert.equal(calls[3].url,'https://api.test/api/v1/server-bridge/servers/node/control/cmd-1');
  } finally {globalThis.fetch=previous;}
});

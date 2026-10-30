import test from 'node:test';
import assert from 'node:assert/strict';
import {assertOfficialJoin0397} from '../build-tests/server_join_identity_0397.js';
const expected = {uuid:'123E4567-E89B-42D3-A456-426614174000',name:'OfficialPlayer',serverId:'velocity-main'};
const correct = {uuid:'123e4567e89b42d3a456426614174000',username:'OfficialPlayer',serverId:'velocity-main'};
test('accepts the authorized Mojang profile, with UUID normalization',()=>{
  assert.deepEqual(assertOfficialJoin0397(correct,expected),correct);
});
for (const [label, change] of [
  ['changed UUID',{uuid:'123e4567e89b42d3a456426614174001'}],
  ['changed name',{username:'AnotherPlayer'}],
  ['changed server',{serverId:'different-node'}],
  ['malformed UUID',{uuid:'123e4567e89b42d3a45642661417400x'}],
  ['empty username',{username:''}],
]) test('rejects '+label,()=>assert.throws(()=>assertOfficialJoin0397({...correct,...change},expected)));

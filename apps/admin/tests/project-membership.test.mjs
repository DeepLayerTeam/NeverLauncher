import {test} from 'node:test';
import assert from 'node:assert/strict';
import {assignableRoles0387,membershipChange0387} from '../src/admin/project-membership-0387.ts';
const roles=[
  {id:'owner',name:'Owner',permissions:['*']},
  {id:'operator',name:'Operator',permissions:['project:read','project:write']},
  {id:'viewer',name:'Viewer',permissions:['project:read']},
  {id:'admin',name:'Admin',permissions:['users:manage','settings:manage']},
  {id:'player',name:'Player',permissions:['profile:launch']},
];
const user={id:'user1',email:'ops@example.test',status:'active',roleId:'player',projectRoles:{alpha:'operator',beta:'viewer'}};
test('project role picker excludes instance-wide admin and player roles',()=>{
  assert.deepEqual(assignableRoles0387(roles).map(r=>r.id),['owner','operator','viewer']);
});
test('grant changes only the chosen project and captures old map for stale-update detection',()=>{
  const change=membershipChange0387(user,'beta','operator',assignableRoles0387(roles));
  assert.deepEqual(change,{expectedProjectRoles:{alpha:'operator',beta:'viewer'},projectRoles:{alpha:'operator',beta:'operator'}});
  assert.equal(user.projectRoles.beta,'viewer');
});
test('revoke removes only the named membership',()=>{
  const change=membershipChange0387(user,'alpha','',assignableRoles0387(roles));
  assert.deepEqual(change.projectRoles,{beta:'viewer'});
});
test('unknown role and project wildcard are rejected before HTTP',()=>{
  assert.throws(()=>membershipChange0387(user,'beta','admin',assignableRoles0387(roles)));
  assert.throws(()=>membershipChange0387(user,'*','owner',assignableRoles0387(roles)));
});

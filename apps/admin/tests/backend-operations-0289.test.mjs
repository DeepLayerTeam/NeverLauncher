import {test} from 'node:test';
import assert from 'node:assert/strict';
import {can,canSeeSection} from '../src/admin/permissions.ts';
import {endpointForSection} from '../src/admin/sections.ts';

test('0.28.9 backend operations require a global permission, not a project wildcard',()=>{
 const scoped={user:{id:'u',email:'test',roleId:'player'},permissions:[],projectPermissions:{demo:['*']}};
 assert.equal(can(scoped,'backend:control','demo'),false);
 assert.equal(canSeeSection(scoped,'backend-operations','demo'),false);
 const global={...scoped,permissions:['backend:control']};
 assert.equal(canSeeSection(global,'backend-operations','demo'),true);
 assert.equal(can(global,'host:exec'),false);
 assert.equal(can(global,'gameserver:console','demo'),true); // project wildcard only, never from backend grant
 assert.equal(endpointForSection('backend-operations','demo'),'/api/v1/operations/backend/status');
});

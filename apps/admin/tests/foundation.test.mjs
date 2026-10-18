import { test } from 'node:test';
import assert from 'node:assert/strict';
import { can, canSeeSection } from '../src/admin/permissions.ts';
import { endpointForSection } from '../src/admin/sections.ts';
import { requestJSON, ApiError, collection } from '../src/api/client.ts';

const scoped = { user: { id: 'u', email: 'u@example.test', roleId: 'viewer' }, permissions: [], projectPermissions: { alpha: ['project:read', 'project:write', 'release:prepare'], beta: ['project:read'] } };
test('project actions are not silently granted outside project scope', () => {
  assert.equal(can(scoped, 'project:write', 'alpha'), true);
  assert.equal(can(scoped, 'project:write', 'beta'), false);
  assert.equal(can(scoped, 'project:write'), false);
  assert.equal(can(scoped, 'users:manage', 'alpha'), false);
  assert.equal(canSeeSection(scoped, 'profiles', 'beta'), true);
  assert.equal(canSeeSection(scoped, 'users', 'alpha'), false);
  assert.equal(canSeeSection(scoped, 'server-bridge', 'alpha'), false);
  assert.equal(canSeeSection(null, 'dashboard', 'alpha'), false);
});
test('global wildcard remains an owner-only permission projection', () => {
  const owner = { ...scoped, permissions: ['*'] };
  assert.equal(can(owner, 'users:manage'), true);
  assert.equal(canSeeSection(owner, 'backup-restore', ''), true);
});
test('project URL parameters are encoded and unrelated pages use global routes', () => {
  assert.equal(endpointForSection('profiles', 'a/b c'), '/api/v1/projects/a%2Fb%20c/profiles');
  assert.equal(endpointForSection('users', 'a/b'), '/api/v1/admin/users');
});
test('API unwraps real backend shapes and sets authorization without cache', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async (url, init) => {
      assert.equal(url, 'https://example.test/api/v1/admin/me');
      assert.equal(init.headers.get('Authorization'), 'Bearer secret');
      assert.equal(init.cache, 'no-store');
      return { ok: true, json: async () => ({ data: { permissions: ['project:read'] } }) };
    };
    const data = await requestJSON('https://example.test/', '/api/v1/admin/me', 'secret');
    assert.deepEqual(data.permissions, ['project:read']);
  } finally { globalThis.fetch = original; }
});
test('HTTP errors preserve actual status and reason', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => ({ ok: false, status: 403, statusText: 'Forbidden', json: async () => ({ error: { message: 'project denied', reasonCode: 'project-membership-required' } }) });
    await assert.rejects(requestJSON('https://example.test', '/api/v1/admin/users', 'token'), err => err instanceof ApiError && err.status === 403 && err.reasonCode === 'project-membership-required');
  } finally { globalThis.fetch = original; }
});
test('item extraction rejects nested payloads that are not collection rows', () => {
  assert.deepEqual(collection({ items: [{ id: 'a' }, null, 'bad'] }), [{ id: 'a' }]);
});

test('typed Admin API uses access-filtered overview instead of public projects endpoint', async () => {
  const { AdminApi } = await import('../src/api/admin.ts');
  const original = globalThis.fetch;
  const visited = [];
  try {
    globalThis.fetch = async url => {
      visited.push(url);
      return { ok: true, json: async () => ({ projects: [{ id: 'p1', name: 'First' }], profiles: [] }) };
    };
    const client = new AdminApi('https://example.test', 'secret');
    const projects = await client.projects();
    assert.equal(projects[0].id, 'p1');
    await client.overview('p/2');
    assert.deepEqual(visited, ['https://example.test/api/v1/admin/overview', 'https://example.test/api/v1/admin/overview?projectId=p%2F2']);
  } finally { globalThis.fetch = original; }
});

test('collection tables search, facet, numeric sort, pagination and empty pages', async () => {
  const { filterSortRows, paginateRows } = await import('../src/components/resource-model.ts');
  const columns = [{ field: 'name', title: 'Name' }, { field: 'status', title: 'Status', facet: true }, { field: 'size', title: 'Size' }];
  const rows = [{ name: 'Beta', status: 'draft', size: 20 }, { name: 'Alpha', status: 'live', size: 5 }, { name: 'Gamma', status: 'live', size: 30 }];
  const filtered = filterSortRows(rows, columns, 'a', 'status', 'live', 'size', true);
  assert.deepEqual(filtered.map(item => item.name), ['Gamma', 'Alpha']);
  assert.deepEqual(paginateRows(filtered, 2, 1).rows.map(item => item.name), ['Alpha']);
  assert.equal(paginateRows(filtered, 999, 1).page, 2);
  assert.deepEqual(paginateRows([], 1, 10).rows, []);
  assert.deepEqual(rows.map(r => r.name), ['Beta', 'Alpha', 'Gamma'], 'do not mutate backend response');
});

/** Project membership is never inferred from a global RoleID. The API remains authoritative. */
export type ProjectRoleUser0387 = {
  id: string; email: string; displayName?: string; status: string; roleId: string;
  projectRoles?: Record<string, string>;
};
export type ProjectRole0387 = { id: string; name: string; description?: string; permissions: string[] };

/** Privileged global roles must not appear in the ordinary project-role picker. */
const assignable = new Set(['owner', 'release-manager', 'operator', 'support', 'developer', 'viewer']);
export function assignableRoles0387(roles: ProjectRole0387[]): ProjectRole0387[] {
  return roles.filter(role => assignable.has(role.id) && Array.isArray(role.permissions) &&
    (role.permissions.includes('*') || role.permissions.includes('project:read')));
}

export function membershipChange0387(
  user: ProjectRoleUser0387, projectId: string, roleId: string, allowed: ProjectRole0387[],
): {projectRoles:Record<string,string>;expectedProjectRoles:Record<string,string>} {
  if (!user.id || !projectId || projectId === '*') throw new Error('Не выбран конкретный проект и пользователь.');
  if (roleId && !allowed.some(role => role.id === roleId)) throw new Error('Недопустимая проектная роль.');
  const existing = { ...(user.projectRoles ?? {}) };
  const next = { ...existing };
  if (roleId) next[projectId] = roleId;
  else delete next[projectId];
  return {projectRoles:next,expectedProjectRoles:existing};
}

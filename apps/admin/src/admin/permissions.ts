export interface AdminUser {
  id: string; email: string; displayName?: string; roleId: string; status?: string;
  projectRoles?: Record<string, string>;
}
export interface AdminIdentity {
  user: AdminUser;
  permissions: string[];
  projectPermissions: Record<string, string[]>;
  authorizationSource?: string;
}

/** Только для отображения; каждая операция повторно проверяется на сервере. */
export function can(identity: AdminIdentity | null, permission: string, projectId?: string): boolean {
  if (!identity) return false;
  const globals = identity.permissions || [];
  if (globals.includes('*') || globals.includes(permission)) return true;
  if (!projectId || projectId === '*') return false;
  const scoped = identity.projectPermissions?.[projectId] ?? [];
  // Подстановочный символ проекта нельзя трактовать как разрешение для хоста или Backend.
  if (permission.startsWith('host:') || permission.startsWith('backend:')) return false;
  return scoped.includes('*') || scoped.includes(permission);
}

export const globalPermissionForSection: Record<string, string> = {
  'backend-operations':'backend:control', 'migration-center':'settings:manage', users: 'users:manage', roles: 'users:manage',
  audit: 'audit:read', config: 'settings:manage', 'official-provider': 'settings:manage', 'auth-provider-wizard': 'settings:manage', 'texture-management': 'settings:manage', storage: 'project:read', 'extension-registry': 'extension:manage',
  'extensions-manager': 'extension:manage',
  diagnostics: 'diagnostics:read', 'backup-restore': 'storage:manage',
};

export function canSeeSection(identity: AdminIdentity | null, section: string, projectId: string): boolean {
  if (section === 'dashboard' || section === 'devices') return !!identity;
  if (section === 'server-bridge') return can(identity, 'project:read', projectId);
  if (section === 'release-workspace') return can(identity, 'release:prepare', projectId);
  if (section === 'job-monitor') return can(identity, 'project:read', projectId);
  const global = globalPermissionForSection[section];
  if (global) {
    if (section === 'storage') return can(identity, global) || can(identity, global, projectId);
    // Этим маршрутам сейчас требуется глобальное право, а не ограниченное конкретным проектом.
    return can(identity, global);
  }
  return can(identity, 'project:read', projectId);
}

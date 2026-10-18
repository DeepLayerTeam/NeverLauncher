import type { SectionId } from './routing';
export type Section = { id: SectionId; title: string };
export const sections: Section[] = [
  { id: 'dashboard', title: 'Обзор' }, { id: 'projects', title: 'Проекты' },
  { id: 'profiles', title: 'Профили' }, { id: 'channels', title: 'Каналы' },
  { id: 'packages', title: 'Пакеты и файлы' }, { id: 'releases', title: 'Релизы' },
  { id: 'users', title: 'Пользователи' }, { id: 'roles', title: 'Роли' },
  { id: 'operations', title: 'Операции' }, { id: 'release-workspace', title: 'Мастер релизов' }, { id: 'job-monitor', title: 'Монитор jobs' }, { id: 'devices', title: 'Устройства' }, { id: 'audit', title: 'Аудит' }, { id: 'config', title: 'Конфигурация' },
  { id: 'storage', title: 'Хранилище' }, { id: 'extension-registry', title: 'NeverExtensions Registry' },
  { id: 'extensions-manager', title: 'Admin Extensions' }, { id: 'server-bridge', title: 'ServerBridge' },
  { id: 'diagnostics', title: 'Диагностика' }, { id: 'backup-restore', title: 'Резервное копирование' },
];
export function endpointForSection(active: SectionId, projectId: string): string {
  const scoped = `/api/v1/projects/${encodeURIComponent(projectId)}`;
  switch (active) {
    case 'operations': return '/api/v1/operations';
    case 'release-workspace': return '/api/v1/release-drafts';
    case 'job-monitor': return '/api/v1/operations';
    case 'dashboard': return '/api/v1/admin/overview';
    case 'projects': return '/api/v1/admin/overview';
    case 'profiles': return `${scoped}/profiles`;
    case 'channels': return `${scoped}/channels`;
    case 'packages': case 'releases': return `${scoped}/versions`;
    case 'users': return '/api/v1/admin/users';
    case 'roles': return '/api/v1/admin/roles';
    case 'devices': return '/api/v1/admin/auth/devices';
    case 'audit': return '/api/v1/admin/audit';
    case 'config': return '/api/v1/admin/config';
    case 'storage': return '/api/v1/admin/storage/health';
    case 'extension-registry': return '/api/v1/admin/extension-registry/extensions';
    case 'extensions-manager': return '/api/v1/admin/extensions/manager';
    case 'server-bridge': return `/api/v1/server-bridge/projects/${encodeURIComponent(projectId)}/overview`;
    case 'diagnostics': return '/api/v1/operations/diagnostics';
    case 'backup-restore': return '/api/v1/operations/backup';
  }
}

import type { ProjectContext } from './project-context';
export const routeIds = ['dashboard','branding-studio','projects','profiles','channels','packages','releases','users','roles','devices','audit','config','official-provider','auth-provider-wizard','storage','extension-registry','extensions-manager','server-bridge','texture-management','diagnostics','backup-restore','operations','backend-operations','release-workspace','job-monitor','migration-center'] as const;
export type SectionId = typeof routeIds[number];
const ids: ReadonlySet<string> = new Set(routeIds);
export type AdminRoute = { section: SectionId } & Partial<ProjectContext>;
const keyNames: Record<keyof ProjectContext,string> = {projectId:'project',profileId:'profile',channelId:'channel',serverId:'server'};
/** Разберите один фрагмент URL, не принимая его значения за доказательство прав или существования ресурса. */
export function parseAdminRoute(hash: string): AdminRoute {
  const raw = hash.replace(/^#\/?/, '');
  const question = raw.indexOf('?');
  const path = question < 0 ? raw : raw.slice(0, question);
  let segment = '';
  try { segment = decodeURIComponent(path.split('/')[0]); } catch { /* некорректная ссылка */ }
  const route: AdminRoute = { section: ids.has(segment) ? segment as SectionId : 'dashboard' };
  const params = new URLSearchParams(question < 0 ? '' : raw.slice(question + 1));
  for (const field of Object.keys(keyNames) as Array<keyof ProjectContext>) {
    const value = params.get(keyNames[field]);
    if (value && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value)) route[field] = value;
  }
  return route;
}
export function adminHref(section: SectionId, context: Partial<ProjectContext> = {}): string {
  const params = new URLSearchParams();
  for (const field of Object.keys(keyNames) as Array<keyof ProjectContext>) {
    if (context[field]) params.set(keyNames[field], context[field]);
  }
  const query = params.toString();
  return `#/${section}${query ? '?' + query : ''}`;
}

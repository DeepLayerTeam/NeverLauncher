/** Owner navigation is a non-secret, authenticated preference, never an authority.
 * Project/profile/channel IDs must be rechecked against a fresh access-filtered
 * Admin overview before any UI uses them. The API remains the access gate. */
export type ProjectContext = { projectId: string; profileId: string; channelId: string };
export const emptyProjectContext: ProjectContext = { projectId: '', profileId: '', channelId: '' };
export type ProjectResource = { id: string; projectId?: string };
export type ProjectCatalog = {
  projects: readonly ProjectResource[];
  profiles: readonly ProjectResource[];
  channels: readonly ProjectResource[];
};
const bound = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value);
export function contextStorageKey(backendUrl: string, principalId: string): string {
  const normalized = new URL(backendUrl, 'http://localhost').href.replace(/\/$/, '');
  return `neverlauncher.admin.owner-context.0381.${encodeURIComponent(normalized)}.${encodeURIComponent(principalId)}`;
}
export function readSavedContext(storage: Pick<Storage, 'getItem'>, key: string): ProjectContext {
  try {
    const raw: unknown = JSON.parse(storage.getItem(key) || 'null');
    if (!raw || typeof raw !== 'object') return { ...emptyProjectContext };
    const record = raw as Record<string, unknown>;
    return {
      projectId: bound(record.projectId) ? record.projectId : '',
      profileId: bound(record.profileId) ? record.profileId : '',
      channelId: bound(record.channelId) ? record.channelId : '',
    };
  } catch { return { ...emptyProjectContext }; }
}
export function saveContext(storage: Pick<Storage,'setItem'>, key: string, ctx: ProjectContext): void {
  storage.setItem(key, JSON.stringify(ctx));
}
export function resolveProjectContext(url: Partial<ProjectContext>, saved: ProjectContext, catalog: ProjectCatalog): ProjectContext {
  const projectExists = (id: string) => !!id && catalog.projects.some(p => p.id === id);
  const projectId = [url.projectId, saved.projectId, catalog.projects[0]?.id].find(id => !!id && projectExists(id)) || '';
  if (!projectId) return { ...emptyProjectContext };
  const within = (items: readonly ProjectResource[], id?: string) => !!id && items.some(item => item.id === id && (!item.projectId || item.projectId === projectId));
  // A saved subresource from another project must never be reused.
  const sameSavedProject = saved.projectId === projectId;
  const sameUrlProject = url.projectId === projectId;
  return {
    projectId,
    profileId: sameUrlProject ? (within(catalog.profiles, url.profileId) ? url.profileId! : '') :
      (sameSavedProject && within(catalog.profiles, saved.profileId) ? saved.profileId : '') || '',
    channelId: sameUrlProject ? (within(catalog.channels, url.channelId) ? url.channelId! : '') :
      (sameSavedProject && within(catalog.channels, saved.channelId) ? saved.channelId : '') || '',
  };
}

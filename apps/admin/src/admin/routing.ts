import { useEffect, useState } from 'react';
export const routeIds = ['dashboard','projects','profiles','channels','packages','releases','users','roles','devices','audit','config','storage','extension-registry','extensions-manager','server-bridge','diagnostics','backup-restore','operations','release-workspace','job-monitor'] as const;
export type SectionId = typeof routeIds[number];
const ids: ReadonlySet<string> = new Set(routeIds);
function fromHash(): SectionId {
  try {
    const segment = decodeURIComponent(location.hash.replace(/^#\/?/, '').split(/[/?]/)[0]);
    return ids.has(segment) ? segment as SectionId : 'dashboard';
  } catch { return 'dashboard'; }
}
export function navigate(section: SectionId) { window.location.hash = `/${section}`; }
/** Hash URLs support refresh, share, and browser back/forward without nginx rewrites. */
export function useAdminRoute(): SectionId {
  const [active, setActive] = useState(fromHash);
  useEffect(() => { const update = () => setActive(fromHash()); window.addEventListener('hashchange', update); return () => window.removeEventListener('hashchange', update); }, []);
  return active;
}

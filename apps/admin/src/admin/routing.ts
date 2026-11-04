import { useEffect, useState } from 'react';
import type { ProjectContext } from './project-context-0381';
import {parseAdminRoute, adminHref, type SectionId, type AdminRoute} from './route-links-0381';
export {routeIds,parseAdminRoute,adminHref} from './route-links-0381';
export type {SectionId,AdminRoute} from './route-links-0381';
/** Старая навигация по разделам сохраняет выбор владельца при переходах. */
export function navigate(section: SectionId, overrides: Partial<ProjectContext> = {}): void {
  const previous = parseAdminRoute(window.location.hash);
  window.location.hash = adminHref(section, {...previous,...overrides});
}
export function replaceAdminRoute(section: SectionId, context: Partial<ProjectContext>): void {
  window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}${adminHref(section,context)}`);
  window.dispatchEvent(new HashChangeEvent('hashchange'));
}
/** URL сохраняется после обновления страницы, передачи ссылки и перемещения назад/вперёд в статическом развёртывании nginx. */
export function useAdminRoute(): AdminRoute {
  const [route, setRoute] = useState(() => parseAdminRoute(window.location.hash));
  useEffect(() => {
    const update = () => setRoute(parseAdminRoute(window.location.hash));
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  return route;
}

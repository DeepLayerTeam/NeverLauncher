import type { ReleaseVersion0386 } from '../api/release.ts';
import type { ChannelHead } from './owner-lifecycle.ts';

/** Ранее опубликованные релизы НЕ взаимозаменяемы с активным. Только Backend
 * может определить текущий релиз; отсутствие или несовпадение указателя
 * делает откат недоступным, а не выбирает молча последнюю строку. */
export function channelHistory0386(items: ReleaseVersion0386[], projectId: string, profileId: string, channel: string,
  head: ChannelHead | null, headError = ''): {history: ReleaseVersion0386[]; rollbackTargets: ReleaseVersion0386[]; trustedHead: ChannelHead|null} {
  const trustedHead = head && !headError && head.projectId === projectId && head.profileId === profileId && head.channel === channel
    && Number.isSafeInteger(head.revision) && head.revision >= 0 ? head : null;
  const history = items.filter(r => r.status === 'published' && r.profileId === profileId && r.channel === channel)
    .slice().sort((a,b) => {
      const ams = Date.parse(a.publishedAt || '') || 0;
      const bms = Date.parse(b.publishedAt || '') || 0;
      return bms-ams || a.id.localeCompare(b.id);
    });
  return { history, trustedHead, rollbackTargets: trustedHead ? history.filter(r => r.id !== trustedHead.releaseId) : [] };
}

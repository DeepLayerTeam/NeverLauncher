/** 0.35.3 player navigation: URL-free, owner-binding-safe, deterministic screen and history state. */
export const navigation0353 = [
  {id:'overview',title:'Главная',group:'Игра'},
  {id:'accounts',title:'Аккаунты',group:'Игра'},
  {id:'servers',title:'Серверы',group:'Игра'},
  {id:'builds',title:'Сборки',group:'Игра'},
  {id:'optionalMods',title:'Опциональные моды',group:'Игра'},
  {id:'textures',title:'Скины и плащи',group:'Игра'},
  {id:'download',title:'Загрузки',group:'Игра'},
  {id:'history',title:'История запусков',group:'Поддержка'},
  {id:'settings',title:'Настройки',group:'Поддержка'},
  {id:'diagnostics',title:'Диагностика',group:'Поддержка'},
  {id:'migration',title:'Миграция с Gravit',group:'Дополнительно'},
  {id:'extensions',title:'Расширения',group:'Дополнительно'},
] as const;
export type PlayerScreen0353 = typeof navigation0353[number]['id'] | 'firstRun';
const allowed = new Set<string>(['firstRun',...navigation0353.map(item=>item.id)]);
export function restoreScreen0353(stored: string | null, onboardingComplete: boolean): PlayerScreen0353 {
  return onboardingComplete && stored && allowed.has(stored) && stored !== 'firstRun'
    ? stored as PlayerScreen0353 : onboardingComplete ? 'overview' : 'firstRun';
}
export function permittedScreen0353(target: string, signed: boolean, onboardingComplete: boolean, trustError: boolean): boolean {
  if (!allowed.has(target)) return false;
  if (trustError) return target === 'firstRun';
  return !signed || onboardingComplete || ['firstRun','accounts','settings','diagnostics'].includes(target);
}
export type HistoryRow0353 = {
  startedAt:string;projectId:string;profileId:string;version:string;success:boolean;
  exitCode?:number;logPath:string;message:string;
};
export type HistoryFilter0353 = 'all'|'success'|'failed';
export function filterHistory0353(entries:readonly HistoryRow0353[], filter:HistoryFilter0353): HistoryRow0353[] {
  return entries.filter(item=>filter==='all'||(filter==='success' ? item.success : !item.success))
    .slice().sort((a,b)=>{
      const at=Date.parse(a.startedAt), bt=Date.parse(b.startedAt);
      return (Number.isFinite(bt)?bt:0)-(Number.isFinite(at)?at:0);
    });
}
export function chooseProject0353(projectId:string, items:readonly {id:string}[], preferred:string, signedId=''):string {
  if(signedId) return items.some(item=>item.id===signedId) ? signedId : '';
  return items.some(item=>item.id===preferred) ? preferred : items[0]?.id||'';
}
export function chooseProfile0353(profileId:string, items:readonly {id:string}[], preferred:string, signedId=''):string {
  if(signedId) return items.some(item=>item.id===signedId) ? signedId : '';
  return items.some(item=>item.id===preferred) ? preferred : items[0]?.id||'';
}
export function canSelectServer0353(id:string, servers:readonly {id:string;status:string}[], lockedId:string):boolean {
  return (!lockedId||lockedId===id) && (id===''&&!lockedId || servers.some(server=>server.id===id && server.status==='active'));
}
/** Remove an existing project/profile suffix only on exact path components. */
export function gameBaseDirectory0353(root:string, projectId:string, profileId:string):string {
  const trimmed=root.replace(/[\\/]+$/,'');
  if(!projectId||!profileId)return trimmed;
  const parts=trimmed.split(/[\\/]/);
  if(parts.length>=3 && parts[parts.length-2]===projectId && parts[parts.length-1]===profileId)
    return trimmed.slice(0,trimmed.length-projectId.length-profileId.length-2);
  return trimmed;
}

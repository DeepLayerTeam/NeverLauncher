/** User selections reference only component IDs from a signed catalog.
 * They are deliberately NOT a rewritten manifest or an unsigned actions list.
 * Native NeverRuntime remains the sole authority for resolving the final plan.
 */
export const CUSTOM_PREFIX_0247 = '@custom:v1:';
export type ComponentChoice0247 = {base: string; overrides: Map<string, boolean>};
export type SelectableComponent0247 = {
  id:string; name:string; required?:boolean; visible?:boolean; limited?:boolean;
  dependencies?:{id:string;versionRange?:string}[]; conflicts?:{id:string;versionRange?:string}[]; exclusiveGroup?:string;
};
const idPattern = /^[a-z0-9][a-z0-9._-]{0,127}$/;
export function parseChoice0247(encoded:string):ComponentChoice0247 {
  if (!encoded.startsWith(CUSTOM_PREFIX_0247)) return {base:encoded,overrides:new Map()};
  if (encoded.length>8192) throw new Error('Слишком длинный выбор компонентов');
  const content=encoded.slice(CUSTOM_PREFIX_0247.length);
  const split=content.indexOf(':');
  if(split<0)throw new Error('Некорректный формат выбора компонентов');
  const base=content.slice(0,split), changes=content.slice(split+1);
  if(base&&!idPattern.test(base))throw new Error('Некорректный идентификатор пресета');
  const overrides=new Map<string,boolean>();
  for(const item of changes?changes.split(','):[]){
    const id=item.slice(1), operator=item[0];
    if((operator!=='+'&&operator!=='-')||!idPattern.test(id)||overrides.has(id))throw new Error(`Некорректная или повторная операция: ${item}`);
    overrides.set(id,operator==='+');
  }
  return {base,overrides};
}
export function encodeChoice0247(choice:ComponentChoice0247):string {
  if(choice.base&&!idPattern.test(choice.base))throw new Error('Некорректный пресет');
  if(choice.overrides.size===0)return choice.base;
  const changes=[...choice.overrides].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([id,enable])=>{
    if(!idPattern.test(id))throw new Error(`Некорректный компонент: ${id}`);
    return `${enable?'+':'-'}${id}`;
  });
  const encoded=`${CUSTOM_PREFIX_0247}${choice.base}:${changes.join(',')}`;
  if(encoded.length>8192)throw new Error('Слишком много выбранных компонентов');
  return encoded;
}
/** Propose an edit, including safe removal of *current* dependents/conflicts.
 * This is UI assistance only; native validates all transitive constraints.
 */
export function proposeChoice0247(
  encoded:string, components:SelectableComponent0247[], active:string[], id:string, enable:boolean,
):{choice:string;removed:string[];added:string[]} {
  const byID=new Map(components.map(c=>[c.id,c]));
  const target=byID.get(id);
  if(!target||target.required||target.limited||target.visible===false)throw new Error('Этот компонент нельзя изменять вручную');
  const current=new Set(active), next=new Set(current);
  if(enable){
    next.add(id);
    // Include required transitive dependencies before analyzing exclusions.
    const seen=new Set<string>();
    const include=(key:string)=>{
      if(seen.has(key))return;
      seen.add(key);
      for(const dep of byID.get(key)?.dependencies||[]){
        if(!byID.has(dep.id))throw new Error(`Неизвестная зависимость ${dep.id}`);
        next.add(dep.id);include(dep.id);
      }
    };
    include(id);
  }else next.delete(id);
  if(enable){
    // A signed conflict is directional; either component may declare it.
    const enabledNow=new Set([...next].filter(x=>!current.has(x)));
    for(const c of components){
      if(!next.has(c.id)||enabledNow.has(c.id))continue;
      const incompatible=[...enabledNow].some(enabledID=>{
        const enabledComponent=byID.get(enabledID);
        return Boolean(enabledComponent?.exclusiveGroup&&enabledComponent.exclusiveGroup===c.exclusiveGroup)||
          Boolean(enabledComponent?.conflicts?.some(x=>x.id===c.id&&(!x.versionRange||x.versionRange==='*')))||
          Boolean(c.conflicts?.some(x=>x.id===enabledID&&(!x.versionRange||x.versionRange==='*')));
      });
      if(incompatible)next.delete(c.id);
    }
  }
  // If a component becomes unavailable, remove its selected dependents as well.
  let changed=true;
  while(changed){
    changed=false;
    for(const c of components){
      if(!next.has(c.id)||!c.dependencies?.some(dep=>!next.has(dep.id)&&current.has(dep.id)))continue;
      next.delete(c.id);changed=true;
    }
  }
  const removed=[...current].filter(x=>!next.has(x));
  const added=[...next].filter(x=>!current.has(x));
  if(removed.some(x=>byID.get(x)?.required))throw new Error('Конфликт затрагивает обязательный компонент');
  const result=parseChoice0247(encoded);
  for(const name of removed)result.overrides.set(name,false);
  for(const name of added){
    // Dependencies are resolved by native, including hidden signed components.
    if(name===id)result.overrides.set(name,true);
    else result.overrides.delete(name);
  }
  result.overrides.set(id,enable);
  return {choice:encodeChoice0247(result),removed,added};
}

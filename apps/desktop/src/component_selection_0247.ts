/** Player choices only reference identifiers from a signed catalog. NeverRuntime
 * verifies the signature, resolves the final graph and is authoritative for IO.
 */
export const CUSTOM_PREFIX_0247 = '@custom:v1:';
export type ComponentChoice0247 = {base: string; overrides: Map<string, boolean>};
export type SelectableComponent0247 = {
  id:string; name:string; version?:string; required?:boolean; visible?:boolean; limited?:boolean;
  dependencies?:{id:string;versionRange?:string}[];
  conflicts?:{id:string;versionRange?:string}[];
  exclusiveGroup?:string;
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

// Same supported SemVer range operators as the native catalog graph (v3-v5).
// A malformed range must not be silently treated as "no conflict" by the UI.
type Version = {numbers:bigint[];pre:string[]};
const versionPattern=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;
const max64=(1n<<64n)-1n;
function semver(value:string):Version {
  if(value.length>128)throw new Error(`Некорректная версия компонента: ${value}`);
  const match=versionPattern.exec(value);
  if(!match||[match[4],match[5]].filter(Boolean).some(s=>s!.split('.').some(p=>!p||!/^[0-9A-Za-z-]+$/.test(p)))||
    (match?.[4]?.split('.').some(p=>/^\d+$/.test(p)&&p.length>1&&p[0]==='0')))
    throw new Error(`Некорректная версия компонента: ${value}`);
  const numbers=match.slice(1,4).map(x=>BigInt(x));
  if(numbers.some(x=>x>max64))throw new Error(`Версия выходит за допустимый диапазон: ${value}`);
  return {numbers,pre:match[4]?.split('.')||[]};
}
function compare(a:Version,b:Version):number {
  for(let i=0;i<3;i++){if(a.numbers[i]!==b.numbers[i])return a.numbers[i]<b.numbers[i]?-1:1;}
  if(!a.pre.length)return b.pre.length?1:0;
  if(!b.pre.length)return -1;
  for(let i=0;i<Math.min(a.pre.length,b.pre.length);i++){
    const x=a.pre[i],y=b.pre[i],xn=/^\d+$/.test(x),yn=/^\d+$/.test(y);
    if(xn&&yn){const xv=BigInt(x),yv=BigInt(y);if(xv!==yv)return xv<yv?-1:1;}
    else if(xn!==yn)return xn?-1:1;
    else if(x!==y)return x<y?-1:1;
  }
  return Math.sign(a.pre.length-b.pre.length);
}
export function matchesVersion0247(actual:string,range:string):boolean {
  // Native validates the version even for wildcard constraints.
  const version=semver(actual);
  if(!range.trim()||range.trim()==='*')return true;
  if(range.length>256)throw new Error('Слишком длинный диапазон версий');
  return range.split('||').some(branch=>{
    const tokens=branch.trim().split(/\s+/);
    if(!branch.trim()||tokens.length>16)throw new Error(`Некорректный диапазон: ${range}`);
    return tokens.every(token=>{
      if(token==='*')return true;
      const match=/^(>=|<=|>|<|=|\^|~)?(.+)$/.exec(token);
      if(!match)throw new Error(`Некорректное условие: ${token}`);
      const op=match[1]||'=',base=semver(match[2]),cmp=compare(version,base);
      if(op==='=')return cmp===0;
      if(op==='>')return cmp>0;
      if(op==='>=')return cmp>=0;
      if(op==='<')return cmp<0;
      if(op==='<=')return cmp<=0;
      const upper=[...base.numbers];
      if(op==='~'){upper[1]++;upper[2]=0n;}
      else if(upper[0]>0n){upper[0]++;upper[1]=0n;upper[2]=0n;}
      else if(upper[1]>0n){upper[1]++;upper[2]=0n;}
      else upper[2]++;
      if(upper.some(n=>n>max64))throw new Error(`Переполнение диапазона: ${range}`);
      return cmp>=0&&compare(version,{numbers:upper,pre:[]})<0;
    });
  });
}

/** Create a workable candidate before native preview. On enable, the requested
 * component and its entire dependency closure have priority over existing
 * incompatible components. Their dependents are also removed. Never silently
 * evict a required component or a dependency of the requested component.
 */
export function proposeChoice0247(
  encoded:string, components:SelectableComponent0247[], active:string[], id:string, enable:boolean,
):{choice:string;removed:string[];added:string[]} {
  const byID=new Map(components.map(c=>[c.id,c]));
  if(byID.size!==components.length)throw new Error('Повторный ID компонента');
  const target=byID.get(id);
  if(!target||target.required||target.limited||target.visible===false)throw new Error('Этот компонент нельзя изменять вручную');
  const current=new Set(active),next=new Set(current);
  const protectedIDs=new Set<string>();
  if(enable){
    const walk=(key:string)=>{
      if(protectedIDs.has(key))return;
      const component=byID.get(key);
      if(!component)throw new Error(`Неизвестная зависимость: ${key}`);
      protectedIDs.add(key);next.add(key);
      for(const dep of component.dependencies||[]){
        const other=byID.get(dep.id);
        if(!other)throw new Error(`Для ${key} отсутствует зависимость ${dep.id}`);
        if(dep.versionRange&&dep.versionRange!=='*'&&!matchesVersion0247(other.version||'',dep.versionRange))
          throw new Error(`${key} требует ${dep.id} ${dep.versionRange}; доступна ${other.version||'неизвестная версия'}`);
        walk(dep.id);
      }
    };
    walk(id);
  }else next.delete(id);

  const conflicts=(a:SelectableComponent0247,b:SelectableComponent0247)=>
    Boolean(a.exclusiveGroup&&a.exclusiveGroup===b.exclusiveGroup)||
    Boolean(a.conflicts?.some(r=>r.id===b.id&&(!r.versionRange||r.versionRange==='*'||matchesVersion0247(b.version||'',r.versionRange))))||
    Boolean(b.conflicts?.some(r=>r.id===a.id&&(!r.versionRange||r.versionRange==='*'||matchesVersion0247(a.version||'',r.versionRange))));
  if(enable){
    // Check every pair, not merely the directly clicked component. An added
    // transitive dependency may itself conflict with an existing mod.
    for(const requested of components.filter(c=>protectedIDs.has(c.id))){
      for(const other of components){
        if(!next.has(other.id)||requested.id===other.id||!conflicts(requested,other))continue;
        if(protectedIDs.has(other.id))throw new Error(`Несовместимые зависимости: ${requested.name} и ${other.name}`);
        if(other.required)throw new Error(`Конфликт с обязательным компонентом: ${other.name}`);
        next.delete(other.id);
      }
    }
  }
  // Removing a dependency must also remove every selected dependent, including
  // dependents introduced by a signed preset. This is transitive and stable.
  let changed=true;
  while(changed){
    changed=false;
    for(const c of components){
      if(!next.has(c.id)||!c.dependencies?.some(dep=>!next.has(dep.id)))continue;
      if(c.required||protectedIDs.has(c.id))throw new Error(`Невозможно отключить зависимость обязательного компонента ${c.name}`);
      next.delete(c.id);changed=true;
    }
  }
  const removed=[...current].filter(x=>!next.has(x));
  const added=[...next].filter(x=>!current.has(x));
  if(removed.some(x=>byID.get(x)?.required))throw new Error('Конфликт затрагивает обязательный компонент');
  const result=parseChoice0247(encoded);
  for(const name of removed)result.overrides.set(name,false);
  for(const name of added){
    // Native expands dependencies, even hidden ones. Remove stale explicit
    // exclusions rather than granting unrelated user-selected roots.
    if(name===id)result.overrides.set(name,true);
    else result.overrides.delete(name);
  }
  result.overrides.set(id,enable);
  return {choice:encodeChoice0247(result),removed,added};
}

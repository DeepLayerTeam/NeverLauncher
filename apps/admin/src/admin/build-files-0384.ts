/** Browser-side preflight only. The API independently enforces paths and SHA-256. */
export type BuildImportFile0384 = {name:string;webkitRelativePath?:string};
export type PlannedImport0384<T extends BuildImportFile0384> = {file:T;path:string};
const reserved = /^(saves|screenshots|resourcepacks|shaderpacks|config|logs|crash-reports|diagnostics|\.neverlauncher)(\/|$)/i;
const personalFile = /^(options\.txt|optionsof\.txt|servers\.dat|usercache\.json)$/i;
export function normalizeImportPath0384(source: BuildImportFile0384):string {
 const relative=(source.webkitRelativePath||source.name).replace(/\\/g,'/');
 const segments=relative.split('/');
 // Directory-picker entries have an enclosing folder, selected individual files do not.
 const path=(source.webkitRelativePath && segments.length>1 ? segments.slice(1) : segments).join('/');
 if (!path || path.length>1024 || path.startsWith('/') || path.split('/').some(p=>!p||p==='.'||p==='..') || /[\x00-\x1f\x7f]/.test(path) || /^[A-Za-z]:/.test(path)) throw new Error(`Недопустимый путь файла: ${relative}`);
 return path;
}
export function planImports0384<T extends BuildImportFile0384>(files:readonly T[]): {accepted:PlannedImport0384<T>[];skipped:string[]} {
 const accepted:PlannedImport0384<T>[]=[];
 const skipped:string[]=[];
 const seen=new Set<string>();
 for (const file of files) {
  const path=normalizeImportPath0384(file);
  if (reserved.test(path)||personalFile.test(path)){skipped.push(path);continue}
  const folded=path.toLocaleLowerCase('en-US');
  if (seen.has(folded))throw new Error(`Конфликт имён в импортируемой папке (включая регистр): ${path}`);
  seen.add(folded);accepted.push({file,path});
 }
 return {accepted,skipped};
}
export type FileDifference0384={path:string;change:string;oldSha256?:string;newSha256?:string};
export function diffCounts0384(items: readonly FileDifference0384[]): Record<string,number> {
 const counts:Record<string,number>={};
 for(const item of items)counts[item.change]=(counts[item.change]||0)+1;
 return counts;
}
export function hasCompleteBuild0384(files:readonly {path:string;size:number;sha256:string;selected:boolean}[], actual:readonly {path:string;size:number;sha256:string}[]):boolean {
 const selected=files.filter(x=>x.selected);
 if(selected.length!==actual.length)return false;
 const byPath=new Map(actual.map(f=>[f.path,f]));
 return selected.every(f=>{const found=byPath.get(f.path);return !!found && f.sha256===found.sha256 && f.size===found.size});
}

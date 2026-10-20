// The editor works on an unsigned copy. Backend recomputes revision/digest;
// this module deliberately never computes or signs a release checksum.
export type Action0248 = { type: 'File'|'ClassPath'|'JvmArgs'|'ClientArgs'; path?: string; args?:string[] };
export type Relation0248 = {id:string;versionRange?:string};
export type Conditions0248 = {schemaVersion:'1.0';os?:string[];arch?:string[];javaMajorMin?:number;javaMajorMax?:number;minecraftVersions?:string[];minecraftVersionRange?:string;loaders?:string[];loaderVersionRange?:string;permissions?:string[]};
export type Component0248 = {
 id:string;name:string;description?:string;files:string[];version?:string;dependencies?:Relation0248[];conflicts?:Relation0248[];
 exclusiveGroup?:string;conditions?:Conditions0248;actions?:Action0248[];
 categoryId?:string;groupId?:string;required?:boolean;default?:boolean;visible:boolean;limited?:boolean;metadata?:Record<string,string>;
};
export type Category0248 = {id:string;name:string;description?:string;parentId?:string};
export type Group0248 = Category0248 & {categoryId?:string};
export type Preset0248 = {id:string;name:string;description?:string;components:string[]};
export type Catalog0248 = {
 schemaVersion:'5.0';revision:number;digest:string;components:Component0248[];
 categories?:Category0248[];groups?:Group0248[];presets?:Preset0248[];defaultPreset?:string;
};
export type CatalogFile0248 = {path:string;ownership?:string;required?:boolean;size:number;sha256:string};
export type CatalogSnapshot0248 = {packageId:string;projectId:string;status:string;manifestSchemaVersion:string;catalog:Catalog0248|null;files:CatalogFile0248[]};
export type CatalogMutation0248 = {expectedRevision:number;catalog:Catalog0248};
export type CatalogPreview0248 = {valid:boolean;digest:string;revision:number;errors:string[];presets:Array<{preset:string;selected?:string[];error?:string}>};

export const validComponentID0248=(v:string)=>/^[a-z0-9][a-z0-9._-]{0,127}$/.test(v)&&!v.includes('..');
export const splitLines0248=(text:string)=>text.split(/[\n,]/).map(x=>x.trim()).filter(Boolean);
export const parseRelations0248=(text:string):Relation0248[]=>text.split('\n').map(line=>line.trim()).filter(Boolean).map(line=>{
 const space=line.indexOf(' ');
 return space===-1?{id:line}:{id:line.slice(0,space).trim(),versionRange:line.slice(space).trim()};
});
export const formatRelations0248=(values:Relation0248[]|undefined)=>(values||[]).map(x=>x.id+(x.versionRange?' '+x.versionRange:'')).join('\n');
export const freshComponent0248=(id:string,files:string[]):Component0248=>({id,name:id,files,version:'1.0.0',visible:true});
export const listAvailableFiles0248=(catalog:Catalog0248,files:CatalogFile0248[],selectedID:string)=>{
 const owned=new Set(catalog.components.filter(c=>c.id!==selectedID).flatMap(c=>c.files.map(f=>f.toLowerCase())));
 return files.filter(f=>(f.ownership==='optional'||(!f.required&&f.ownership===undefined))&&!owned.has(f.path.toLowerCase()));
};
// Local checks provide immediate form feedback; the server validator is always
// authoritative for constraints, signatures, paths, ownership and presets.
export function lintCatalog0248(cat:Catalog0248,files:CatalogFile0248[]):string[]{
 const errors:string[]=[];
 const ids=new Set<string>();const paths=new Set<string>();
 for(const c of cat.components){
  if(!validComponentID0248(c.id)||ids.has(c.id))errors.push(`Некорректный или дублирующийся ID: ${c.id}`);
  ids.add(c.id);
  if(!c.name.trim())errors.push(`Не указано имя компонента ${c.id}`);
  if(!c.files.length)errors.push(`Компонент ${c.id} не имеет optional-файлов`);
  for(const path of c.files){if(paths.has(path.toLowerCase()))errors.push(`Файл назначен нескольким компонентам: ${path}`);paths.add(path.toLowerCase());}
 }
 const available=new Set(files.filter(f=>f.ownership==='optional'||(!f.required&&!f.ownership)).map(f=>f.path));
 for(const path of paths)if(![...available].some(x=>x.toLowerCase()===path))errors.push(`Файл отсутствует или не optional: ${path}`);
 for(const f of available)if(!paths.has(f.toLowerCase()))errors.push(`Файл не назначен компоненту: ${f}`);
 for(const c of cat.components){
  for(const relation of [...(c.dependencies||[]),...(c.conflicts||[])])if(!ids.has(relation.id))errors.push(`${c.id}: неизвестная ссылка ${relation.id}`);
 }
 const presetIDs=new Set<string>();
 for(const preset of cat.presets||[]){
  if(presetIDs.has(preset.id))errors.push(`Повтор пресета ${preset.id}`);
  presetIDs.add(preset.id);
  for(const id of preset.components)if(!ids.has(id))errors.push(`Пресет ${preset.id}: компонент ${id} отсутствует`);
 }
 if(cat.defaultPreset&&!presetIDs.has(cat.defaultPreset))errors.push('Пресет по умолчанию отсутствует');
 return errors;
}
export function renameComponent0248(cat:Catalog0248,oldID:string,newID:string):Catalog0248{
 return {...cat,components:cat.components.map(c=>({ ...c,id:c.id===oldID?newID:c.id,
  dependencies:c.dependencies?.map(r=>({...r,id:r.id===oldID?newID:r.id})),
  conflicts:c.conflicts?.map(r=>({...r,id:r.id===oldID?newID:r.id}))})),
  presets:cat.presets?.map(p=>({...p,components:p.components.map(id=>id===oldID?newID:id)}))};
}
export function removeComponent0248(cat:Catalog0248,id:string):Catalog0248{
 return {...cat,components:cat.components.filter(c=>c.id!==id).map(c=>({...c,dependencies:c.dependencies?.filter(r=>r.id!==id),conflicts:c.conflicts?.filter(r=>r.id!==id)})),
  presets:cat.presets?.map(p=>({...p,components:p.components.filter(c=>c!==id)}))};
}

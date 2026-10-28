import React, {useMemo, useState} from 'react';
import {canSelectServer0353, filterHistory0353, type HistoryFilter0353, type HistoryRow0353} from './desktop_navigation_0353';

type Project = {id:string;title?:string;name?:string};
type Profile = {id:string;title?:string;name?:string;description?:string;loader?:string;defaultChannel?:string};
type Server = {id:string;name:string;status:string;health:string;kind:string;minecraftVersion?:string};
type ManifestSummary = {projectId:string;profileId:string;version:string;channel:string;minecraft:{version:string;loader:string};files:{path:string}[];componentCatalog?:{components:{id:string;required?:boolean}[]}};

type BuildsProps = {
 projects:Project[];profiles:Profile[];selectedProject:string;selectedProfile:string;manifest:ManifestSummary|null;
 signedProject:string;signedProfile:string;loading:boolean;error:string;
 refresh:()=>void; chooseProject:(id:string)=>void;chooseProfile:(id:string)=>void;showMods:()=>void;showDownloads:()=>void;
};
export function BuildsWorkspace0353({projects,profiles,selectedProject,selectedProfile,manifest,signedProject,signedProfile,loading,error,refresh,chooseProject,chooseProfile,showMods,showDownloads}:BuildsProps){
 return <section className="panel workspace0353"><div className="workspaceHead0353"><div><h3>Сборки и профили</h3><p>Проекты и профили из Backend. Манифест проверяется Native Ed25519 перед установкой.</p></div><button disabled={loading} onClick={refresh}>Обновить каталог</button></div>
 {error&&<p role="alert" className="workspaceError0353">{error}</p>}
 <div className="workspaceSplit0353"><div><h4>Проекты</h4>{!projects.length&&<p>Нет доступных проектов. Проверьте аккаунт и Backend.</p>}
 <div className="workspaceList0353">{projects.map(project=><button key={project.id} disabled={Boolean(signedProject)&&signedProject!==project.id} aria-pressed={selectedProject===project.id} className={selectedProject===project.id?'activeRow':''} onClick={()=>chooseProject(project.id)}><strong>{project.title||project.name||project.id}</strong><small>{project.id}</small></button>)}</div></div>
 <div><h4>Профили</h4>{!selectedProject?<p>Выберите проект.</p>:!profiles.length?<p>Профили не найдены. Обновите каталог.</p>:null}
 <div className="workspaceList0353">{profiles.map(profile=><button key={profile.id} disabled={Boolean(signedProfile)&&signedProfile!==profile.id} aria-pressed={selectedProfile===profile.id} className={selectedProfile===profile.id?'activeRow':''} onClick={()=>chooseProfile(profile.id)}><strong>{profile.title||profile.name||profile.id}</strong><small>{profile.loader||'vanilla'} · {profile.defaultChannel||'stable'}</small>{profile.description&&<small>{profile.description}</small>}</button>)}</div></div></div>
 {manifest&&manifest.projectId===selectedProject&&manifest.profileId===selectedProfile ? <div className="workspaceSummary0353" role="status"><div><strong>{manifest.minecraft.version}</strong><small>Minecraft</small></div><div><strong>{manifest.minecraft.loader}</strong><small>Загрузчик</small></div><div><strong>{manifest.version}</strong><small>Версия сборки · {manifest.channel}</small></div><div><strong>{manifest.files.length}</strong><small>Файлов в манифесте</small></div><div><strong>{manifest.componentCatalog?.components.length||0}</strong><small>Компонентов</small></div></div>:<div><p>Откройте профиль, чтобы получить и проверить подписанный релиз.</p>{selectedProfile&&<button disabled={loading} onClick={()=>chooseProfile(selectedProfile)}>Открыть профиль {selectedProfile}</button>}</div>}
 <div className="toolbar inline"><button disabled={!manifest||loading} onClick={showMods}>Выбрать моды</button><button disabled={!manifest||loading} className="primary" onClick={showDownloads}>Установка / проверка</button></div></section>;
}

type ServersProps = {servers:Server[];selectedId:string;signedId:string;autoEnter:boolean;serverHost:string;serverPort:number;offline:boolean;projectId:string;profileId:string;error:string;loading:boolean;
 reload:()=>void;select:(id:string)=>void;save:()=>Promise<void>;onOpenSettings:()=>void;};
export function ServersWorkspace0353({servers,selectedId,signedId,autoEnter,serverHost,serverPort,offline,projectId,profileId,error,loading,reload,select,save,onOpenSettings}:ServersProps){
 const [saving,setSaving]=useState(false);const [saveError,setSaveError]=useState('');const [saved,setSaved]=useState(false);
 const current=servers.find(s=>s.id===selectedId);
 return <section className="panel workspace0353"><div className="workspaceHead0353"><div><h3>Серверы</h3><p>Узлы ServerBridge активного профиля. Список загружается из Backend; не является DNS-каталогом Minecraft.</p></div><button disabled={loading||!projectId||!profileId} onClick={reload}>Обновить серверы</button></div>
 {error&&<p role="alert" className="workspaceError0353">{error}</p>}
 <p>{projectId&&profileId?`Проект ${projectId} · профиль ${profileId}`:'Сначала выберите сборку.'}</p>
 <div className="workspaceList0353">{servers.map(server=><button key={server.id} className={selectedId===server.id?'activeRow':''} aria-pressed={selectedId===server.id} disabled={!canSelectServer0353(server.id,servers,signedId)} onClick={()=>{select(server.id);setSaved(false);setSaveError('');}}><strong>{server.name} {selectedId===server.id?'· выбран':''}</strong><span>{server.kind} · {server.health||'состояние неизвестно'}{server.minecraftVersion?` · Minecraft ${server.minecraftVersion}`:''}</span></button>)}</div>
 {!servers.length&&<p>Активные серверы отсутствуют или недоступны. Проверьте профиль и подключение.</p>}
 {current&&<p role="status">Выбран: {current.name} ({current.id}). {signedId?'Выбор закреплён подписанным bundle.':'Можно сохранить выбранный сервер для следующих запусков.'}</p>}
 {autoEnter&&<p>Auto-enter: {serverHost?`${serverHost}:${serverPort}`:'не задан публичный игровой адрес'}. Изменение ServerBridge ID само по себе не меняет DNS-адрес сервера.</p>}
 {offline&&<p role="status">Offline режим не создаёт ServerBridge-сессию. Для подключения необходима разрешённая онлайн-аутентификация.</p>}
 {saveError&&<p role="alert" className="workspaceError0353">{saveError}</p>}{saved&&<p role="status">Выбранный сервер сохранён в Desktop-конфигурации.</p>}
 <div className="toolbar inline"><button disabled={saving||loading||!current} onClick={async()=>{setSaving(true);setSaveError('');try{await save();setSaved(true)}catch(e){setSaveError(String(e))}finally{setSaving(false)}}}>{saving?'Сохранение…':'Сохранить выбор'}</button><button onClick={onOpenSettings}>Настройки подключения</button></div>
 </section>;
}

type HistoryProps = {entries:HistoryRow0353[];loading:boolean;error:string;reload:()=>void;activeProcess?:{id:string;state:string;message:string}|null;onStop:()=>void};
export function HistoryWorkspace0353({entries,loading,error,reload,activeProcess,onStop}:HistoryProps){
 const [filter,setFilter]=useState<HistoryFilter0353>('all');
 const [expanded,setExpanded]=useState<string|null>(null);
 const rows=useMemo(()=>filterHistory0353(entries,filter),[entries,filter]);
 return <section className="panel workspace0353"><div className="workspaceHead0353"><div><h3>История запусков</h3><p>Фактические завершения Minecraft из журнала NeverRuntime, не синтетические события интерфейса.</p></div><button disabled={loading} onClick={reload}>Обновить историю</button></div>
 {error&&<p role="alert" className="workspaceError0353">{error}</p>}
 {activeProcess&&['running','stopping'].includes(activeProcess.state)&&<div className="workspaceLive0353" role="status"><strong>Игра запущена</strong><span>{activeProcess.message}</span><button onClick={onStop}>Остановить Minecraft</button></div>}
 <div className="toolbar inline" role="group" aria-label="Фильтр истории">{([['all','Все'],['success','Успешные'],['failed','С ошибками']] as const).map(([id,title])=><button key={id} aria-pressed={filter===id} className={filter===id?'activeRow':''} onClick={()=>setFilter(id)}>{title}</button>)}</div>
 {!rows.length&&<p>Запусков по выбранному фильтру нет.</p>}
 <div className="workspaceHistory0353">{rows.map((item,index)=>{const key=`${item.startedAt}:${item.projectId}:${item.profileId}:${index}`;const selected=expanded===key;return <article key={key} className="workspaceHistoryItem0353"><button aria-expanded={selected} onClick={()=>setExpanded(selected?null:key)}><span className={item.success?'workspaceOk0353':'workspaceFailed0353'}>{item.success?'Успешно':'Ошибка'}</span><strong>{item.profileId} · {item.version}</strong><time dateTime={item.startedAt}>{Number.isFinite(Date.parse(item.startedAt))?new Date(item.startedAt).toLocaleString():'Время неизвестно'}</time><span aria-hidden="true">{selected?'−':'+'}</span></button>{selected&&<div className="workspaceHistoryDetails0353"><p>{item.message||'Нет подробного сообщения.'}</p><dl><dt>Проект</dt><dd>{item.projectId}</dd><dt>Профиль</dt><dd>{item.profileId}</dd><dt>Код завершения</dt><dd>{item.exitCode??'—'}</dd><dt>Путь к локальному логу</dt><dd className="breakAnywhere0353">{item.logPath||'Не указан'}</dd></dl></div>}</article>})}</div>
 </section>;
}

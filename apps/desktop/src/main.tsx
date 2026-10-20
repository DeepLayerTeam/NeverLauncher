import React, { useEffect, useMemo, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import './styles.css';
import { DesktopExtensions0209 } from './extensions_0209';
import { launchPreferences, scopedServers, type ScopedServer } from './desktop_experience_0229';

type Stage = 'idle' | 'connecting' | 'session' | 'project' | 'profile' | 'manifest' | 'java' | 'files' | 'repair' | 'cleanup' | 'ready' | 'launching' | 'running' | 'failed';
type Screen = 'firstRun' | 'overview' | 'auth' | 'projects' | 'profile' | 'download' | 'settings' | 'logs' | 'diagnostics' | 'extensions';

type DesktopSettings = {
  schemaVersion?: string;
  backendUrl: string;
  manifestUrl: string;
  projectId: string;
  profileId: string;
  gameDirectory: string;
  javaPath: string;
  username: string;
  memoryMb: number;
  channel: string;
  pinnedPublicKey: string;
  trustPolicyPath?: string;
  serverId?: string;
  screenWidth: number;
  screenHeight: number;
  fullscreen: boolean;
  autoEnter: boolean;
  serverHost: string;
  serverPort: number;
  offlineEnabled: boolean;
  componentPreset?: string;
  configPath?: string;
};

type CatalogRequirement = {id:string;versionRange?:string};
type CatalogConditions0244 = {schemaVersion:string;os?:string[];arch?:string[];javaMajorMin?:number;javaMajorMax?:number;minecraftVersions?:string[];minecraftVersionRange?:string;loaders?:string[];loaderVersionRange?:string;permissions?:string[]};
type CatalogAction0245 = {type:'File'|'ClassPath'|'JvmArgs'|'ClientArgs';path?:string;args?:string[]};
type CatalogComponent = {actions?:CatalogAction0245[]; conditions?:CatalogConditions0244; id:string; name:string; files:string[]; version?:string; dependencies?:CatalogRequirement[]; conflicts?:CatalogRequirement[]; exclusiveGroup?:string; description?:string; categoryId?:string; groupId?:string; required?:boolean; default?:boolean; visible?:boolean; limited?:boolean; metadata?:Record<string,string> };
type ComponentCatalog = {schemaVersion:string; revision:number; digest:string; components:CatalogComponent[]; categories?:{id:string;name:string;description?:string;parentId?:string}[];groups?:{id:string;name:string;description?:string;parentId?:string;categoryId?:string}[];presets?:{id:string;name:string;description?:string;components:string[]}[];defaultPreset?:string};
// UI explanation only. NeverRuntime's verified resolver is authoritative for IO and launch.
function previewVersion0243(actual:string,range:string):boolean {
  if(!range.trim()||range.trim()==='*')return true;
  const parse=(value:string):{parts:number[];pre:string[]}|null=>{
    const match=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(value);
    if(!match)return null;
    const parts=match.slice(1,4).map(Number);
    return parts.every(Number.isSafeInteger)?{parts,pre:match[4]?.split('.')||[]}:null;
  };
  const compare=(a:ReturnType<typeof parse>,b:ReturnType<typeof parse>):number=>{
    if(!a||!b)throw new Error('Некорректная версия');
    for(let i=0;i<3;i++)if(a.parts[i]!==b.parts[i])return a.parts[i]<b.parts[i]?-1:1;
    if(!a.pre.length&&b.pre.length)return 1;if(a.pre.length&&!b.pre.length)return -1;
    for(let i=0;i<Math.min(a.pre.length,b.pre.length);i++){
      const x=a.pre[i],y=b.pre[i];const xn=/^\d+$/.test(x),yn=/^\d+$/.test(y);
      if(xn&&yn){const xb=BigInt(x),yb=BigInt(y);if(xb!==yb)return xb<yb?-1:1;continue;}
      if(xn!==yn)return xn?-1:1;
      if(x!==y)return x<y?-1:1;
    }
    return Math.sign(a.pre.length-b.pre.length);
  };
  const installed=parse(actual);if(!installed)throw new Error(`Некорректная версия ${actual}`);
  return range.split('||').some(branch=>{
    const pieces=branch.trim().split(/\s+/);if(!branch.trim())throw new Error(`Некорректный диапазон ${range}`);
    return pieces.every(token=>{
      if(token==='*')return true;
      const match=/^(>=|<=|>|<|=|\^|~)?(.+)$/.exec(token);if(!match)throw new Error(`Некорректное условие ${token}`);
      const op=match[1]||'=';const required=parse(match[2]);if(!required)throw new Error(`Некорректная версия ${match[2]}`);
      const result=compare(installed,required);
      if(op==='=')return result===0;if(op==='>=')return result>=0;if(op==='>')return result>0;if(op==='<=')return result<=0;if(op==='<')return result<0;
      const next=[...required.parts];
      if(op==='~'){next[1]++;next[2]=0;}
      else if(next[0]>0){next[0]++;next[1]=0;next[2]=0;}
      else if(next[1]>0){next[1]++;next[2]=0;}else next[2]++;
      return result>=0&&compare(installed,{parts:next,pre:[]})<0;
    });
  });
}
function componentPresetPlan0243(cat:ComponentCatalog,preset:string):{selected:Set<string>;reasons:Map<string,string>;error:string|null}{
  const chosen=new Set<string>();const reasons=new Map<string,string>();
  if(cat.schemaVersion==='1.0')return {selected:new Set(cat.components.map(c=>c.id)),reasons,error:null};
  const byID=new Map(cat.components.map(c=>[c.id,c]));
  const presetID=preset||cat.defaultPreset;
  const selectedPreset=cat.presets?.find(p=>p.id===presetID);
  if(presetID&&!selectedPreset)return {selected:chosen,reasons,error:`Неизвестный пресет: ${presetID}`};
  for(const c of cat.components)if(c.required){chosen.add(c.id);reasons.set(c.id,'Обязательный компонент релиза');}
  const roots=selectedPreset?selectedPreset.components:cat.components.filter(c=>c.default).map(c=>c.id);
  for(const id of roots){chosen.add(id);if(!reasons.has(id))reasons.set(id,presetID?`Пресет ${presetID}`:'Включён по умолчанию');}
  if(cat.schemaVersion!=='3.0'&&cat.schemaVersion!=='4.0')return {selected:chosen,reasons,error:null};
  const expanded=new Set<string>();const stack:string[]=[];
  try {
    const visit=(id:string)=>{
      if(stack.includes(id))throw new Error(`Циклическая зависимость: ${[...stack,id].join(' → ')}`);
      if(expanded.has(id))return;
      const c=byID.get(id);if(!c)throw new Error(`Неизвестный компонент: ${id}`);
      stack.push(id);
      for(const dep of c.dependencies||[]){
        const required=byID.get(dep.id);if(!required)throw new Error(`Для ${id} отсутствует зависимость ${dep.id}`);
        if(!previewVersion0243(required.version||'',dep.versionRange||''))throw new Error(`${id} требует ${dep.id} ${dep.versionRange||'*'}, доступна ${required.version||'неизвестна'}`);
        chosen.add(dep.id);if(!reasons.has(dep.id))reasons.set(dep.id,`Требуется компоненту ${id}`);
        visit(dep.id);
      }
      stack.pop();expanded.add(id);
    };
    for(const c of cat.components)if(chosen.has(c.id))visit(c.id);
    const groups=new Map<string,string>();
    for(const c of cat.components){
      if(!chosen.has(c.id))continue;
      if(c.exclusiveGroup){const other=groups.get(c.exclusiveGroup);if(other)throw new Error(`Взаимоисключающие компоненты: ${other} и ${c.id} (${c.exclusiveGroup})`);groups.set(c.exclusiveGroup,c.id);}
      for(const conflict of c.conflicts||[]){const other=byID.get(conflict.id);if(other&&chosen.has(other.id)&&previewVersion0243(other.version||'',conflict.versionRange||''))throw new Error(`Конфликт: ${c.id} несовместим с ${other.id} ${other.version||''}`);}
    }
  }catch(error){return {selected:chosen,reasons,error:String(error instanceof Error?error.message:error)};}
  return {selected:chosen,reasons,error:null};
}
// Breadcrumbs are calculated from the verified owner-defined hierarchy.
function componentTopologyLabel(cat:ComponentCatalog,component:CatalogComponent):string {
  const chain=(entries:{id:string;name:string;parentId?:string}[],id?:string):string=>{
    const names:string[]=[];const seen=new Set<string>();
    while(id&&names.length<9&&!seen.has(id)){
      seen.add(id);const entry=entries.find(x=>x.id===id);if(!entry)break;
      names.unshift(entry.name);id=entry.parentId;
    }
    return names.join(' / ');
  };
  const group=cat.groups?.find(x=>x.id===component.groupId);
  const categoryID=component.categoryId||group?.categoryId;
  return [chain(cat.categories||[],categoryID),chain(cat.groups||[],component.groupId)].filter(Boolean).join(' · ');
}
type ManifestFile = { path: string; size: number; sha256: string; url: string; mirrors?: string[]; required: boolean; executable?: boolean; ownership?: 'managed' | 'required' | 'optional' | 'user-owned' | 'generated' };
type Manifest = {
  schemaVersion: string;
  projectId: string;
  profileId: string;
  channel: string;
  version: string;
  minecraft: { version: string; loader: string; mainClass?: string; gameArgs?: string[] };
  runtime: {
    java: { majorVersion: number; minimumMajorVersion?: number; recommendedMajorVersion?: number; maximumMajorVersion?: number; distribution: string; allowCustomPath?: boolean };
    jvmArgs?: string[];
    memory?: { minimumMb: number; recommendedMb: number; maximumMb: number };
    launch?: { mainClass?: string; mainModule?: string; classpathStrategy?: string; classpathEntries?: string[]; modulepathEntries?: string[]; environmentAllowlist?: string[]; nativesDirectory?: string; offlineMode?: boolean };
  };
  files: ManifestFile[];
  componentCatalog?: ComponentCatalog;
  fileRules?: { pattern: string; action: 'include' | 'exclude' | 'verify'; ownership: 'managed' | 'required' | 'optional' | 'user-owned' | 'generated' }[];
};

type ManagedJavaResult = {
  status: string; distribution: string; majorVersion: number; releaseName: string; javaExecutable: string;
  installDirectory: string; archiveSha256: string; archiveSize: number; cached: boolean; message: string;
};

type JavaInfoResult = {
  found: boolean;
  compatible: boolean;
  requiredMajorVersion: number;
  detectedMajorVersion?: number;
  executable: string;
  versionOutput: string;
  recommendedMemoryMb?: number;
  maximumMemoryMb?: number;
  message: string;
};

type FileCheckResult = { path: string; status: 'ok' | 'missing' | 'invalid' | string; message: string };
type DownloadResult = { downloaded: number; skipped: number; failed: number; repaired?: number; bytesDownloaded?: number; cacheHits?: number; bytesReused?: number; failedFiles?: string[]; messages: string[] };
type PendingDownload = { operationId: string; mode: string; status: string; projectId: string; profileId: string; version: string; totalFiles: number };
type DownloadProgress = {
  operationId: string; phase: string; totalFiles: number; queued: number; active: number;
  completed: number; failed: number; skipped: number;
  bytesExpected: number; bytesTransferred: number; cacheHits: number; bytesReused: number; currentFile?: string | null;
};
type LaunchPlan = { javaExecutable: string; workingDirectory: string; mainClass: string; mainModule?: string; classpathEntries: string[]; modulepathEntries?: string[]; environmentAllowlist?: string[]; jvmArgs: string[]; gameArgs: string[]; commandPreview: string; deterministicSha256?: string };
type ProcessStatus = { id: string; pid?: number; state: 'running' | 'stopping' | 'exited' | string; startedAt: string; finishedAt?: string; exitCode?: number; success?: boolean; logPath: string; message: string; windowsSensor?: any };
type RepairResult = { status: string; before: FileCheckResult[]; download: DownloadResult; after: FileCheckResult[]; repaired: number; message: string };
type CleanUnusedResult = { moved: number; preserved: number; quarantineDir: string; messages: string[] };
type LaunchHistoryEntry = { startedAt: string; projectId: string; profileId: string; version: string; success: boolean; exitCode?: number; logPath: string; message: string };
type BackendProject = { id: string; title?: string; name?: string; homepage?: string; profilesEndpoint?: string };
type BackendProfile = { id: string; title?: string; name?: string; loader?: string; defaultChannel?: string; description?: string };
type BackendReadiness = { status?: string; version?: string; storage?: unknown; repository?: unknown; checks?: Record<string, unknown> };
type BackendServiceStatus = { name?: string; version?: string; status?: string; environment?: string; message?: string; storage?: unknown };
type DesktopReadiness = { status: string; readiness: BackendReadiness; serviceStatus: BackendServiceStatus; apiVersion: 'v1'; runtime: 'NeverRuntime' };
type DesktopDiagnosticsPolicy = { enabled?: boolean; version?: string; privacyMode?: string; allowedFields?: string[]; redactedFields?: string[]; status?: string };
type DesktopBindingPolicy = { apiVersion: 'v1'; manifestVerification: 'Ed25519 pinned-key required'; runtime: 'NeverRuntime' };
type DesktopBindingResult = { status: string; configPath: string; gameDirectory: string; message: string };
type AuthSession = { accessToken: string; refreshToken: string; sessionId: string; email: string; userId: string; expiresAt?: string };
type DeviceKeyInfo = { userId: string; publicKey: string; fingerprint: string; deviceId?: string; createdAtUnix: number; storageBackend: string; keyAlgorithm: string; keyBinding: string; hardwareProvider: string; hardwareBound: boolean; privateKeyExposedToFrontend: boolean };
type DeviceSignatureResult = { fingerprint: string; publicKey: string; signature: string; keyAlgorithm: string; keyBinding: string; hardwareProvider: string; hardwareBound: boolean };
type ManagedDevice = { id: string; name: string; status: 'active' | 'revoked' | string; trustState: string; assurance: string; keyAlgorithm: string; keyBinding: string; hardwareProvider?: string; attestationState?: string; attestationExpiresAt?: string; keyFingerprint: string; platform?: string; clientVersion?: string; lastSeenAt?: string; lastIp?: string; revokedAt?: string; revokedReason?: string; replacedAt?: string; replacedByDeviceId?: string; replacementReason?: string; current: boolean; revocationPermanent: boolean };
type MinecraftLaunchCredentials = { username: string; uuid: string; accessToken: string; userType: string; authServerBaseUrl: string };
type GuardAttestationSubmission = { launcherVersion: string; attestation: any; signature: string; fingerprint: string; keyAlgorithm: string; keyBinding: string; hardwareProvider: string; hardwareBound: boolean };

type SettingsCheck = { valid: boolean; status: string; messages: string[]; normalizedGameDirectory: string };
type DiagnosticsExport = { path: string; message: string };


function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, (ch) => ch.charCodeAt(0));
}

function bytesToBase64Url(value: ArrayBuffer | ArrayBufferView): string {
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let raw = '';
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeWebAuthnRequestOptions(publicKey: any): PublicKeyCredentialRequestOptions {
  return {
    ...publicKey,
    challenge: base64UrlToBytes(publicKey.challenge),
    allowCredentials: Array.isArray(publicKey.allowCredentials)
      ? publicKey.allowCredentials.map((item: any) => ({ ...item, id: base64UrlToBytes(item.id) }))
      : undefined,
  } as PublicKeyCredentialRequestOptions;
}

const DESKTOP_VERSION = __NEVERLAUNCHER_VERSION__;
const RELEASE_DOCTOR_MARKER = 'Desktop First-Run Binding';

const stageLabels: Record<Stage, string> = {
  idle: 'ожидание',
  connecting: 'подключение',
  session: 'сессия',
  project: 'проект',
  profile: 'профиль',
  manifest: 'манифест',
  java: 'Java',
  files: 'файлы',
  repair: 'восстановление',
  cleanup: 'очистка',
  ready: 'готово',
  launching: 'запуск',
  running: 'работает',
  failed: 'ошибка',
};

const defaultSettings: DesktopSettings = {
  schemaVersion: '1.0',
  backendUrl: '',
  manifestUrl: '',
  projectId: '',
  profileId: '',
  gameDirectory: '',
  javaPath: '',
  username: 'Player',
  memoryMb: 4096,
  channel: 'stable',
  pinnedPublicKey: '',
  serverId: '',
  screenWidth: 1280,
  screenHeight: 720,
  fullscreen: false,
  autoEnter: false,
  serverHost: '',
  serverPort: 25565,
  offlineEnabled: false,
};

function loadSettings(): DesktopSettings {
  try {
    const raw = localStorage.getItem('neverlauncher.desktop.settings');
    return raw ? { ...defaultSettings, ...JSON.parse(raw) } : defaultSettings;
  } catch {
    return defaultSettings;
  }
}

async function callTauri<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  return invoke<T>(command, args);
}

function normalizedSettings(settings: DesktopSettings): DesktopSettings {
  return {
    ...defaultSettings,
    ...settings,
    schemaVersion: '1.0',
    channel: settings.channel || 'stable',
    username: settings.username || 'Player',
    memoryMb: Number(settings.memoryMb ?? 4096),
    screenWidth: Number(settings.screenWidth ?? 1280),
    screenHeight: Number(settings.screenHeight ?? 720),
    serverPort: Number(settings.serverPort ?? 25565),
  };
}

function App() {
  const [settings, setSettings] = useState<DesktopSettings>(() => loadSettings());
  const [screen, setScreen] = useState<Screen>(settings.backendUrl || settings.manifestUrl ? 'overview' : 'firstRun');
  const [stage, setStage] = useState<Stage>('idle');
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [javaInfo, setJavaInfo] = useState<JavaInfoResult | null>(null);
  const [files, setFiles] = useState<FileCheckResult[]>([]);
  const [download, setDownload] = useState<DownloadResult | null>(null);
  const [repairResult, setRepairResult] = useState<RepairResult | null>(null);
  const [downloadProgress, setDownloadProgress] = useState<DownloadProgress | null>(null);
  const [transferBusy, setTransferBusy] = useState(false);
  const [pendingJob, setPendingJob] = useState<PendingDownload | null>(null);
  const recoveryAttempted = useRef(new Set<string>());
  // Recover a durable signed operation after Desktop restart. Explicitly paused
  // jobs stay paused; interrupted/running jobs resume without user intervention.
  useEffect(() => {
    const root = settings.gameDirectory;
    const recoveryId = `${root}|${settings.pinnedPublicKey}`;
    if (!root || !settings.pinnedPublicKey || recoveryAttempted.current.has(recoveryId)) return;
    recoveryAttempted.current.add(recoveryId);
    let disposed = false;
    void callTauri<PendingDownload | null>('pending_download_job', { root, pinnedPublicKey: settings.pinnedPublicKey }).then((job) => {
      if (disposed || !job) return;
      setPendingJob(job);
      if (job.status === 'paused') return;
      setTransferBusy(true);
      void callTauri<DownloadResult>('resume_download_job', { root, pinnedPublicKey: settings.pinnedPublicKey }).then((result) => {
        if (disposed) return;
        setDownload(result);
        setPendingJob(null);
        log(`После перезапуска: скачано ${result.downloaded}, ошибок ${result.failed}.`);
        void callTauri<PendingDownload | null>('pending_download_job', { root, pinnedPublicKey: settings.pinnedPublicKey }).then(setPendingJob);
      }).catch((error) => { if (!disposed) log(`Автовосстановление загрузки: ${String(error)}`); })
        .finally(() => { if (!disposed) setTransferBusy(false); });
    }).catch((error) => { if (!disposed) log(`Проверка сохранённой загрузки: ${String(error)}`); });
    return () => { disposed = true; recoveryAttempted.current.delete(recoveryId); };
  }, [settings.gameDirectory, settings.pinnedPublicKey]);

  useEffect(() => {
    let mounted = true;
    let unlisten: (() => void) | undefined;
    void listen<DownloadProgress>('neverlauncher-download-progress', (event) => {
      if (mounted) setDownloadProgress(event.payload);
    }).then((stop) => { if (mounted) unlisten = stop; else stop(); }).catch(() => { /* Desktop web preview has no Tauri event bus. */ });
    return () => { mounted = false; unlisten?.(); };
  }, []);
  const [cleanResult, setCleanResult] = useState<CleanUnusedResult | null>(null);
  const [launchHistory, setLaunchHistory] = useState<LaunchHistoryEntry[]>([]);
  const [launchPlan, setLaunchPlan] = useState<LaunchPlan | null>(null);
  const [launchResult, setLaunchResult] = useState<ProcessStatus | null>(null);
  const [logs, setLogs] = useState<string[]>([`NeverLauncher Desktop ${DESKTOP_VERSION}: product-клиент ожидает first-run подключение к Backend API.`]);
  const [backendStatus, setBackendStatus] = useState<string>('не проверен');
  const [projects, setProjects] = useState<BackendProject[]>([]);
  const [profiles, setProfiles] = useState<BackendProfile[]>([]);
  const [profileServers, setProfileServers] = useState<ScopedServer[]>([]);
  const [selectedProject, setSelectedProject] = useState<string>(settings.projectId || '');
  const [selectedProfile, setSelectedProfile] = useState<string>(settings.profileId || '');
  const [readinessContract, setReadinessContract] = useState<DesktopReadiness | null>(null);
  const [diagnosticsPolicy, setDiagnosticsPolicy] = useState<DesktopDiagnosticsPolicy | null>(null);
  const [bindingPolicy, setBindingPolicy] = useState<DesktopBindingPolicy | null>(null);
  const [settingsCheck, setSettingsCheck] = useState<SettingsCheck | null>(null);
  const [email, setEmail] = useState('admin@neverlauncher.local');
  const [password, setPassword] = useState('admin');
  const [authSession, setAuthSession] = useState<AuthSession | null>(null);
  const [deviceKey, setDeviceKey] = useState<DeviceKeyInfo | null>(null);
  const [deviceTrustStatus, setDeviceTrustStatus] = useState<string>('не инициализирован');
  const [managedDevices, setManagedDevices] = useState<ManagedDevice[]>([]);

  useEffect(() => {
    callTauri<DesktopSettings>('load_desktop_config')
      .then((config) => {
        const next = normalizedSettings(config);
        if (next.backendUrl || next.manifestUrl) setScreen('overview');
        setSettings(next);
        setSelectedProject(next.projectId || '');
        setSelectedProfile(next.profileId || '');
        log(next.configPath ? `Desktop config загружен: ${next.configPath}.` : 'Desktop config загружен.');
      })
      .catch(() => {
        const fallback = normalizedSettings(loadSettings());
        setSettings(fallback);
        setSelectedProject(fallback.projectId || '');
        setSelectedProfile(fallback.profileId || '');
        log('Конфигурация Tauri недоступна: localStorage fallback разрешён только для web-preview; production-сборка должна использовать конфигурацию Tauri и защищённое хранилище.');
      });
  }, []);

  useEffect(() => {
    if (!settings.backendUrl.trim()) return;
    void restoreSession();
  }, [settings.backendUrl]);

  useEffect(() => {
    if (!launchResult?.id || !['running', 'stopping'].includes(launchResult.state)) return;
    const timer = window.setInterval(() => {
      callTauri<ProcessStatus>('runtime_process_status', { processId: launchResult.id })
        .then((status) => {
          setLaunchResult(status);
          if (status.state === 'exited') {
            setStage(status.success ? 'ready' : 'failed');
            log(status.message);
            void refreshLaunchHistory();
          }
        })
        .catch((error) => log(`Не удалось получить статус runtime process: ${String(error)}`));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [launchResult?.id, launchResult?.state]);

  useEffect(() => {
    const next = normalizedSettings(settings);
    localStorage.setItem('neverlauncher.desktop.settings', JSON.stringify(next));
    if (next.projectId && next.projectId !== selectedProject) setSelectedProject(next.projectId);
    if (next.profileId && next.profileId !== selectedProfile) setSelectedProfile(next.profileId);
  }, [settings]);

  const fileSummary = useMemo(() => {
    const ok = files.filter((file) => file.status === 'ok').length;
    const broken = files.filter((file) => file.status !== 'ok').length;
    return { ok, broken, total: files.length || manifest?.files.length || 0 };
  }, [files, manifest]);

  const readiness = useMemo(() => {
    const checks = [
      backendStatus === 'ready',
      projects.length > 0 || selectedProject.length > 0,
      profiles.length > 0 || selectedProfile.length > 0,
      Boolean(manifest),
      Boolean(javaInfo?.compatible),
      manifest ? fileSummary.broken === 0 : false,
      Boolean(launchPlan),
    ];
    return Math.round((checks.filter(Boolean).length / checks.length) * 100);
  }, [backendStatus, fileSummary.broken, javaInfo, launchPlan, manifest, profiles.length, projects.length, selectedProfile, selectedProject]);

  function patchSettings(key: keyof DesktopSettings, value: string | number | boolean) {
    setSettings((current) => normalizedSettings({ ...current, [key]: value }));
  }

  function selectProject(projectId: string) {
    setSelectedProject(projectId);
    setSelectedProfile('');
    setProfileServers([]);
    setManifest(null);
    setSettings((current) => normalizedSettings({ ...current, projectId, profileId: '', serverId: '', offlineEnabled: false }));
  }

  function selectProfile(profileId: string) {
    setSelectedProfile(profileId);
    const profile = profiles.find((item) => item.id === profileId);
    setManifest(null);
    setProfileServers([]);
    setSettings((current) => normalizedSettings({ ...current, profileId, serverId: '', offlineEnabled: false, channel: profile?.defaultChannel || current.channel || 'stable' }));
  }

  async function persistDesktopConfig() {
    const next = normalizedSettings({ ...settings, projectId: selectedProject, profileId: selectedProfile });
    setSettings(next);
    try {
      const result = await callTauri<DesktopBindingResult>('save_desktop_config', { config: next });
      log(result.message + ` (${result.configPath})`);
    } catch {
      localStorage.setItem('neverlauncher.desktop.settings', JSON.stringify(next));
      log('Привязка Desktop сохранена во временный localStorage fallback; в production Tauri используется каталог конфигурации приложения.');
    }
  }

  async function resetDesktopBinding() {
    try {
      const result = await callTauri<DesktopBindingResult>('reset_desktop_binding');
      setSettings(normalizedSettings({ ...defaultSettings, gameDirectory: result.gameDirectory }));
      setSelectedProject('');
      setSelectedProfile('');
      setProjects([]);
      setProfiles([]);
      setProfileServers([]);
      setManifest(null);
      setScreen('firstRun');
      log(result.message);
    } catch {
      localStorage.removeItem('neverlauncher.desktop.settings');
      setSettings(defaultSettings);
      setSelectedProject('');
      setSelectedProfile('');
      setScreen('firstRun');
      log('Привязка Desktop сброшена во временном localStorage fallback.');
    }
  }

  function log(message: string) {
    setLogs((current) => [`${new Date().toLocaleTimeString()} · ${message}`, ...current].slice(0, 80));
  }

  function endpoint(path: string) {
    const base = settings.backendUrl.trim();
    if (!base) throw new Error('URL Backend не задан: выполните привязку при первом запуске.');
    return `${base.replace(/\/$/, '')}${path}`;
  }

  function buildManifestUrl(projectId = selectedProject, profileId = selectedProfile) {
    if (settings.manifestUrl.trim()) return settings.manifestUrl.trim();
    if (!projectId || !profileId) return '';
    return endpoint(`/api/v1/projects/${encodeURIComponent(projectId)}/profiles/${encodeURIComponent(profileId)}/manifest?channel=${encodeURIComponent(settings.channel || 'stable')}`);
  }

  async function fetchBackendJson(path: string, token = authSession?.accessToken): Promise<any> {
    const response = await fetch(endpoint(path), token ? { headers: { Authorization: `Bearer ${token}` } } : undefined);
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.json();
  }

  function accessTokenPayload(token: string): Record<string, unknown> {
    try {
      const part = token.split('.')[1];
      if (!part) return {};
      const normalized = part.replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
      const payload = JSON.parse(atob(padded));
      return payload && typeof payload === 'object' ? payload : {};
    } catch {
      return {};
    }
  }

  function accessTokenSubject(token: string): string {
    const payload = accessTokenPayload(token);
    return typeof payload.sub === 'string' ? payload.sub : '';
  }

  function accessTokenDeviceId(token: string): string {
    const payload = accessTokenPayload(token);
    return typeof payload.device_id === 'string' ? payload.device_id : '';
  }

  function accessTokenBindingEpoch(token: string): number {
    const payload = accessTokenPayload(token);
    const epoch = typeof payload.binding_epoch === 'number' ? Math.trunc(payload.binding_epoch) : 0;
    return epoch >= 1 ? epoch : 1;
  }

  async function postDeviceJson(path: string, token: string, body: Record<string, unknown> = {}): Promise<Response> {
    return fetch(endpoint(path), {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async function persistTrustedAccess(session: AuthSession, accessToken: string): Promise<AuthSession> {
    const next = { ...session, accessToken };
    await callTauri<void>('store_auth_session', { backendUrl: settings.backendUrl, session: next });
    setAuthSession(next);
    return next;
  }


  async function passkeyStepUp(session: AuthSession): Promise<AuthSession> {
    if (!navigator.credentials?.get) throw new Error('WebAuthn/passkey недоступен в текущем desktop webview.');
    const beginResponse = await postDeviceJson('/api/v1/auth/passkeys/step-up/begin', session.accessToken);
    if (!beginResponse.ok) throw new Error(`Passkey step-up begin: ${beginResponse.status} ${beginResponse.statusText}`);
    const beginPayload = await beginResponse.json();
    const begin = beginPayload.data ?? beginPayload;
    if (!begin.transactionToken || !begin.publicKey?.challenge) throw new Error('Backend вернул неполный passkey step-up challenge.');
    const credential = await navigator.credentials.get({ publicKey: decodeWebAuthnRequestOptions(begin.publicKey) }) as PublicKeyCredential | null;
    if (!credential) throw new Error('Passkey step-up отменён.');
    const assertion = credential.response as AuthenticatorAssertionResponse;
    const completeResponse = await postDeviceJson('/api/v1/auth/passkeys/step-up/complete', session.accessToken, {
      transactionToken: begin.transactionToken,
      credential: {
        id: credential.id, rawId: bytesToBase64Url(credential.rawId), type: credential.type,
        response: {
          clientDataJSON: bytesToBase64Url(assertion.clientDataJSON),
          authenticatorData: bytesToBase64Url(assertion.authenticatorData),
          signature: bytesToBase64Url(assertion.signature),
          userHandle: assertion.userHandle ? bytesToBase64Url(assertion.userHandle) : undefined,
        },
      },
    });
    if (!completeResponse.ok) throw new Error(`Passkey step-up complete: ${completeResponse.status} ${completeResponse.statusText}`);
    const completePayload = await completeResponse.json();
    const data = completePayload.data ?? completePayload;
    if (!data.accessToken) throw new Error('Backend не вернул access token после passkey step-up.');
    log('Выполнена свежая phishing-resistant step-up authentication для восстановления device key.');
    return persistTrustedAccess(session, data.accessToken);
  }

  async function replaceDesktopDeviceKey(mode: 'rotate' | 'recover'): Promise<void> {
    if (!authSession?.accessToken) throw new Error('Требуется активная сессия.');
    const userId = authSession.userId || accessTokenSubject(authSession.accessToken);
    if (!userId) throw new Error('Не удалось определить userId.');
    let session = authSession;
    let oldDeviceId = deviceKey?.deviceId || accessTokenDeviceId(session.accessToken);
    if (!oldDeviceId) throw new Error('Не удалось определить исходный trusted device.');
    if (mode === 'recover') session = await passkeyStepUp(session);

    const staged = await callTauri<DeviceKeyInfo>('stage_device_key_replacement', { backendUrl: settings.backendUrl, userId });
    if (staged.privateKeyExposedToFrontend) throw new Error('Staged private key покинул native boundary; fail-closed.');
    setDeviceTrustStatus(mode === 'rotate' ? 'key rotation' : 'key recovery');
    let serverCommitted = false;
    try {
      const beginPath = mode === 'rotate' ? '/api/v1/auth/devices/key-rotation/begin' : '/api/v1/auth/devices/key-recovery/begin';
      const beginResponse = await postDeviceJson(beginPath, session.accessToken, {
        oldDeviceId, name: `NeverLauncher Desktop · ${navigator.platform || 'desktop'}`.slice(0, 96),
        platform: navigator.platform || 'desktop', clientVersion: DESKTOP_VERSION, publicKey: staged.publicKey,
        keyAlgorithm: staged.keyAlgorithm, keyBinding: staged.keyBinding, hardwareProvider: staged.hardwareProvider || undefined,
      });
      if (!beginResponse.ok) {
        const body = await beginResponse.json().catch(() => null);
        throw new Error(body?.error?.message || `${mode} begin: ${beginResponse.status} ${beginResponse.statusText}`);
      }
      const beginPayload = await beginResponse.json();
      const begin = beginPayload.data ?? beginPayload;
      if (!begin.challengeId || !begin.challenge || !begin.signingPayload || !begin.newDeviceId) throw new Error('Backend вернул неполный key replacement challenge.');
      if (begin.newFingerprint !== staged.fingerprint) throw new Error('Backend replacement fingerprint не совпадает со staged key.');
      const newProof = await callTauri<DeviceSignatureResult>('sign_staged_device_replacement', { backendUrl: settings.backendUrl, userId, payload: begin.signingPayload });
      if (newProof.fingerprint !== staged.fingerprint) throw new Error('Staged signer вернул другую identity.');
      let oldSignature = '';
      if (mode === 'rotate') {
        const oldProof = await callTauri<DeviceSignatureResult>('sign_current_device_replacement', { backendUrl: settings.backendUrl, userId, payload: begin.signingPayload });
        if (!deviceKey || oldProof.fingerprint !== deviceKey.fingerprint) throw new Error('Current-key rotation proof подписан неожиданной identity.');
        oldSignature = oldProof.signature;
      }
      const completePath = `/api/v1/auth/devices/${encodeURIComponent(oldDeviceId)}/key-${mode === 'rotate' ? 'rotation' : 'recovery'}/complete`;
      const completeResponse = await postDeviceJson(completePath, session.accessToken, { challengeId: begin.challengeId, challenge: begin.challenge, oldSignature: oldSignature || undefined, newSignature: newProof.signature });
      const completePayload = await completeResponse.json().catch(() => null);
      if (!completeResponse.ok) throw new Error(completePayload?.error?.message || `${mode} complete: ${completeResponse.status} ${completeResponse.statusText}`);
      const data = completePayload.data ?? completePayload;
      if (!data.accessToken || !data.device?.id) throw new Error('Backend не вернул replacement device/access token.');
      serverCommitted = true;
      session = await persistTrustedAccess(session, data.accessToken);
      const committed = await callTauri<DeviceKeyInfo>('commit_staged_device_key', { backendUrl: settings.backendUrl, userId, deviceId: data.device.id });
      setDeviceKey(committed);
      setDeviceTrustStatus(committed.keyBinding === 'hardware' ? 'rotated · требуется attestation' : 'rotated · verified');
      log(`Device key ${mode === 'rotate' ? 'rotated' : 'recovered'}: ${oldDeviceId} → ${data.device.id}; старый fingerprint оставлен permanent tombstone.`);
      if (committed.keyBinding === 'hardware') session = await attestDesktopDeviceKey(session, committed);
      await loadManagedDevices(session);
    } catch (error) {
      if (!serverCommitted) await callTauri<void>('abort_staged_device_key', { backendUrl: settings.backendUrl, userId }).catch(() => undefined);
      else log('Backend уже завершил replacement; staged key сохранён для повторного commit/reconciliation после ошибки native storage.');
      throw error;
    }
  }

  async function reconcileStagedReplacement(session: AuthSession): Promise<DeviceKeyInfo | null> {
    const userId = session.userId || accessTokenSubject(session.accessToken);
    if (!userId) return null;
    const staged = await callTauri<DeviceKeyInfo | null>('staged_device_key_status', { backendUrl: settings.backendUrl, userId });
    if (!staged) return null;
    const response = await fetch(endpoint('/api/v1/auth/devices?status=active'), { headers: { Authorization: `Bearer ${session.accessToken}` } });
    if (!response.ok) return null;
    const payload = await response.json(); const data = payload.data ?? payload;
    const match = (Array.isArray(data.items) ? data.items : []).find((item: ManagedDevice) => item.status === 'active' && item.keyFingerprint === staged.fingerprint);
    if (!match) return null;
    const committed = await callTauri<DeviceKeyInfo>('commit_staged_device_key', { backendUrl: settings.backendUrl, userId, deviceId: match.id });
    setDeviceKey(committed);
    log(`Завершён interrupted staged-key commit для device ${match.id}; текущая session повторно подтвердит possession и binding.`);
    return committed;
  }

  async function attestDesktopDeviceKey(session: AuthSession, key: DeviceKeyInfo): Promise<AuthSession> {
    if (key.keyBinding !== 'hardware' || key.keyAlgorithm !== 'p256') {
      setDeviceTrustStatus('verified · software proof-of-possession');
      return session;
    }
    if (!key.deviceId) throw new Error('Hardware attestation требует зарегистрированный deviceId.');
    setDeviceTrustStatus('hardware attestation');
    const beginResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(key.deviceId)}/attest/begin`, session.accessToken);
    if (!beginResponse.ok) throw new Error(`Device attestation begin: ${beginResponse.status} ${beginResponse.statusText}`);
    const beginPayload = await beginResponse.json();
    const begin = beginPayload.data ?? beginPayload;
    if (!begin.challengeId || !begin.challenge || !begin.signingPayload || !begin.attestationValidUntil) throw new Error('Backend вернул неполный device attestation challenge.');
    if (begin.hardwareProvenance !== 'not-remotely-verified') throw new Error('Backend вернул неизвестную hardware provenance semantics; fail-closed.');

    const signature = await callTauri<DeviceSignatureResult>('attest_device_payload', { backendUrl: settings.backendUrl, userId: session.userId, payload: begin.signingPayload });
    if (signature.fingerprint !== key.fingerprint || signature.publicKey !== key.publicKey || signature.keyAlgorithm !== 'p256' || signature.keyBinding !== 'hardware' || !signature.hardwareBound) {
      throw new Error('Native attestation signer вернул другую или не-hardware identity.');
    }
    const completeResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(key.deviceId)}/attest/complete`, session.accessToken, {
      challengeId: begin.challengeId,
      deviceId: key.deviceId,
      challenge: begin.challenge,
      signature: signature.signature,
    });
    if (!completeResponse.ok) throw new Error(`Device attestation complete: ${completeResponse.status} ${completeResponse.statusText}`);
    const completePayload = await completeResponse.json();
    const data = completePayload.data ?? completePayload;
    if (!data.accessToken || data.attestationState !== 'verified' || data.attestationMethod !== 'challenge-response-v1') throw new Error('Backend не подтвердил challenge-response attestation.');
    if (data.hardwareProvenance !== 'not-remotely-verified' || data.authorizationElevation !== false || data.phishingResistantElevation !== false) {
      throw new Error('Backend изменил security semantics device attestation; fail-closed.');
    }
    setDeviceTrustStatus(`attested · до ${new Date(data.attestationExpiresAt).toLocaleString()}`);
    log(`Challenge-response attestation подтверждён для ${key.deviceId}; freshness=${data.attestationExpiresAt}. Проверено владение зарегистрированным hardware key; vendor TPM/Secure Enclave provenance не заявляется.`);
    return persistTrustedAccess(session, data.accessToken);
  }

  async function registerDesktopDeviceKey(session: AuthSession, key: DeviceKeyInfo, retryOnConflict = true): Promise<AuthSession> {
    const beginResponse = await postDeviceJson('/api/v1/auth/devices/register/begin', session.accessToken, {
      name: `NeverLauncher Desktop · ${navigator.platform || 'desktop'}`.slice(0, 96),
      platform: navigator.platform || 'desktop',
      clientVersion: DESKTOP_VERSION,
      keyAlgorithm: key.keyAlgorithm,
      keyBinding: key.keyBinding,
      hardwareProvider: key.hardwareProvider || undefined,
    });
    if (!beginResponse.ok) throw new Error(`Device registration begin: ${beginResponse.status} ${beginResponse.statusText}`);
    const beginPayload = await beginResponse.json();
    const begin = beginPayload.data ?? beginPayload;
    if (!begin.challengeId || !begin.deviceId || !begin.challenge || !begin.signingPayload) throw new Error('Backend вернул неполный device registration challenge.');
    const signature = await callTauri<DeviceSignatureResult>('sign_device_payload', { backendUrl: settings.backendUrl, userId: session.userId, payload: begin.signingPayload });
    if (signature.fingerprint !== key.fingerprint || signature.publicKey !== key.publicKey || signature.keyAlgorithm !== key.keyAlgorithm || signature.keyBinding !== key.keyBinding) throw new Error('Native device key backend вернул другую identity.');
    const completeResponse = await postDeviceJson('/api/v1/auth/devices/register/complete', session.accessToken, {
      challengeId: begin.challengeId,
      deviceId: begin.deviceId,
      challenge: begin.challenge,
      publicKey: signature.publicKey,
      signature: signature.signature,
    });
    if (completeResponse.status === 409 && retryOnConflict) {
      const replacement = await callTauri<DeviceKeyInfo>('reset_device_key', { backendUrl: settings.backendUrl, userId: session.userId });
      setDeviceKey(replacement);
      log('Локальный device key уже зарегистрирован в другом server record; создан новый ключ в OS secure storage и регистрация повторяется.');
      return registerDesktopDeviceKey(session, replacement, false);
    }
    if (!completeResponse.ok) throw new Error(`Device registration complete: ${completeResponse.status} ${completeResponse.statusText}`);
    const completePayload = await completeResponse.json();
    const data = completePayload.data ?? completePayload;
    if (!data.accessToken) throw new Error('Backend не вернул access token после device registration.');
    const bound = await callTauri<DeviceKeyInfo>('bind_device_key', { backendUrl: settings.backendUrl, userId: session.userId, deviceId: begin.deviceId });
    setDeviceKey(bound);
    setDeviceTrustStatus('verified');
    log(`Устройство зарегистрировано: ${bound.fingerprint.slice(0, 16)}…; binding=${bound.keyBinding}; provider=${bound.hardwareProvider || bound.storageBackend}; private key не покидает native boundary.`);
    const trusted = await persistTrustedAccess(session, data.accessToken);
    return attestDesktopDeviceKey(trusted, bound);
  }

  async function verifyDesktopDeviceKey(session: AuthSession, key: DeviceKeyInfo): Promise<AuthSession> {
    if (!key.deviceId) return registerDesktopDeviceKey(session, key);
    const beginResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(key.deviceId)}/verify/begin`, session.accessToken);
    if (beginResponse.status === 404) {
      setDeviceTrustStatus('требуется recovery');
      throw new Error('Server device record отсутствует или отозван. Локальный ключ сохранён; используйте «Восстановить ключ», чтобы заменить identity через phishing-resistant recovery без потери rollback-возможности.');
    }
    if (!beginResponse.ok) throw new Error(`Device verification begin: ${beginResponse.status} ${beginResponse.statusText}`);
    const beginPayload = await beginResponse.json();
    const begin = beginPayload.data ?? beginPayload;
    if (!begin.challengeId || !begin.challenge || !begin.signingPayload) throw new Error('Backend вернул неполный device verification challenge.');
    const signature = await callTauri<DeviceSignatureResult>('sign_device_payload', { backendUrl: settings.backendUrl, userId: session.userId, payload: begin.signingPayload });
    if (signature.fingerprint !== key.fingerprint) throw new Error('Device key fingerprint изменился во время proof-of-possession.');
    const completeResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(key.deviceId)}/verify/complete`, session.accessToken, {
      challengeId: begin.challengeId,
      deviceId: key.deviceId,
      challenge: begin.challenge,
      signature: signature.signature,
    });
    if (!completeResponse.ok) throw new Error(`Device verification complete: ${completeResponse.status} ${completeResponse.statusText}`);
    const completePayload = await completeResponse.json();
    const data = completePayload.data ?? completePayload;
    if (!data.accessToken) throw new Error('Backend не вернул access token после device verification.');
    setDeviceTrustStatus('verified');
    log(`Proof-of-possession подтверждён устройством ${key.deviceId}; binding=${key.keyBinding}; provider=${key.hardwareProvider || key.storageBackend}.`);
    const trusted = await persistTrustedAccess(session, data.accessToken);
    return attestDesktopDeviceKey(trusted, key);
  }

  async function ensureDesktopDeviceTrust(session: AuthSession): Promise<AuthSession> {
    const userId = session.userId || accessTokenSubject(session.accessToken);
    if (!userId) throw new Error('Не удалось определить canonical user id для device key.');
    const normalized = session.userId ? session : { ...session, userId };
    if (!session.userId) await callTauri<void>('store_auth_session', { backendUrl: settings.backendUrl, session: normalized });
    setDeviceTrustStatus('проверяется');
    const reconciled = await reconcileStagedReplacement(normalized);
    if (reconciled) return verifyDesktopDeviceKey(normalized, reconciled);
    const key = await callTauri<DeviceKeyInfo>('ensure_device_key', { backendUrl: settings.backendUrl, userId });
    if (key.privateKeyExposedToFrontend) throw new Error('Device key backend сообщил private key exposed to frontend; fail-closed.');
    setDeviceKey(key);
    return verifyDesktopDeviceKey(normalized, key);
  }

  async function refreshDeviceKeyStatus() {
    if (!authSession?.accessToken) return;
    const userId = authSession.userId || accessTokenSubject(authSession.accessToken);
    if (!userId) return;
    const key = await callTauri<DeviceKeyInfo | null>('device_key_status', { backendUrl: settings.backendUrl, userId });
    setDeviceKey(key);
    setDeviceTrustStatus(key?.deviceId ? 'registered' : key ? 'local-key-only' : 'not-created');
  }

  async function loadManagedDevices(session: AuthSession | null = authSession) {
    if (!session?.accessToken) { setManagedDevices([]); return; }
    const response = await fetch(endpoint('/api/v1/auth/devices'), { headers: { Authorization: `Bearer ${session.accessToken}` } });
    if (!response.ok) throw new Error(`Device list: ${response.status} ${response.statusText}`);
    const payload = await response.json();
    const data = payload.data ?? payload;
    setManagedDevices(Array.isArray(data.items) ? data.items : []);
  }

  async function renameManagedDevice(device: ManagedDevice) {
    if (!authSession?.accessToken || device.status !== 'active') return;
    const name = window.prompt('Новое имя устройства', device.name)?.trim();
    if (!name || name === device.name) return;
    const response = await fetch(endpoint(`/api/v1/auth/devices/${encodeURIComponent(device.id)}`), {
      method: 'PATCH',
      headers: { Authorization: `Bearer ${authSession.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!response.ok) throw new Error(`Device rename: ${response.status} ${response.statusText}`);
    await loadManagedDevices(authSession);
    log(`Trusted device ${device.id} переименован.`);
  }

  async function revokeManagedDevice(device: ManagedDevice) {
    if (!authSession?.accessToken || device.status !== 'active') return;
    const warning = device.current
      ? 'Отозвать текущее устройство? Текущая Never session, refresh token, Minecraft session и device key станут недействительными. Для повторной регистрации будет создан новый ключ.'
      : `Отозвать устройство «${device.name}»? Все связанные с ним сессии будут немедленно завершены, а старый ключ нельзя будет зарегистрировать повторно.`;
    if (!window.confirm(warning)) return;
    const response = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(device.id)}/revoke`, authSession.accessToken, { reason: device.current ? 'desktop-self-revoke' : 'desktop-device-revoke' });
    if (!response.ok) throw new Error(`Device revoke: ${response.status} ${response.statusText}`);
    const payload = await response.json();
    const data = payload.data ?? payload;
    log(`Устройство ${device.id} отозвано: sessions=${data.revokedSessions ?? 0}, refreshFamilies=${data.revokedRefreshFamilies ?? 0}, minecraft=${data.revokedMinecraftSessions ?? 0}, challenges=${data.invalidatedChallenges ?? 0}.`);
    if (device.current) {
      if (authSession.userId) await callTauri<void>('delete_device_key', { backendUrl: settings.backendUrl, userId: authSession.userId }).catch(() => undefined);
      await callTauri<void>('delete_auth_session', { backendUrl: settings.backendUrl }).catch(() => undefined);
      setAuthSession(null);
      setDeviceKey(null);
      setManagedDevices([]);
      setDeviceTrustStatus('revoked · требуется новый вход и новый device key');
      return;
    }
    await loadManagedDevices(authSession);
  }

  async function revokeOtherManagedDevices() {
    if (!authSession?.accessToken) return;
    if (!window.confirm('Отозвать все остальные trusted devices? Текущее устройство останется активным; остальные device keys и связанные сессии будут отозваны без возможности восстановления ключа.')) return;
    const response = await postDeviceJson('/api/v1/auth/devices/revoke-others', authSession.accessToken, { reason: 'desktop-revoke-other-devices' });
    if (!response.ok) throw new Error(`Revoke other devices: ${response.status} ${response.statusText}`);
    const payload = await response.json();
    const data = payload.data ?? payload;
    log(`Другие устройства отозваны: devices=${data.revokedDevices ?? 0}, sessions=${data.revokedSessions ?? 0}, minecraft=${data.revokedMinecraftSessions ?? 0}, challenges=${data.invalidatedChallenges ?? 0}.`);
    await loadManagedDevices(authSession);
  }

  async function loginDesktop() {
    setStage('session');
    const response = await fetch(endpoint('/api/v1/auth/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, deviceId: 'desktop-client' }),
    });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    const payload = await response.json();
    const next: AuthSession = {
      accessToken: payload.data.tokens.accessToken,
      refreshToken: payload.data.tokens.refreshToken,
      sessionId: payload.data.session.id,
      email,
      userId: payload.data.user?.id || payload.data.session?.userId || accessTokenSubject(payload.data.tokens.accessToken),
    };
    if (!next.userId) throw new Error('Backend не вернул canonical user id.');
    await callTauri<void>('store_auth_session', { backendUrl: settings.backendUrl, session: next });
    setAuthSession(next);
    log(`Вход выполнен. Серверная сессия ${next.sessionId} сохранена в системном хранилище учётных данных; refresh token не записывается в конфигурацию/localStorage.`);
    try {
      const trusted = await ensureDesktopDeviceTrust(next);
      await loadManagedDevices(trusted);
    } catch (error) {
      setDeviceTrustStatus('ошибка');
      log(`Device Trust не активирован: ${String(error)}`);
    }
  }

  async function rotateDesktopSession(session: AuthSession): Promise<AuthSession> {
    if (!session.refreshToken) throw new Error('нет refresh token: выполните вход заново');
    const userId = session.userId || accessTokenSubject(session.accessToken);
    const body: Record<string, unknown> = { refreshToken: session.refreshToken };
    const tokenDeviceId = accessTokenDeviceId(session.accessToken);
    if (userId && tokenDeviceId) {
      const key = await callTauri<DeviceKeyInfo | null>('device_key_status', { backendUrl: settings.backendUrl, userId });
      if (!key?.deviceId || key.deviceId !== tokenDeviceId) {
        throw new Error('сессия привязана к trusted device, но соответствующий device key отсутствует в OS secure storage');
      }
      const proof = await callTauri<DeviceSignatureResult>('sign_session_refresh', {
        backendUrl: settings.backendUrl,
        userId,
        sessionId: session.sessionId,
        deviceId: tokenDeviceId,
        bindingEpoch: accessTokenBindingEpoch(session.accessToken),
        refreshToken: session.refreshToken,
      });
      if (proof.fingerprint !== key.fingerprint) throw new Error('refresh proof подписан неожиданным device key');
      body.deviceId = tokenDeviceId;
      body.deviceSignature = proof.signature;
      setDeviceKey(key);
    }
    const response = await fetch(endpoint('/api/v1/auth/refresh'), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    if (!response.ok) {
      const errorPayload = await response.json().catch(() => null);
      const message = errorPayload?.error?.message || `${response.status} ${response.statusText}`;
      throw new Error(message);
    }
    const payload = await response.json();
    const next: AuthSession = { ...session, accessToken: payload.data.tokens.accessToken, refreshToken: payload.data.tokens.refreshToken, sessionId: payload.data.session.id, userId: userId || accessTokenSubject(payload.data.tokens.accessToken) };
    await callTauri<void>('store_auth_session', { backendUrl: settings.backendUrl, session: next });
    setAuthSession(next);
    return next;
  }

  async function refreshDesktopSession() {
    if (!authSession) throw new Error('нет сохранённой сессии: выполните вход заново');
    await rotateDesktopSession(authSession);
    log('Сессия обновлена: refresh token ротирован сервером и атомарно заменён в системном хранилище учётных данных.');
  }

  async function logoutDesktop() {
    if (authSession?.accessToken) {
      await fetch(endpoint('/api/v1/auth/logout'), { method: 'POST', headers: { Authorization: `Bearer ${authSession.accessToken}` } }).catch(() => undefined);
    }
    await callTauri<void>('delete_auth_session', { backendUrl: settings.backendUrl });
    setAuthSession(null);
    setManagedDevices([]);
    setDeviceTrustStatus(deviceKey ? 'ключ сохранён локально' : 'не инициализирован');
    log('Сессия отозвана на сервере и удалена из системного хранилища учётных данных. Device key сохранён в OS secure storage для следующего входа.');
  }

  async function checkBackend() {
    setStage('connecting');
    try {
      if (!settings.backendUrl.trim()) throw new Error('Backend URL не задан');
      await fetchBackendJson('/health');
      const readiness = await fetchBackendJson('/ready');
      const status = await fetchBackendJson('/api/v1/status');
      await fetchBackendJson('/api/v1/runtime/requirements');
      const diagnostics = await fetchBackendJson('/api/v1/diagnostics/policy');
      setReadinessContract({
        status: String(readiness?.status ?? status?.status ?? 'ready'),
        readiness: readiness ?? {},
        serviceStatus: status ?? {},
        apiVersion: 'v1',
        runtime: 'NeverRuntime',
      });
      setDiagnosticsPolicy(diagnostics ? { ...diagnostics, status: diagnostics.enabled === false ? 'disabled' : 'enabled' } : null);
      setBindingPolicy({ apiVersion: 'v1', manifestVerification: 'Ed25519 pinned-key required', runtime: 'NeverRuntime' });
      setBackendStatus('ready');
      log('Backend API v1 готов: health, readiness, status, требования runtime и политика диагностики отвечают.');
    } catch (error) {
      setBackendStatus('failed');
      setStage('failed');
      log(`Backend API недоступен: ${String(error)}`);
    }
  }

  async function restoreSession() {
    setStage('session');
    try {
      const stored = await callTauri<AuthSession | null>('load_auth_session', { backendUrl: settings.backendUrl });
      if (!stored) { setAuthSession(null); log('Сохранённая сессия в системном хранилище учётных данных отсутствует.'); return; }
      try {
        const payload = await fetchBackendJson('/api/v1/auth/accounts', stored.accessToken);
        const normalized = { ...stored, userId: stored.userId || accessTokenSubject(stored.accessToken) };
        setAuthSession(normalized);
        if (normalized.userId) await callTauri<void>('store_auth_session', { backendUrl: settings.backendUrl, session: normalized });
        log(`Сессия восстановлена из системного хранилища учётных данных: ${Array.isArray(payload?.data?.items) ? payload.data.items.length : 'ok'}.`);
        if (normalized.userId) {
          try { const trusted = await ensureDesktopDeviceTrust(normalized); await loadManagedDevices(trusted); } catch (error) { setDeviceTrustStatus('ошибка'); log(`Device Trust при восстановлении не подтверждён: ${String(error)}`); }
        }
      } catch {
        const rotated = await rotateDesktopSession({ ...stored, userId: stored.userId || accessTokenSubject(stored.accessToken) });
        log('Access token истёк; сессия восстановлена через ротацию refresh token из системного хранилища учётных данных.');
        if (rotated.userId) {
          try { const trusted = await ensureDesktopDeviceTrust(rotated); await loadManagedDevices(trusted); } catch (error) { setDeviceTrustStatus('ошибка'); log(`Device Trust после refresh не подтверждён: ${String(error)}`); }
        }
      }
    } catch (error) {
      setAuthSession(null);
      log(`Сессию восстановить не удалось: ${String(error)}`);
    }
  }

  async function loadProjects(): Promise<string> {
    setStage('project');
    try {
      const payload = await fetchBackendJson('/api/v1/projects');
      const items: BackendProject[] = payload?.items ?? [];
      setProjects(items);
      const nextProject = selectedProject || settings.projectId || items[0]?.id || '';
      if (nextProject) selectProject(nextProject);
      log(`Проекты загружены: ${items.length}.`);
      return nextProject;
    } catch (error) {
      setStage('failed');
      log(`Не удалось загрузить проекты: ${String(error)}`);
      return '';
    }
  }

  async function loadProfiles(projectId = selectedProject || settings.projectId): Promise<string> {
    setStage('profile');
    try {
      if (!projectId) throw new Error('проект не выбран');
      const payload = await fetchBackendJson(`/api/v1/projects/${projectId}/profiles`);
      const items: BackendProfile[] = payload?.items ?? [];
      setProfiles(items);
      const nextProfile = selectedProfile || settings.profileId || items[0]?.id || '';
      if (nextProfile) selectProfile(nextProfile);
      log(`Профили проекта ${projectId}: ${items.length}.`);
      return nextProfile;
    } catch (error) {
      setStage('failed');
      log(`Не удалось загрузить профили: ${String(error)}`);
      return '';
    }
  }

  async function loadProfileServers(projectId = selectedProject || settings.projectId, profileId = selectedProfile || settings.profileId) {
    if (!projectId || !profileId) throw new Error('Select a project and profile first');
    const payload = await fetchBackendJson(`/api/v1/projects/${encodeURIComponent(projectId)}/profiles/${encodeURIComponent(profileId)}/servers`);
    const items = scopedServers(payload?.data ?? payload);
    setProfileServers(items);
    setSettings((current) => items.some((item) => item.id === current.serverId) ? current : { ...current, serverId: '' });
    log(`Доступные серверы профиля: ${items.length}.`);
  }

  async function cacheSignedManifest(activeManifest = manifest, root = settings.gameDirectory) {
    if (!activeManifest) throw new Error('Нет подписанного манифеста для кеширования');
    await callTauri<void>('cache_desktop_manifest', {
      manifest: activeManifest, root, pinnedPublicKey: settings.pinnedPublicKey,
    });
    log('Подписанный Manifest сохранён в локальный offline cache (повторная проверка подписи обязательна).');
  }

  async function loadCachedOfflineManifest() {
    try {
      const result = await callTauri<Manifest>('load_cached_desktop_manifest', {
        root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey,
        projectId: settings.projectId, profileId: settings.profileId, channel: settings.channel,
      });
      setManifest(result);
      setProfileServers([]);
      setLaunchPlan(null);
      patchSettings('offlineEnabled', true);
      log(`Offline Manifest ${result.version} проверен по pinned Ed25519 ключу.`);
    } catch (error) { log(`Offline Manifest отклонён: ${String(error)}`); }
  }

  function currentLaunchPreferences() {
    if (!manifest) throw new Error('Manifest не загружен');
    if (!['2.0','3.0'].includes(manifest.schemaVersion)) throw new Error('Desktop launch settings require Manifest v2/v3');
    return launchPreferences(settings, manifest.runtime.memory, Boolean(manifest.runtime.launch?.offlineMode), profileServers);
  }

  async function loadManifest(projectId = selectedProject || settings.projectId, profileId = selectedProfile || settings.profileId) {
    setStage('manifest');
    try {
      const url = buildManifestUrl(projectId, profileId);
      if (!url) throw new Error('сначала выберите проект и профиль');
      const result = await callTauri<Manifest>('load_manifest', { url, pinnedPublicKey: settings.pinnedPublicKey });
      setManifest(result);
      if (settings.componentPreset && !(result.componentCatalog?.presets||[]).some(p=>p.id===settings.componentPreset)) {
        patchSettings('componentPreset','');
      }
      setSelectedProject(result.projectId);
      setSelectedProfile(result.profileId);
      setLaunchPlan(null);
      setLaunchResult(null);
      if (!settings.offlineEnabled) {
        await loadProfileServers(result.projectId, result.profileId).catch((error) => log(`Server browser недоступен: ${String(error)}`));
      }
      const effectiveRoot = settings.gameDirectory.includes(result.projectId)
        ? settings.gameDirectory
        : `${settings.gameDirectory || './.neverlauncher/projects'}/${result.projectId}/${result.profileId}`;
      void cacheSignedManifest(result, effectiveRoot).catch((error) => log(`Offline cache не сохранён: ${String(error)}`));
      log(`Манифест загружен: ${result.projectId}/${result.profileId}/${result.version}.`);
      const policy = result.runtime.memory;
      const minMemory = Math.max(512, policy?.minimumMb || 512);
      const maxMemory = Math.min(32768, policy?.maximumMb || 32768);
      setSettings((current) => normalizedSettings({
        ...current,
        gameDirectory: current.gameDirectory.includes(result.projectId)
          ? current.gameDirectory
          : `${current.gameDirectory || './.neverlauncher/projects'}/${result.projectId}/${result.profileId}`,
        projectId: result.projectId, profileId: result.profileId, channel: result.channel || current.channel,
        memoryMb: current.memoryMb >= minMemory && current.memoryMb <= maxMemory
          ? current.memoryMb
          : Math.min(maxMemory, Math.max(minMemory, policy?.recommendedMb || 4096)),
        offlineEnabled: false,
      }));
    } catch (error) {
      setStage('failed');
      log(`Манифест не загружен: ${String(error)}.`);
    }
  }

  async function validateSettings() {
    try {
      const result = await callTauri<SettingsCheck>('validate_desktop_settings', {
        gameDirectory: settings.gameDirectory,
        javaPath: settings.javaPath || null,
        memoryMb: settings.memoryMb,
      });
      setSettingsCheck(result);
      log(result.messages.join(' '));
    } catch (error) {
      log(`Настройки не проверены: ${String(error)}`);
    }
  }

  async function checkJavaRuntime() {
    setStage('java');
    try {
      const activeManifest = manifest;
      const required = activeManifest?.runtime.java.majorVersion || 17;
      const distribution = activeManifest?.runtime.java.distribution || 'temurin';
      let result = await callTauri<JavaInfoResult>('check_java', {
        javaPath: settings.javaPath || null,
        requiredMajorVersion: required,
      });
      if (!result.compatible && !settings.javaPath && distribution.toLowerCase() !== 'system') {
        if (!activeManifest || !settings.pinnedPublicKey) throw new Error('Отсутствует проверенный подписанный профиль для установки Java');
        const managed = await callTauri<ManagedJavaResult>('ensure_profile_managed_java', {
          manifest: activeManifest,
          pinnedPublicKey: settings.pinnedPublicKey,
        });
        log(managed.message);
        result = await callTauri<JavaInfoResult>('check_java', {
          javaPath: managed.javaExecutable,
          requiredMajorVersion: required,
        });
      }
      setJavaInfo(result);
      log(result.message);
      await refreshLaunchHistory();
    } catch (error) {
      setJavaInfo(null);
      setStage('failed');
      log(`Java не проверена: ${String(error)}`);
    }
  }

  async function verifyFiles() {
    if (!manifest) {
      log('Сначала загрузите манифест профиля.');
      return;
    }
    setStage('files');
    try {
      const result = await callTauri<FileCheckResult[]>('check_files', { manifest, root: settings.gameDirectory,preset: settings.componentPreset||null });
      setFiles(result);
      const broken = result.filter((file) => file.status !== 'ok').length;
      log(broken === 0 ? 'Файлы клиента проверены.' : `Нужно исправить файлов: ${broken}.`);
    } catch (error) {
      setStage('failed');
      log(`Проверка файлов не выполнена: ${String(error)}`);
    }
  }

  async function controlTransfer(action: 'pause' | 'cancel') {
    try {
      await callTauri('control_download_job', { root: settings.gameDirectory, action });
      log(action === 'pause' ? 'Запрошена пауза загрузки.' : 'Загрузка отменена.');
      if (action === 'cancel') setPendingJob(null);
    } catch (error) { log(`Управление загрузкой: ${String(error)}`); }
  }

  async function resumeTransfer() {
    if (transferBusy || !pendingJob) return;
    setTransferBusy(true);
    try {
      const result = await callTauri<DownloadResult>('resume_download_job', { root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey });
      setDownload(result);
      if (manifest) setFiles(await callTauri<FileCheckResult[]>('check_files', { manifest, root: settings.gameDirectory,preset: settings.componentPreset||null }).catch(() => files));
      log(`Возобновление: скачано ${result.downloaded}, ошибок ${result.failed}.`);
      setPendingJob(await callTauri<PendingDownload | null>('pending_download_job', { root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey }));
    } catch (error) { log(`Не удалось возобновить: ${String(error)}`); }
    finally { setTransferBusy(false); }
  }

  async function downloadFiles() {
    if (!manifest || transferBusy) return;
    setStage('files');
    setTransferBusy(true);
    setDownloadProgress(null);
    try {
      const result = await callTauri<DownloadResult>('download_missing_files', {
        manifest, root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey, preset:settings.componentPreset||null,
      });
      setDownload(result);
      setFiles(await callTauri<FileCheckResult[]>('check_files', { manifest, root: settings.gameDirectory,preset: settings.componentPreset||null }));
      log(`Загрузка: ${result.downloaded} файлов, ошибок ${result.failed}, передано ${result.bytesDownloaded || 0} байт.`);
    } catch (error) {
      setStage('failed');
      log(`Загрузка не выполнена: ${String(error)}`);
    } finally {
      setTransferBusy(false);
      void callTauri<PendingDownload | null>('pending_download_job', { root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey }).then(setPendingJob).catch(() => {});
    }
  }

  async function repairClient() {
    if (!manifest || transferBusy) {
      if (!manifest) log('Восстановление невозможно без манифеста профиля.');
      return;
    }
    setStage('repair');
    setTransferBusy(true);
    setDownloadProgress(null);
    try {
      const result = await callTauri<RepairResult>('repair_client', { manifest, root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey,preset:settings.componentPreset||null });
      setRepairResult(result);
      setDownload(result.download);
      setFiles(result.after);
      log(`${result.message}: восстановлено ${result.repaired}, скачано ${result.download.downloaded}, ошибок ${result.download.failed}.`);
    } catch (error) {
      setStage('failed');
      log(`Восстановление завершилось ошибкой: ${String(error)}`);
    } finally {
      setTransferBusy(false);
      void callTauri<PendingDownload | null>('pending_download_job', { root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey }).then(setPendingJob).catch(() => {});
    }
  }

  async function rollbackClientRelease() {
    if (transferBusy) return;
    setTransferBusy(true);
    try {
      await callTauri<void>('rollback_client_release', { root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey });
      setFiles(manifest ? await callTauri<FileCheckResult[]>('check_files', { manifest, root: settings.gameDirectory,preset: settings.componentPreset||null }) : []);
      setDownload(null);
      log('Восстановлен последний исправный игровой релиз. Для запуска загрузите его подписанный manifest.');
    } catch (error) { log(`Откат игрового релиза не выполнен: ${String(error)}`); }
    finally { setTransferBusy(false); }
  }

  async function cleanUnusedFiles() {
    if (!manifest) {
      log('Очистка невозможна без манифеста профиля.');
      return;
    }
    setStage('cleanup');
    try {
      const result = await callTauri<CleanUnusedResult>('clean_unused_files', { manifest, root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey });
      setCleanResult(result);
      log(`Очистка завершена: перемещено ${result.moved}, сохранено ${result.preserved}. Карантин: ${result.quarantineDir}.`);
    } catch (error) {
      setStage('failed');
      log(`Очистка завершилась ошибкой: ${String(error)}`);
    }
  }

  async function refreshLaunchHistory() {
    try {
      const result = await callTauri<LaunchHistoryEntry[]>('load_launch_history', { root: settings.gameDirectory });
      setLaunchHistory(result);
      log(`История запусков загружена: ${result.length}.`);
    } catch (error) {
      log(`История запусков не загружена: ${String(error)}`);
    }
  }

  async function buildPlan() {
    if (!manifest) {
      log('План запуска невозможен без манифеста профиля.');
      return;
    }
    try {
      const result = await callTauri<LaunchPlan>('build_launch_plan', {
        manifest,
        root: settings.gameDirectory,
        javaPath: settings.javaPath || null,
        username: settings.username,
        pinnedPublicKey: settings.pinnedPublicKey,
        preferences: currentLaunchPreferences(),
      });
      setLaunchPlan(result);
      setStage('ready');
      log('План запуска собран.');
    } catch (error) {
      setStage('failed');
      log(`План запуска не собран: ${String(error)}`);
    }
  }

  async function createGuardLaunchTicket(): Promise<string> {
    if (!authSession?.accessToken) throw new Error('Guard Attestation требует активную Never session.');
    const userId = authSession.userId || accessTokenSubject(authSession.accessToken);
    const deviceId = accessTokenDeviceId(authSession.accessToken);
    if (!userId || !deviceId) throw new Error('Guard Attestation требует session, привязанную к trusted device.');
    const key = deviceKey ?? await callTauri<DeviceKeyInfo | null>('device_key_status', { backendUrl: settings.backendUrl, userId });
    if (!key?.deviceId || key.deviceId !== deviceId || key.keyBinding !== 'hardware' || key.keyAlgorithm !== 'p256' || !key.hardwareBound) {
      throw new Error('Guard Attestation требует локальный hardware-bound P-256 device key текущего trusted device.');
    }

    const beginResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(deviceId)}/guard-attest/begin`, authSession.accessToken, {
      launcherVersion: DESKTOP_VERSION,
    });
    const beginPayload = await beginResponse.json().catch(() => null);
    if (!beginResponse.ok) throw new Error(beginPayload?.error?.message || `Guard Attestation begin: ${beginResponse.status} ${beginResponse.statusText}`);
    const begin = beginPayload?.data ?? beginPayload;
    if (!begin?.challengeId || !begin?.challenge || !begin?.expiresAt || begin.launcherVersion !== DESKTOP_VERSION) {
      throw new Error('Backend вернул неполный или несовместимый Guard Attestation challenge.');
    }

    const submission = await callTauri<GuardAttestationSubmission>('neverguard_guard_attestation', {
      request: {
        backendUrl: settings.backendUrl,
        userId,
        deviceId,
        sessionId: authSession.sessionId,
        bindingEpoch: accessTokenBindingEpoch(authSession.accessToken),
        launcherVersion: DESKTOP_VERSION,
        challengeId: begin.challengeId,
        challenge: begin.challenge,
        challengeExpiresAt: begin.expiresAt,
      },
    });
    if (submission.launcherVersion !== DESKTOP_VERSION || submission.fingerprint !== key.fingerprint || submission.keyAlgorithm !== 'p256' || submission.keyBinding !== 'hardware' || !submission.hardwareBound) {
      throw new Error('Native Guard Attestation signer вернул неожиданную release/device identity.');
    }

    const completeResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(deviceId)}/guard-attest/complete`, authSession.accessToken, {
      challengeId: begin.challengeId,
      challenge: begin.challenge,
      challengeExpiresAt: begin.expiresAt,
      launcherVersion: DESKTOP_VERSION,
      attestation: submission.attestation,
      signature: submission.signature,
    });
    const completePayload = await completeResponse.json().catch(() => null);
    if (!completeResponse.ok) throw new Error(completePayload?.error?.message || `Guard Attestation complete: ${completeResponse.status} ${completeResponse.statusText}`);
    const data = completePayload?.data ?? completePayload;
    if (!data?.verified || !data?.launchTicket || !data?.oneTime) throw new Error('Backend не выдал одноразовый Guard launch ticket.');
    log(`NeverGuard attestation подтверждена Backend: evidence=${String(data.evidenceSha256 || '').slice(0, 16)}…, ticket до ${data.expiresAt}.`);
    return data.launchTicket;
  }

  async function createContinuousGuardTicket(processId: string): Promise<string> {
    if (!authSession?.accessToken) throw new Error('Guard Attestation v2 требует активную Never session.');
    const userId = authSession.userId || accessTokenSubject(authSession.accessToken);
    const deviceId = accessTokenDeviceId(authSession.accessToken);
    if (!userId || !deviceId) throw new Error('Guard Attestation v2 требует trusted-device binding.');
    const key = deviceKey ?? await callTauri<DeviceKeyInfo | null>('device_key_status', { backendUrl: settings.backendUrl, userId });
    if (!key?.deviceId || key.deviceId !== deviceId || key.keyBinding !== 'hardware' || key.keyAlgorithm !== 'p256' || !key.hardwareBound) {
      throw new Error('Guard Attestation v2 требует hardware-bound P-256 device key текущего trusted device.');
    }
    const beginResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(deviceId)}/guard-attest-v2/begin`, authSession.accessToken, {
      launcherVersion: DESKTOP_VERSION,
    });
    const beginPayload = await beginResponse.json().catch(() => null);
    if (!beginResponse.ok) throw new Error(beginPayload?.error?.message || `Guard Attestation v2 begin: ${beginResponse.status} ${beginResponse.statusText}`);
    const begin = beginPayload?.data ?? beginPayload;
    if (!begin?.challengeId || !begin?.challenge || !begin?.expiresAt || begin.attestationSchema !== 'neverguard/windows-guard-attestation/v2') {
      throw new Error('Backend вернул неполный или несовместимый Guard Attestation v2 challenge.');
    }
    const submission = await callTauri<GuardAttestationSubmission>('neverguard_guard_attestation_v2', {
      request: {
        backendUrl: settings.backendUrl,
        userId,
        deviceId,
        sessionId: authSession.sessionId,
        bindingEpoch: accessTokenBindingEpoch(authSession.accessToken),
        launcherVersion: DESKTOP_VERSION,
        challengeId: begin.challengeId,
        challenge: begin.challenge,
        challengeExpiresAt: begin.expiresAt,
        processId,
      },
    });
    if (submission.launcherVersion !== DESKTOP_VERSION || submission.fingerprint !== key.fingerprint || submission.keyAlgorithm !== 'p256' || submission.keyBinding !== 'hardware' || !submission.hardwareBound) {
      throw new Error('Native Guard Attestation v2 signer вернул неожиданную release/device identity.');
    }
    const completeResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(deviceId)}/guard-attest-v2/complete`, authSession.accessToken, {
      challengeId: begin.challengeId,
      challenge: begin.challenge,
      challengeExpiresAt: begin.expiresAt,
      launcherVersion: DESKTOP_VERSION,
      attestation: submission.attestation,
      signature: submission.signature,
    });
    const completePayload = await completeResponse.json().catch(() => null);
    if (!completeResponse.ok) throw new Error(completePayload?.error?.message || `Guard Attestation v2 complete: ${completeResponse.status} ${completeResponse.statusText}`);
    const data = completePayload?.data ?? completePayload;
    if (!data?.verified || data.attestationVersion !== 2 || !data?.continuousGuardTicket || !data?.oneTime) {
      throw new Error('Backend не подтвердил Continuous Guard Attestation v2.');
    }
    log(`Continuous Guard Attestation v2 подтверждена: evidence=${String(data.continuousEvidenceSha256 || '').slice(0, 16)}…, cross-checks=${data.crossCheckCount ?? 0}.`);
    return data.continuousGuardTicket;
  }

  async function createMinecraftLaunchSession(guardAttestationTicket: string): Promise<MinecraftLaunchCredentials> {
    if (!authSession?.accessToken) throw new Error('Для запуска Minecraft требуется активная Never session.');
    const response = await fetch(endpoint('/api/v1/minecraft/session'), {
      method: 'POST',
      headers: { Authorization: `Bearer ${authSession.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientToken: `desktop-${authSession.sessionId}`, guardAttestationTicket }),
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) throw new Error(payload?.error?.message || `Не удалось получить Minecraft session: ${response.status} ${response.statusText}`);
    const data = payload?.data ?? payload;
    if (!data.accessToken || !data.profile?.id || !data.profile?.name) throw new Error('Backend вернул неполную Minecraft session.');
    return { username: data.profile.name, uuid: data.profile.id, accessToken: data.accessToken, userType: 'mojang', authServerBaseUrl: settings.backendUrl.trim().replace(/\/$/, '') };
  }

  async function createServerJoinAfterLaunch(username: string, minecraftAccessToken: string, continuousGuardTicket?: string) {
    if (!authSession?.accessToken || !settings.serverId) return;
    if (!profileServers.some((server) => server.id === settings.serverId)) throw new Error('serverId отсутствует в серверном списке профиля');
    const response = await fetch(endpoint('/api/v1/session/join'), {
      method: 'POST',
      headers: { Authorization: `Bearer ${authSession.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, serverId: settings.serverId, projectId: settings.projectId, profileId: settings.profileId, channel: settings.channel, minecraftAccessToken, continuousGuardTicket }),
    });
    if (!response.ok) throw new Error(`Не удалось создать сессию входа ServerBridge: ${response.status} ${response.statusText}`);
    const payload = await response.json();
    log(`Сессия входа ServerBridge создана: ${JSON.stringify(payload.data ?? payload)}`);
  }

  async function launch() {
    if (!manifest) {
      log('Запуск невозможен без manifest профиля.');
      return;
    }
    setStage('launching');
    try {
      const preferences = currentLaunchPreferences();
      // Only cached signed Manifest v2 may be used when the backend is offline.
      // Never manufacture Minecraft access tokens for offline launches.
      let minecraftCredentials: MinecraftLaunchCredentials | undefined;
      if (!preferences.offline) {
        const guardAttestationTicket = await createGuardLaunchTicket();
        minecraftCredentials = await createMinecraftLaunchSession(guardAttestationTicket);
      }
      // Auto-enter needs its one-time ServerBridge ticket *before* Java receives
      // --server/--quickPlayMultiplayer, otherwise Minecraft can connect before
      // our post-launch join call. Policies requiring runtime attestation will
      // reject pre-join, in which case we fail closed instead of racing a join.
      if (preferences.autoEnter && minecraftCredentials) {
        await createServerJoinAfterLaunch(minecraftCredentials.username, minecraftCredentials.accessToken);
      }
      const result = await callTauri<ProcessStatus>('launch_minecraft', {
        request: {
          manifest,
          root: settings.gameDirectory,
          javaPath: settings.javaPath || null,
          username: minecraftCredentials?.username || settings.username,
          minecraftCredentials: minecraftCredentials || null,
          pinnedPublicKey: settings.pinnedPublicKey,
          preferences,
          componentPreset:settings.componentPreset||null,
        },
      });
      let continuousGuardTicket: string | undefined;
      if (!preferences.offline && result.windowsSensor) {
        try {
          continuousGuardTicket = await createContinuousGuardTicket(result.id);
        } catch (attestationError) {
          await callTauri<ProcessStatus>('stop_runtime_process', { processId: result.id }).catch(() => undefined);
          throw new Error(`Windows runtime остановлен: Continuous Guard Attestation v2 не подтверждена: ${String(attestationError)}`);
        }
      }
      try {
        if (!preferences.offline && !preferences.autoEnter && minecraftCredentials) {
          await createServerJoinAfterLaunch(minecraftCredentials.username, minecraftCredentials.accessToken, continuousGuardTicket);
        }
      } catch (joinError) {
        await callTauri<ProcessStatus>('stop_runtime_process', { processId: result.id }).catch(() => undefined);
        throw new Error(`Runtime остановлен: ServerBridge join после Attestation v2 не подтверждён: ${String(joinError)}`);
      }
      setLaunchResult(result);
      setStage('running');
      log(`${result.message}: PID ${result.pid ?? 'unknown'}, process ${result.id}.`);
    } catch (error) {
      setStage('failed');
      log(`Запуск не выполнен: ${String(error)}`);
    }
  }

  async function stopRuntimeProcess() {
    if (!launchResult?.id || !['running', 'stopping'].includes(launchResult.state)) return;
    try {
      const result = await callTauri<ProcessStatus>('stop_runtime_process', { processId: launchResult.id });
      setLaunchResult(result);
      log(result.message);
    } catch (error) { log(`Runtime process не остановлен: ${String(error)}`); }
  }

  async function exportDiagnostics() {
    try {
      const result = await callTauri<DiagnosticsExport>('export_diagnostics_bundle', {
        root: settings.gameDirectory,
        launcherVersion: DESKTOP_VERSION,
        backendUrl: settings.backendUrl,
        stage,
        logs,
      });
      log(result.message);
      await refreshLaunchHistory();
    } catch (error) {
      log(`Диагностика не экспортирована: ${String(error)}`);
    }
  }

  async function openGameDirectory() {
    try {
      await callTauri<string>('open_game_directory', { root: settings.gameDirectory });
      log('Каталог клиента открыт.');
    } catch (error) {
      log(`Каталог клиента не открыт: ${String(error)}`);
    }
  }

  async function runFullCheck() {
    await checkBackend();
    await persistDesktopConfig();
    await restoreSession();
    const projectId = await loadProjects();
    const profileId = await loadProfiles(projectId);
    await loadManifest(projectId, profileId);
    await validateSettings();
    await checkJavaRuntime();
    await verifyFiles();
    await buildPlan();
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">NeverLauncher</div>
        <div className="version">{DESKTOP_VERSION} · Рабочий Desktop Launcher</div>
        <nav>
          {[
            ['firstRun', 'Первый запуск'], ['overview', 'Обзор'], ['auth', 'Вход'], ['projects', 'Проекты'], ['profile', 'Профиль'],
            ['download', 'Загрузка'], ['settings', 'Настройки'], ['extensions', 'Расширения'], ['logs', 'Логи'], ['diagnostics', 'Диагностика'],
          ].map(([id, title]) => <button key={id} className={screen === id ? 'active' : ''} onClick={() => setScreen(id as Screen)}>{title}</button>)}
        </nav>
      </aside>

      <section className="content">
        <header className="hero">
          <div>
            <p className="eyebrow">Рабочий Desktop Launcher</p>
            <h1>Движок запуска и восстановление клиента</h1>
            <p>Desktop {DESKTOP_VERSION} выполняет реальную проверку файлов, восстановление повреждённых объектов, безопасную очистку, сборку плана запуска, запуск Minecraft, запись логов и историю запусков.</p>
          </div>
          <div className="statusPill">{stageLabels[stage]}</div>
        </header>

        <section className="toolbar">
          <button onClick={runFullCheck}>Полная проверка</button>
          <button onClick={persistDesktopConfig}>Сохранить привязку</button>
          <button onClick={repairClient}>Восстановить</button>
          <button disabled={transferBusy} onClick={rollbackClientRelease}>Откатить игровой релиз</button>
          <button onClick={cleanUnusedFiles}>Очистить лишнее</button>
          <button onClick={buildPlan}>Собрать план запуска</button>
          <button className="primary" disabled={transferBusy} onClick={launch}>Играть</button>
          <button onClick={exportDiagnostics}>Экспорт диагностики</button>
        </section>

        <section className="settings compact">
          <label>URL Backend<input value={settings.backendUrl} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('backendUrl', event.target.value)} /></label>
          <label>Переопределение URL манифеста<input value={settings.manifestUrl} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('manifestUrl', event.target.value)} placeholder="обычно пусто: используется /api/v1/projects/{project}/profiles/{profile}/manifest?channel=stable" /></label>
          <label>Каталог игры<input value={settings.gameDirectory} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('gameDirectory', event.target.value)} /></label>
          <label>Имя игрока<input value={settings.username} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('username', event.target.value)} /></label>
          <label>Память, МБ<input type="number" value={settings.memoryMb} min={Math.max(512, manifest?.runtime.memory?.minimumMb || 0)} max={Math.min(32768, manifest?.runtime.memory?.maximumMb || 32768)} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('memoryMb', Number(event.target.value))} /></label>
          <label>Канал<input value={settings.channel} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('channel', event.target.value)} /></label>
        </section>

        {screen === 'firstRun' && <FirstRunPanel settings={settings} patchSettings={patchSettings} bindingPolicy={bindingPolicy} checkBackend={checkBackend} loadProjects={loadProjects} loadProfiles={loadProfiles} persistDesktopConfig={persistDesktopConfig} resetDesktopBinding={resetDesktopBinding} selectedProject={selectedProject} selectedProfile={selectedProfile} /> }
        {screen === 'overview' && <Overview readiness={readiness} backendStatus={backendStatus} manifest={manifest} javaInfo={javaInfo} fileSummary={fileSummary} launchPlan={launchPlan} readinessContract={readinessContract} diagnosticsPolicy={diagnosticsPolicy} />}
        {screen === 'auth' && <AuthPanel email={email} setEmail={setEmail} password={password} setPassword={setPassword} session={authSession} deviceKey={deviceKey} deviceTrustStatus={deviceTrustStatus} managedDevices={managedDevices} checkBackend={checkBackend} loginDesktop={loginDesktop} refreshDesktopSession={refreshDesktopSession} logoutDesktop={logoutDesktop} restoreSession={restoreSession} refreshDeviceKeyStatus={refreshDeviceKeyStatus} loadManagedDevices={loadManagedDevices} renameManagedDevice={renameManagedDevice} revokeManagedDevice={revokeManagedDevice} revokeOtherManagedDevices={revokeOtherManagedDevices} replaceDesktopDeviceKey={replaceDesktopDeviceKey} />}
        {screen === 'projects' && <ProjectPanel projects={projects} selectedProject={selectedProject} setSelectedProject={selectProject} loadProjects={loadProjects} loadProfiles={loadProfiles} />}
        {screen === 'profile' && <ProfilePanel profiles={profiles} selectedProfile={selectedProfile} setSelectedProfile={selectProfile} loadManifest={loadManifest} manifest={manifest} componentPreset={settings.componentPreset||""} pinnedPublicKey={settings.pinnedPublicKey} setComponentPreset={(x:string)=>patchSettings("componentPreset",x)} />}
        {screen === 'download' && <DownloadPanel files={files} download={download} downloadProgress={downloadProgress} transferBusy={transferBusy} pendingJob={pendingJob} controlTransfer={controlTransfer} resumeTransfer={resumeTransfer} repairResult={repairResult} cleanResult={cleanResult} verifyFiles={verifyFiles} downloadFiles={downloadFiles} repairClient={repairClient} rollbackClientRelease={rollbackClientRelease} cleanUnusedFiles={cleanUnusedFiles} fileSummary={fileSummary} />}
        {screen === 'settings' && <SettingsPanel settings={settings} patchSettings={patchSettings} validateSettings={validateSettings} settingsCheck={settingsCheck} checkJavaRuntime={checkJavaRuntime} javaInfo={javaInfo} openGameDirectory={openGameDirectory} manifest={manifest} profileServers={profileServers} loadProfileServers={loadProfileServers} loadCachedOfflineManifest={loadCachedOfflineManifest} cacheSignedManifest={cacheSignedManifest} />}
        {screen === 'extensions' && <DesktopExtensions0209 backendUrl={settings.backendUrl} token={authSession?.accessToken ?? ''} projectId={selectedProject || settings.projectId} gameDirectory={settings.gameDirectory} log={log} />}
        {screen === 'logs' && <LogsPanel logs={logs} launchPlan={launchPlan} launchResult={launchResult} launchHistory={launchHistory} refreshLaunchHistory={refreshLaunchHistory} stopRuntimeProcess={stopRuntimeProcess} />}
        {screen === 'diagnostics' && <DiagnosticsPanel exportDiagnostics={exportDiagnostics} readinessContract={readinessContract} diagnosticsPolicy={diagnosticsPolicy} settingsCheck={settingsCheck} />}
      </section>
    </main>
  );
}


function FirstRunPanel({ settings, patchSettings, bindingPolicy, checkBackend, loadProjects, loadProfiles, persistDesktopConfig, resetDesktopBinding, selectedProject, selectedProfile }: any) {
  return <section className="panel"><h3>Первый запуск</h3><p>NeverLauncher {DESKTOP_VERSION} требует явной привязки Desktop к Backend API и реальному проекту; запуск проходит через рабочий движок запуска и режим восстановления.</p><div className="settings"><label>URL Backend<input value={settings.backendUrl} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('backendUrl', event.target.value)} placeholder="https://launcher.example.ru" /></label><label>ID проекта<input value={settings.projectId} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('projectId', event.target.value)} placeholder="выберите из Backend API" /></label><label>ID профиля<input value={settings.profileId} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('profileId', event.target.value)} placeholder="выберите из Backend API" /></label><label>ID ServerBridge<input value={settings.serverId ?? ''} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('serverId', event.target.value)} placeholder="velocity-main / purpur-main" /></label><label>Канал<input value={settings.channel} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('channel', event.target.value)} /></label></div><div className="toolbar inline"><button onClick={checkBackend}>1. Проверить Backend</button><button onClick={loadProjects}>2. Загрузить проекты</button><button onClick={() => loadProfiles(selectedProject || settings.projectId)}>3. Загрузить профили</button><button className="primary" onClick={persistDesktopConfig}>4. Сохранить привязку</button><button onClick={resetDesktopBinding}>Сбросить</button></div><pre>{JSON.stringify({ configPath: settings.configPath || 'будет создан Tauri-командой', selectedProject, selectedProfile, bindingPolicy }, null, 2)}</pre></section>;
}

function Overview({ readiness, backendStatus, manifest, javaInfo, fileSummary, launchPlan, readinessContract, diagnosticsPolicy }: any) {
  return (
    <>
      <section className="grid">
        <article className="card"><h3>Backend</h3><strong>{backendStatus}</strong><p>Проверки health/readiness и готовность Desktop.</p></article>
        <article className="card"><h3>Манифест</h3><strong>{manifest ? manifest.version : 'не загружен'}</strong><p>{manifest ? `${manifest.projectId}/${manifest.profileId} · ${manifest.minecraft.loader} ${manifest.minecraft.version}` : 'Загрузите профиль клиента.'}</p></article>
        <article className="card"><h3>Java</h3><strong>{javaInfo?.compatible ? 'OK' : 'не проверена'}</strong><p>{javaInfo?.message ?? 'Проверка Java не выполнялась.'}</p></article>
        <article className="card"><h3>Файлы</h3><strong>{fileSummary.ok}/{fileSummary.total}</strong><p>Повреждено или отсутствует: {fileSummary.broken}.</p></article>
        <article className="card"><h3>План запуска</h3><strong>{launchPlan ? 'готов' : 'нет'}</strong><p>Classpath, аргументы JVM и игры.</p></article>
        <article className="card"><h3>Контракт</h3><strong>{readinessContract?.status ?? 'не загружен'}</strong><p>Модель готовности Desktop из Backend API.</p></article>
        <article className="card"><h3>Диагностика</h3><strong>{diagnosticsPolicy?.status ?? 'не загружена'}</strong><p>{diagnosticsPolicy?.privacyMode ?? 'приватность по умолчанию'}.</p></article>
      </section>
      <section className="panel">
        <div className="progressHeader"><span>Готовность запуска</span><span>{readiness}%</span></div>
        <div className="bar"><div style={{ width: `${readiness}%` }} /></div>
        <pre>{launchPlan?.commandPreview ?? 'План запуска ещё не собран.'}</pre>{launchPlan?.deterministicSha256 && <small>Resolved plan SHA-256: <code>{launchPlan.deterministicSha256}</code></small>}
      </section>
    </>
  );
}

function AuthPanel({ email, setEmail, password, setPassword, session, deviceKey, deviceTrustStatus, managedDevices, checkBackend, loginDesktop, refreshDesktopSession, logoutDesktop, restoreSession, refreshDeviceKeyStatus, loadManagedDevices, renameManagedDevice, revokeManagedDevice, revokeOtherManagedDevices, replaceDesktopDeviceKey }: any) {
  return <section className="panel"><h3>Вход, сессия и Device Management</h3><p>NeverLauncher {DESKTOP_VERSION} регистрирует отдельную device identity, подтверждает владение ключом и для hardware P-256 выполняет challenge-response attestation. В этой версии revoke необратим для старого ключа: Backend отзывает связанные Never/refresh/Minecraft-сессии, инвалидирует незавершённые device challenges и ServerBridge joins. Повторное подключение отозванной установки требует нового device key.</p><div className="settings"><label>Электронная почта<input value={email} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setEmail(event.target.value)} /></label><label>Пароль<input type="password" value={password} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setPassword(event.target.value)} /></label></div><div className="toolbar inline"><button onClick={checkBackend}>Проверить Backend</button><button onClick={() => loginDesktop().catch((error: Error) => console.error(error))}>Войти</button><button onClick={() => refreshDesktopSession().catch((error: Error) => console.error(error))}>Обновить сессию</button><button onClick={() => logoutDesktop().catch((error: Error) => console.error(error))}>Выйти</button><button onClick={restoreSession}>Проверить восстановление сессии</button><button onClick={() => refreshDeviceKeyStatus().catch((error: Error) => console.error(error))}>Проверить device key</button>{session && <button onClick={() => loadManagedDevices().catch((error: Error) => console.error(error))}>Обновить устройства</button>}{session && deviceKey?.deviceId && <button onClick={() => replaceDesktopDeviceKey('rotate').catch((error: Error) => console.error(error))}>Ротировать ключ</button>}{session && <button onClick={() => replaceDesktopDeviceKey('recover').catch((error: Error) => console.error(error))}>Восстановить ключ</button>}{session && <button className="danger" onClick={() => revokeOtherManagedDevices().catch((error: Error) => console.error(error))}>Отозвать остальные</button>}</div><pre>{JSON.stringify({ session: session ? { email: session.email, userId: session.userId, sessionId: session.sessionId, status: 'активна', refreshToken: 'скрыт' } : null, deviceTrust: deviceTrustStatus, deviceKey: deviceKey ? { deviceId: deviceKey.deviceId ?? null, fingerprint: deviceKey.fingerprint, algorithm: deviceKey.keyAlgorithm, keyBinding: deviceKey.keyBinding, hardwareProvider: deviceKey.hardwareProvider || null, hardwareBound: deviceKey.hardwareBound, storageBackend: deviceKey.storageBackend, privateKeyExposedToFrontend: deviceKey.privateKeyExposedToFrontend } : null }, null, 2)}</pre>{session && <div className="deviceList">{managedDevices.map((device: ManagedDevice) => <article className={`deviceCard ${device.current ? 'currentDevice' : ''}`} key={device.id}><div><strong>{device.name}{device.current ? ' · текущее' : ''}</strong><span>{device.status} · {device.keyAlgorithm}/{device.keyBinding}{device.hardwareProvider ? ` · ${device.hardwareProvider}` : ''}</span><small>{device.platform || 'platform n/a'} · {device.clientVersion || 'version n/a'} · last seen: {device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : '—'}</small><small>fingerprint: {device.keyFingerprint.slice(0, 20)}… · attestation: {device.attestationState || 'unattested'}</small>{device.status === 'revoked' && <small>revoked: {device.revokedAt ? new Date(device.revokedAt).toLocaleString() : '—'} · {device.revokedReason || 'reason n/a'}{device.replacedByDeviceId ? ` · replaced by ${device.replacedByDeviceId}` : ''}</small>}</div>{device.status === 'active' && <div className="deviceActions"><button onClick={() => renameManagedDevice(device).catch((error: Error) => console.error(error))}>Переименовать</button><button className="danger" onClick={() => revokeManagedDevice(device).catch((error: Error) => console.error(error))}>{device.current ? 'Отозвать текущее' : 'Отозвать'}</button></div>}</article>)}</div>}</section>;
}

function ActionPanel({ title, description, actions }: { title: string; description: string; actions: [string, () => void | Promise<void>][] }) {
  return <section className="panel"><h3>{title}</h3><p>{description}</p><div className="toolbar inline">{actions.map(([label, action]) => <button key={label} onClick={action}>{label}</button>)}</div></section>;
}

function ProjectPanel({ projects, selectedProject, setSelectedProject, loadProjects, loadProfiles }: any) {
  return <section className="panel"><h3>Проекты</h3><p>Список проектов загружается из Backend API.</p><div className="toolbar inline"><button onClick={loadProjects}>Загрузить проекты</button><button onClick={() => loadProfiles(selectedProject)}>Загрузить профили</button></div><div className="list">{projects.map((project: BackendProject) => <button key={project.id} className={selectedProject === project.id ? 'row activeRow' : 'row'} onClick={() => setSelectedProject(project.id)}><strong>{project.title ?? project.name ?? project.id}</strong><span>{project.id}</span></button>)}</div></section>;
}

function ProfilePanel({profiles,selectedProfile,setSelectedProfile,loadManifest,manifest,componentPreset,pinnedPublicKey,setComponentPreset}:any){
  const cat:ComponentCatalog|undefined=manifest?.componentCatalog;
  const [nativePreview,setNativePreview]=useState<{selected:string[];unavailable:{id:string;reason:string}[];effectiveFiles:string[];error?:string}|null>(null);
  useEffect(()=>{
    let cancelled=false;
    if(!cat||!['4.0','5.0'].includes(cat.schemaVersion)){setNativePreview(null);return;}
    setNativePreview(null);
    callTauri<{selected:string[];unavailable:{id:string;reason:string}[];effectiveFiles:string[]}>('preview_components_0244',{
      manifest,pinnedPublicKey,componentPreset:componentPreset||null
    }).then(result=>{if(!cancelled)setNativePreview(result);}).catch(error=>{
      if(!cancelled)setNativePreview({selected:[],unavailable:[],effectiveFiles:[],error:String(error)});
    });
    return ()=>{cancelled=true;};
  },[manifest,componentPreset,cat?.digest,pinnedPublicKey]);
  const nativeConditional=cat&&['4.0','5.0'].includes(cat.schemaVersion);
  const plan=cat&&!nativeConditional?componentPresetPlan0243(cat,componentPreset):null;
  const selected=nativeConditional?new Set(nativePreview?.selected||[]):plan?.selected||new Set<string>();
  const files=nativeConditional?nativePreview?.effectiveFiles||[]:cat?.components.filter(c=>selected.has(c.id)).flatMap(c=>c.files)||[];
  const bytes=manifest?.files.filter((f:ManifestFile)=>files.includes(f.path)).reduce((sum:number,f:ManifestFile)=>sum+f.size,0)||0;
  return <section className="panel"><h3>Профиль и компоненты</h3><div className="toolbar inline"><button onClick={loadManifest}>Загрузить манифест</button></div>
    <div className="list">{profiles.map((profile:BackendProfile)=><button key={profile.id} className={selectedProfile===profile.id?'row activeRow':'row'} onClick={()=>setSelectedProfile(profile.id)}><strong>{profile.title??profile.name??profile.id}</strong><span>{profile.loader??'vanilla'}</span></button>)}</div>
    {cat&&<article className="card"><h3>Подписанные компоненты (rev {cat.revision})</h3>
      {(cat.schemaVersion==='2.0'||cat.schemaVersion==='3.0'||cat.schemaVersion==='4.0'||cat.schemaVersion==='5.0')&&<label>Пресет<select value={componentPreset} onChange={(e)=>setComponentPreset(e.target.value)}><option value="">По умолчанию{cat.defaultPreset?` (${cat.defaultPreset})`:''}</option>{cat.presets?.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label>}
      {(plan?.error||nativePreview?.error)&&<p role="alert" className="error">Недопустимая конфигурация: {plan?.error||nativePreview?.error}. Установка и запуск будут заблокированы native resolver.</p>}
      <p>Выбрано {selected.size} компонентов; объём данных каталога {Math.round(bytes/1024)} КиБ. При изменении пресета используйте «Скачать/Обновить» для транзакционной установки. Required включаются всегда.</p>
      {nativeConditional&&!nativePreview&&<p>Проверка платформы и подписанных условий в NeverRuntime…</p>}
      {cat.components.filter(c=>c.visible!==false||selected.has(c.id)).map(c=><div key={c.id} className="row"><strong>{selected.has(c.id)?'✓ ':''}{c.name}</strong><span>{[c.required?'обязательный':null,c.default?'по умолчанию':null,c.limited?'ограниченный':null,c.description||null,plan?.reasons.get(c.id)||null,nativePreview?.unavailable.find(x=>x.id===c.id)?.reason||null,componentTopologyLabel(cat,c)||null,(c.actions?.length?`Действия: ${c.actions.map(a=>a.type+(a.path?` (${a.path})`:'')).join(', ')}`:null)].filter(Boolean).join(' · ')}</span></div>)}
    </article>}
    <pre>{manifest?JSON.stringify({projectId:manifest.projectId,profileId:manifest.profileId,version:manifest.version,files:manifest.files.length,catalogDigest:cat?.digest},null,2):'Манифест не загружен.'}</pre>
  </section>;
}

function DownloadPanel({ files, download, downloadProgress, transferBusy, repairResult, cleanResult,
  verifyFiles, downloadFiles, repairClient, rollbackClientRelease, cleanUnusedFiles, fileSummary, pendingJob, controlTransfer, resumeTransfer }: any) {
  const progress = downloadProgress as DownloadProgress | null;
  const handled = progress ? progress.completed + progress.failed + progress.skipped : 0;
  const total = progress?.totalFiles || 0;
  return <section className="panel">
    <h3>Загрузка, восстановление и очистка</h3>
    <p>Проверенная установка в staging с транзакционным переключением managed-файлов, журналом восстановления и откатом к last-known-good. Пользовательские данные не удаляются.</p>
    <div className="toolbar inline">
      <button disabled={transferBusy} onClick={verifyFiles}>Проверить файлы</button>
      <button disabled={transferBusy} onClick={downloadFiles}>Скачать недостающие</button>
      <button disabled={transferBusy} onClick={repairClient}>Восстановить повреждённое</button>
      <button disabled={transferBusy} onClick={rollbackClientRelease}>Откатить к last-known-good</button>
      <button disabled={transferBusy} onClick={cleanUnusedFiles}>Переместить лишнее в карантин</button>
      {transferBusy && <button onClick={() => controlTransfer('pause')}>Пауза</button>}
      {(transferBusy || pendingJob) && <button onClick={() => controlTransfer('cancel')}>Отменить</button>}
      {!transferBusy && pendingJob && <button onClick={resumeTransfer}>Продолжить сохранённую загрузку</button>}
    </div>
    {pendingJob && <p>Сохранённое задание: {pendingJob.projectId}/{pendingJob.profileId} · {pendingJob.status} · {pendingJob.totalFiles} файлов.</p>}
    {progress && <div role="status" aria-live="polite">
      <p>Состояние: {progress.phase}; обработано {handled} из {total}; активных {progress.active}, в очереди {progress.queued}, ошибок {progress.failed}.</p>
      <progress style={{width: '100%'}} max={Math.max(1, total)} value={handled} aria-label="Прогресс по файлам" />
      <p>Передано по сети: {(progress.bytesTransferred / 1048576).toFixed(2)} МиБ; кеш: {progress.cacheHits ?? 0} файлов ({((progress.bytesReused ?? 0) / 1048576).toFixed(2)} МиБ); плановый размер {(progress.bytesExpected / 1048576).toFixed(2)} МиБ.</p>
      {progress.currentFile && <p>Файл: {progress.currentFile}</p>}
    </div>}
    <p>Исправно: {fileSummary.ok}; проблем: {fileSummary.broken}; всего: {fileSummary.total}.</p>
    <pre>{JSON.stringify({ download, repair: repairResult ? { status: repairResult.status, repaired: repairResult.repaired, message: repairResult.message } : null,
      cleanup: cleanResult, files: files.slice(0, 20) }, null, 2)}</pre>
  </section>;
}

function SettingsPanel({ settings, patchSettings, validateSettings, settingsCheck, checkJavaRuntime, javaInfo, openGameDirectory, manifest, profileServers, loadProfileServers, loadCachedOfflineManifest, cacheSignedManifest }: any) {
  return <section className="panel"><h3>Настройки запуска</h3>
    <div className="settings">
      <label>Путь к Java<input value={settings.javaPath} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('javaPath', e.target.value)} placeholder="auto / managed Java" /></label>
      <label>RAM, МБ<input type="number" min={Math.max(512, manifest?.runtime.memory?.minimumMb || 512)} max={Math.min(32768, manifest?.runtime.memory?.maximumMb || 32768)} value={settings.memoryMb} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('memoryMb', Number(e.target.value))} /></label>
      <label>Ширина окна<input type="number" min={640} max={7680} value={settings.screenWidth} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('screenWidth', Number(e.target.value))} /></label>
      <label>Высота окна<input type="number" min={480} max={4320} value={settings.screenHeight} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('screenHeight', Number(e.target.value))} /></label>
      <label className="checkSetting"><input type="checkbox" checked={settings.fullscreen} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('fullscreen', e.target.checked)} /> Полный экран</label>
      <label className="checkSetting"><input type="checkbox" checked={settings.autoEnter} disabled={settings.offlineEnabled} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('autoEnter', e.target.checked)} /> Автоматически подключаться к серверу</label>
      <label>Сервер профиля<select value={settings.serverId || ''} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => patchSettings('serverId', e.target.value)}><option value="">Без выбранного сервера</option>{profileServers.map((server: ScopedServer) => <option value={server.id} key={server.id}>{server.name} ({server.kind})</option>)}</select></label>
      {settings.autoEnter && <><label>Публичный игровой адрес<input value={settings.serverHost} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('serverHost', e.target.value)} placeholder="mc.example.org" /></label><label>Порт<input type="number" min={1} max={65535} value={settings.serverPort} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('serverPort', Number(e.target.value))} /></label></>}
      <label className="checkSetting"><input type="checkbox" checked={settings.offlineEnabled} disabled={!manifest?.runtime.launch?.offlineMode} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('offlineEnabled', e.target.checked)} /> Offline (только разрешённый подписанным Manifest v2)</label>
      <label>Закреплённый ключ Ed25519<input value={settings.pinnedPublicKey} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('pinnedPublicKey', e.target.value)} /></label>
    </div>
    <div className="toolbar inline"><button onClick={validateSettings}>Проверить настройки</button><button onClick={checkJavaRuntime}>Проверить Java</button><button onClick={openGameDirectory}>Открыть каталог клиента</button><button onClick={() => loadProfileServers().catch(console.error)}>Обновить серверы</button><button onClick={() => cacheSignedManifest().catch(console.error)}>Сохранить подписанный кеш</button><button onClick={loadCachedOfflineManifest}>Загрузить offline-кеш</button></div>
    <p>Server browser показывает узлы ServerBridge, а не игровые DNS-адреса. Для auto-enter укажите публичный адрес выбранного сервера. Offline не выдаёт серверные сессии и требует локальный проверенный Manifest и файлы.</p>
    <pre>{settingsCheck ? JSON.stringify(settingsCheck, null, 2) : javaInfo ? JSON.stringify(javaInfo, null, 2) : 'Настройки ещё не проверены.'}</pre>
  </section>;
}

function LogsPanel({ logs, launchPlan, launchResult, launchHistory, refreshLaunchHistory, stopRuntimeProcess }: any) {
  return <section className="grid two"><article className="panel"><h3>План запуска</h3><pre>{launchPlan?.commandPreview ?? 'План запуска ещё не собран.'}</pre>{launchPlan?.deterministicSha256 && <small>Resolved plan SHA-256: <code>{launchPlan.deterministicSha256}</code></small>}</article><article className="panel"><h3>Результат запуска</h3><p>{launchResult?.message ?? 'Запуск ещё не выполнялся.'}</p><small>{launchResult?.logPath ?? 'Лог появится после запуска.'}</small><div className="toolbar inline"><button onClick={refreshLaunchHistory}>Обновить историю запусков</button>{launchResult && ['running', 'stopping'].includes(launchResult.state) && <button onClick={stopRuntimeProcess}>Остановить процесс</button>}</div></article><article className="panel"><h3>История запусков</h3><pre>{JSON.stringify(launchHistory, null, 2)}</pre></article><article className="panel wide"><h3>Журнал лаунчера</h3><ul>{logs.map((entry: string) => <li key={entry}>{entry}</li>)}</ul></article></section>;
}

function DiagnosticsPanel({ exportDiagnostics, readinessContract, diagnosticsPolicy, settingsCheck }: any) {
  return <section className="panel"><h3>Диагностика</h3><p>Экспортирует локальный диагностический пакет без токенов и серверных секретов. Политика берётся из <code>/api/v1/diagnostics/policy</code>.</p><div className="toolbar inline"><button onClick={exportDiagnostics}>Экспортировать диагностический пакет</button></div><pre>{JSON.stringify({ readinessContract, diagnosticsPolicy, settingsCheck }, null, 2)}</pre></section>;
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(<App />);

import { offlineLaunchSettings0358, offlineSelection0358, offlineRecovery0358 } from './offline_policy_0358';
import { approvedSelectionIdentity0393, ensureReleaseApproval0359 } from './release_update_0359';
import React, { useEffect, useMemo, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import './styles.css';
import { UI_PREFERENCES_KEY0357, SCREENS0357, canNavigate0357, tr0357, shortcut0357, rovingNav0357, nextZoom0357, validateUISettings0357, type Locale0357, type Screen0357, type UISettings0357 } from './desktop_accessibility_0357';
import PlayerMigration0339 from './PlayerMigration0339';
import { installErrorCapture0309 } from './sentry_diagnostics_0309';
import { ensureReviewedDiagnostic03510, type PlayerDiagnosticPreview03510 } from './diagnostics_support_03510';
import { loadDesktopView03011, prewarmDesktop03011 } from './startup_optimizer_03011';


import { parseChoice0247 } from './component_selection_0247';
import { launchPreferences, scopedServers, type ScopedServer } from './desktop_experience_0229';
import { resolveLaunchMode0269, type GameLaunchMode0269 } from './launch_modes_0269';
import { OfficialMinecraftClient0257, type OfficialProfile0257 } from './official_minecraft_0257';
import { progress0354, recovery0354, type NativeTransfer0354, type Recovery0354 } from './download_experience_0354';




// Lazy chunks stay out of the startup bundle; Vite emits content-hashed
// assets that the desktop WebView caches across subsequent screen visits.
const DesktopExtensions0209 = React.lazy(() => loadDesktopView03011('extensions'));
const ComponentChooser0247 = React.lazy(() => loadDesktopView03011('components'));
const ComponentPortability02410 = React.lazy(() => loadDesktopView03011('portability'));
const OfficialMinecraftPanel0257 = React.lazy(() => loadDesktopView03011('official'));
const TexturesPanel0258 = React.lazy(() => loadDesktopView03011('textures'));
const HWIDRisk0299 = React.lazy(() => loadDesktopView03011('deviceRisk'));

type Stage = 'idle' | 'connecting' | 'session' | 'project' | 'profile' | 'manifest' | 'java' | 'files' | 'repair' | 'cleanup' | 'ready' | 'launching' | 'running' | 'failed';
type Screen = Screen0357;

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
  sentryDiagnosticsEnabled?: boolean;
  discordPresenceEnabled?: boolean;
  discordApplicationId?: string;
  discordActionUrl?: string;
  componentPreset?: string;
  configPath?: string;
  onboardingCompleted?: boolean;
  onboardingBootstrapDigest?: string;
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
  signature?: { signature: string; publicKey: string };
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
type ReleaseRequirements0359={installedVersion:string|null;targetVersion:string;targetSignature:string;changes:string[];proposedPreset:string|null;blockers:string[];requiresConfirmation:boolean};
type PlayerConflict0359={path:string;size:number;sha256:string};
type PlayerConflictResult0359={files:PlayerConflict0359[];archiveDirectory:string|null};


type PendingDownload = { operationId: string; mode: string; status: string; projectId: string; profileId: string; version: string; totalFiles: number };
type DownloadProgress = NativeTransfer0354;
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
type SignedBrand0355 = { displayName:string;publisher:string;websiteUrl?:string;accentColor?:string;backgroundColor?:string;textColor?:string;logoPng?:string;iconPng?:string;splashPng?:string;locale?:'ru'|'en';news?:{title:string;url:string}[] };
type SignedProvisioning0352 = { branding?:SignedBrand0355|null;backendUrl:string;projectId:string;profileId:string;channel:string;manifestUrl:string;pinnedPublicKey:string;displayName:string;digest:string;serverId:string;serverHost:string;serverPort:number;autoEnter:boolean };
type AuthSession = { accessToken: string; refreshToken: string; sessionId: string; email: string; userId: string; expiresAt?: string };
type AuthProvider0293 = { id: string; displayName: string; capabilities: string[]; healthy: boolean };
type AuthRouting0293 = { defaultProvider: string; requireExplicitProvider: boolean };
type DeviceKeyInfo = { userId: string; publicKey: string; fingerprint: string; deviceId?: string; createdAtUnix: number; storageBackend: string; keyAlgorithm: string; keyBinding: string; hardwareProvider: string; hardwareBound: boolean; privateKeyExposedToFrontend: boolean };
type DeviceSignatureResult = { fingerprint: string; publicKey: string; signature: string; keyAlgorithm: string; keyBinding: string; hardwareProvider: string; hardwareBound: boolean };
type MacOSTrustStatus0316 = { platform: string; localDeviceKey: string; localSecureEnclave: string; appAttest: string; remoteDeviceKeyProvenance: string; strictProfile: string; reasonCodes: string[] };
type TrustProfileDecision0311 = { profile: string; result: 'allow' | 'deny'; reasonCodes: string[]; recoveryAction?: string };
type TrustAssessment0311 = { keyPossession: string; localHardwareBinding: string; remoteHardwareProvenance: string; profileDecisions?: { standard?: TrustProfileDecision0311; strict?: TrustProfileDecision0311 } };
type ManagedDevice = { trustAssessment?: TrustAssessment0311; id: string; name: string; status: 'active' | 'revoked' | string; trustState: string; assurance: string; keyAlgorithm: string; keyBinding: string; hardwareProvider?: string; attestationState?: string; attestationExpiresAt?: string; keyFingerprint: string; platform?: string; clientVersion?: string; lastSeenAt?: string; lastIp?: string; revokedAt?: string; revokedReason?: string; replacedAt?: string; replacedByDeviceId?: string; replacementReason?: string; current: boolean; revocationPermanent: boolean };
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
  sentryDiagnosticsEnabled: false,
  discordPresenceEnabled: false,
  discordApplicationId: '',
  discordActionUrl: '',
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
    schemaVersion: '1.1',
    channel: settings.channel || 'stable',
    username: settings.username || 'Player',
    memoryMb: Number(settings.memoryMb ?? 4096),
    screenWidth: Number(settings.screenWidth ?? 1280),
    screenHeight: Number(settings.screenHeight ?? 720),
    serverPort: Number(settings.serverPort ?? 25565),
  };
}

function App() {
  // Native benchmark marker: the UI has reached its first painted React frame.
  // No external timers or telemetry run in ordinary production sessions:
  // the native command becomes a no-op unless the process opts into benchmarking.
  useEffect(() => {
    let alive = true;
    const outer = requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (alive) void invoke('benchmark_ui_ready_03511').catch(() => {});
      });
    });
    return () => { alive = false; cancelAnimationFrame(outer); };
  }, []);
  const [settings, setSettings] = useState<DesktopSettings>(() => loadSettings());
  const [screen, setScreen] = useState<Screen>('firstRun');
  const [signedProvisioning0352,setSignedProvisioning0352]=useState<SignedProvisioning0352|null>(null);
  const [bootstrapError0352,setBootstrapError0352]=useState('');
  const [nativeConfigLoaded0357,setNativeConfigLoaded0357]=useState(false);
  const hadStoredUI0357 = useRef<boolean>((()=>{try{return localStorage.getItem(UI_PREFERENCES_KEY0357)!==null;}catch{return false;}})());
  const [ui0357, setUi0357] = useState<UISettings0357>(() => {
    try {
      const saved = localStorage.getItem(UI_PREFERENCES_KEY0357);
      return validateUISettings0357(saved ? JSON.parse(saved) : null, navigator.language?.startsWith('en') ? 'en' : 'ru');
    } catch { return validateUISettings0357(null); }
  });
  const [nativeUI0357, setNativeUI0357] = useState<{os:string;scaleFactor:number}|null>(null);
  const contentRef0357 = useRef<HTMLElement>(null);
  const navRef0357 = useRef<HTMLElement>(null);
  const translate0357 = tr0357(ui0357.locale);
  const normalActionsEnabled0357 = nativeConfigLoaded0357 && !bootstrapError0352 && (!signedProvisioning0352 || Boolean(settings.onboardingCompleted));
  const nativeOS0357 = nativeUI0357?.os || (/Mac/i.test(navigator.platform) ? 'macos' : /Win/i.test(navigator.platform) ? 'windows' : 'linux');
  useEffect(() => {
    let active=true;
    const update=()=>void callTauri<{os:string;scaleFactor:number}>('desktop_native_ui_info_0357')
      .then(value=>{if(active)setNativeUI0357(value);}).catch(() => { /* Browser preview has no native window. */ });
    update();
    window.addEventListener('resize',update);
    window.addEventListener('focus',update);
    return ()=>{active=false;window.removeEventListener('resize',update);window.removeEventListener('focus',update);};
  }, []);
  useEffect(() => {
    document.documentElement.lang = ui0357.locale;
    document.documentElement.dataset.highContrast = String(ui0357.highContrast);
    document.documentElement.dataset.reducedMotion = String(ui0357.reducedMotion);
    // CSS zoom scales legacy pixel-based components as well as rem-based text.
    document.documentElement.style.zoom = `${ui0357.zoom}%`;
    try { localStorage.setItem(UI_PREFERENCES_KEY0357, JSON.stringify(ui0357)); } catch { /* private browsing */ }
    return () => { document.documentElement.style.zoom = ''; };
  }, [ui0357]);
  useEffect(() => {
    contentRef0357.current?.focus({preventScroll:true});
  }, [screen]);
  useEffect(() => {
    const listener = (event: KeyboardEvent) => {
      const action = shortcut0357(event,nativeOS0357);
      if (!action) return;
      if (action.type === 'zoom') {
        event.preventDefault();
        setUi0357(p => ({...p,zoom:nextZoom0357(p.zoom,action.direction)}));
      } else if (action.type === 'focusNav') {
        event.preventDefault();
        if (navRef0357.current?.contains(document.activeElement)) contentRef0357.current?.focus();
        else navRef0357.current?.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
      } else {
        const selected = SCREENS0357[action.index];
        // Signed onboarding cannot be skipped with a shortcut.
        if (!selected || !canNavigate0357(selected,nativeConfigLoaded0357,Boolean(bootstrapError0352),Boolean(signedProvisioning0352),Boolean(settings.onboardingCompleted))) return;
        event.preventDefault();setScreen(selected);
      }
    };
    document.addEventListener('keydown',listener);
    return () => document.removeEventListener('keydown',listener);
  }, [nativeOS0357, settings.onboardingCompleted, signedProvisioning0352, nativeConfigLoaded0357, bootstrapError0352]);

  useEffect(() => {
    if (!signedProvisioning0352?.branding?.locale) return;
    try {
      if (!hadStoredUI0357.current)
        setUi0357(p => ({...p,locale:signedProvisioning0352.branding!.locale!}));
    } catch { /* UI preference storage optional */ }
  }, [signedProvisioning0352]);

  const [firstRunStep0352,setFirstRunStep0352]=useState<'start'|'select'|'complete'>('start');
  const [firstRunBusy0352,setFirstRunBusy0352]=useState(false);
  const [firstRunError0352,setFirstRunError0352]=useState('');
  const [stage, setStage] = useState<Stage>('idle');
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [requirements0359,setRequirements0359]=useState<ReleaseRequirements0359|null>(null);
  const [requirementsApproved0359,setRequirementsApproved0359]=useState('');
  const [requirementsError0359,setRequirementsError0359]=useState('');

  const [javaInfo, setJavaInfo] = useState<JavaInfoResult | null>(null);
  const [files, setFiles] = useState<FileCheckResult[]>([]);
  const [download, setDownload] = useState<DownloadResult | null>(null);
  const [repairResult, setRepairResult] = useState<RepairResult | null>(null);
  const [downloadProgress, setDownloadProgress] = useState<DownloadProgress | null>(null);
  const [transferFailure0354, setTransferFailure0354] = useState<Recovery0354 | null>(null);
  const cancelledTransfer0354 = useRef(false);
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
        void callTauri<PendingDownload | null>('pending_download_job', { root, pinnedPublicKey: settings.pinnedPublicKey }).then((pending) => {
          if (!disposed) { setPendingJob(pending); recordTransferOutcome0354(result, pending); }
        }).catch((error) => { if (!disposed) setTransferFailure0354(recovery0354(error)); });
        log(`После перезапуска: скачано ${result.downloaded}, ошибок ${result.failed}.`);
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
  const [diagnosticPreview03510, setDiagnosticPreview03510] = useState<PlayerDiagnosticPreview03510 | null>(null);
  const [diagnosticConsent03510, setDiagnosticConsent03510] = useState(false);
  const [diagnosticStatus03510, setDiagnosticStatus03510] = useState('');
  const [diagnosticBusy03510, setDiagnosticBusy03510] = useState(false);
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
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [authSession, setAuthSession] = useState<AuthSession | null>(null);
  const [authProviders0293, setAuthProviders0293] = useState<AuthProvider0293[]>([]);
  const [routing0293, setRouting0293] = useState<AuthRouting0293>({ defaultProvider: 'local', requireExplicitProvider: false });
  const [selectedAuthProvider0293, setSelectedAuthProvider0293] = useState('');
  const [authProviderError0293, setAuthProviderError0293] = useState('');
  const [linkedProvider0293, setLinkedProvider0293] = useState('');
  const [linkedIdentifier0293, setLinkedIdentifier0293] = useState('');
  const [linkedPassword0293, setLinkedPassword0293] = useState('');
  const [linkFeedback0293, setLinkFeedback0293] = useState('');
  useEffect(() => {
    let active = true;
    const base = settings.backendUrl.trim().replace(/\/$/, '');
    setAuthProviders0293([]);
    setAuthProviderError0293('');
    if (!/^https?:\/\//i.test(base)) return;
    const controller = new AbortController();
    void fetch(`${base}/api/v1/auth/providers`, { signal: controller.signal })
      .then(async (response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((payload: any) => {
        if (!active) return;
        const data = payload?.data ?? {};
        const providers = Array.isArray(data.items) ? data.items : [];
        setAuthProviders0293(providers.filter((item: any) => typeof item?.id === 'string' && Array.isArray(item.capabilities)).map((item: any) => ({
          id: item.id, displayName: String(item.displayName || item.id), capabilities: item.capabilities,
          healthy: item.healthy === true,
        })));
        setRouting0293({
          defaultProvider: String(data.routing?.defaultProvider || 'local'),
          requireExplicitProvider: data.routing?.requireExplicitProvider === true,
        });
      })
      .catch((error) => { if (active) setAuthProviderError0293(`Невозможно получить список auth providers: ${String(error)}`); });
    return () => { active = false; controller.abort(); };
  }, [settings.backendUrl]);
  const officialMinecraftClient = useRef<OfficialMinecraftClient0257 | null>(null);
  const [officialProfile, setOfficialProfile] = useState<OfficialProfile0257 | null>(null);
  const [minecraftIdentity, setMinecraftIdentity] = useState<GameLaunchMode0269>(settings.offlineEnabled ? 'offline' : 'local');
  const [offlineStatus0358, setOfflineStatus0358] = useState('');
  if (authSession?.accessToken && settings.backendUrl) {
    if (!officialMinecraftClient.current) officialMinecraftClient.current = new OfficialMinecraftClient0257(settings.backendUrl, authSession.accessToken, authSession.sessionId, callTauri);
    else officialMinecraftClient.current.rebind(settings.backendUrl, authSession.accessToken, authSession.sessionId);
  }

  const [deviceKey, setDeviceKey] = useState<DeviceKeyInfo | null>(null);
  const [deviceTrustStatus, setDeviceTrustStatus] = useState<string>('не инициализирован');
  const [macOSTrust0316, setMacOSTrust0316] = useState<MacOSTrustStatus0316 | null>(null);
  useEffect(() => {
    if (!authSession?.userId || !settings.backendUrl) { setMacOSTrust0316(null); return; }
    let cancelled = false;
    void callTauri<MacOSTrustStatus0316>('macos_trust_status_0316', { backendUrl: settings.backendUrl, userId: authSession.userId })
      .then(result => { if (!cancelled) setMacOSTrust0316(result.platform === 'macos' ? result : null); })
      .catch(() => { if (!cancelled) setMacOSTrust0316(null); });
    return () => { cancelled = true; };
  }, [authSession?.userId, settings.backendUrl, deviceKey?.fingerprint]);
  // AKs are enrolled out-of-band by the administrator, never generated by the frontend.
  const [windowsAkName0313, setWindowsAkName0313] = useState('');
  const [windowsAkCert0313, setWindowsAkCert0313] = useState('');
  const [windowsAkChain0313, setWindowsAkChain0313] = useState('');
  const [tpmStatus0313, setTpmStatus0313] = useState('not-verified');
  const [tpmBusy0313, setTpmBusy0313] = useState(false);
  const [measuredBootPolicyId0315, setMeasuredBootPolicyId0315] = useState('');
  const [measuredBootStatus0315, setMeasuredBootStatus0315] = useState('not-verified');
  const [measuredBootBusy0315, setMeasuredBootBusy0315] = useState(false);

  const [managedDevices, setManagedDevices] = useState<ManagedDevice[]>([]);
  // Switching Never identities invalidates any Microsoft account previously
  // linked in the running Desktop process (session tickets are SID-bound).
  useEffect(() => {
    let cancelled = false;
    const client = officialMinecraftClient.current;
    client?.clear();
    setOfficialProfile(null);
    setMinecraftIdentity('local');
    if (authSession?.accessToken && authSession.sessionId && client) {
      void client.restore().then(profile => { if (!cancelled && profile) setOfficialProfile(profile); })
        .catch(() => { /* expired/revoked session must not be treated as linked */ });
    }
    return () => { cancelled = true; };
  }, [authSession?.sessionId, settings.backendUrl]);

  useEffect(() => {
    let disposed=false;
    void (async()=>{
      try{
        const [config,provisioning]=await Promise.all([
          callTauri<DesktopSettings>('load_desktop_config'),
          callTauri<SignedProvisioning0352|null>('load_signed_provisioning_0352'),
        ]);
        if(disposed)return;
        const next=normalizedSettings(config);
        setSettings(next);
        setSelectedProject(next.projectId||'');setSelectedProfile(next.profileId||'');
        setSignedProvisioning0352(provisioning);
        setBootstrapError0352('');
        setNativeConfigLoaded0357(true);
        setScreen(provisioning&&!next.onboardingCompleted?'firstRun':next.backendUrl?'overview':'firstRun');
        log(provisioning?`Подписанный bootstrap ${provisioning.digest.slice(0,16)}… проверен native Ed25519.`:'Desktop config загружен без подписанного bundle.');
      }catch(error){
        if(disposed)return;
        // A production Tauri trust error MUST NOT fall back to mutable localStorage.
        if((window as any).__TAURI_INTERNALS__){
          setBootstrapError0352(`Безопасная загрузка Desktop отклонена: ${String(error)}`);
          setNativeConfigLoaded0357(true);
          setScreen('firstRun');setStage('failed');
          return;
        }
        const fallback=normalizedSettings(loadSettings());
        setSettings(fallback);setSelectedProject(fallback.projectId||'');
        setSelectedProfile(fallback.profileId||'');
        setNativeConfigLoaded0357(true);
        log('Только web preview: параметры восстановлены из localStorage без native trust.');
      }
    })();
    return ()=>{disposed=true};
  }, []);

  // Explicit opt-in is enforced independently by the native process.
  useEffect(() => {
    void callTauri<void>('desktop_sentry_consent', { enabled: settings.sentryDiagnosticsEnabled === true }).catch(() => undefined);
    return () => { void callTauri<void>('desktop_sentry_consent', { enabled: false }).catch(() => undefined); };
  }, [settings.sentryDiagnosticsEnabled]);
  useEffect(() => installErrorCapture0309(window, (category, frames) => {
    void callTauri<void>('desktop_sentry_report', { category, frames }).catch(() => undefined);
  }), []);

  // Rich Presence is opt-in and never part of Minecraft launch readiness.
  // A timer re-establishes IPC after Discord restarts without coupling it to game launch.
  useEffect(() => {
    if (!settings.discordPresenceEnabled || !settings.discordApplicationId?.trim()) {
      void callTauri<void>('discord_presence_clear').catch(() => undefined);
      return;
    }
    const phase = stage === 'running' ? 'В игре' :
      stage === 'launching' ? 'Запуск Minecraft' :
      screen === 'auth' || !authSession ? 'Вход в NeverLauncher' :
      selectedProfile ? 'Выбор / подготовка профиля' : 'Выбор проекта';
    const details = stage === 'running' ? `Minecraft · ${selectedProfile || 'Клиент'}` :
      'NeverLauncher';
    const update = () => void callTauri<void>('discord_presence_set', {
      request: {
        applicationId: settings.discordApplicationId?.trim(),
        state: phase,
        details,
        actionUrl: settings.discordActionUrl?.trim() || null,
      },
    }).catch(() => undefined); // Discord is optional: failure must not block gameplay.
    update();
    const timer = window.setInterval(update, 30000);
    return () => window.clearInterval(timer);
  }, [settings.discordPresenceEnabled, settings.discordApplicationId, settings.discordActionUrl,
      screen, stage, selectedProfile, authSession?.sessionId]);

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
    if(signedProvisioning0352 && ['backendUrl','manifestUrl','projectId','profileId','channel','pinnedPublicKey',...(signedProvisioning0352.serverId?['serverId']:[]),...(signedProvisioning0352.autoEnter?['serverHost','serverPort','autoEnter']:[])].includes(key))return;
    if (key === 'backendUrl' && value !== settings.backendUrl) {
      officialMinecraftClient.current?.clear();
      setOfficialProfile(null);
      setMinecraftIdentity('local');
    }
    setSettings((current) => normalizedSettings({ ...current, [key]: value }));
  }

  function selectProject(projectId: string) {
    if(signedProvisioning0352 && projectId!==signedProvisioning0352.projectId)return;
    setSelectedProject(projectId);
    setSelectedProfile('');
    setProfileServers([]);
    setManifest(null);
    setSettings((current) => normalizedSettings({ ...current, projectId, profileId: '', serverId: '', offlineEnabled: false, componentPreset: '' }));
  }

  function selectProfile(profileId: string) {
    if(signedProvisioning0352 && profileId!==signedProvisioning0352.profileId)return;
    setSelectedProfile(profileId);
    const profile = profiles.find((item) => item.id === profileId);
    setManifest(null);
    setProfileServers([]);
    setSettings((current) => normalizedSettings({ ...current, profileId, serverId: '', offlineEnabled: false, componentPreset: '', channel: profile?.defaultChannel || current.channel || 'stable' }));
  }

  async function persistDesktopConfig() {
    const next = normalizedSettings({ ...settings, projectId: signedProvisioning0352?.projectId||selectedProject, profileId: signedProvisioning0352?.profileId||selectedProfile });
    try {
      const result = await callTauri<DesktopBindingResult>('save_desktop_config', { config: next });
      setSettings(next);
      log(result.message + ` (${result.configPath})`);
    } catch(error) {
      if((window as any).__TAURI_INTERNALS__){log(`Desktop config не сохранён: ${String(error)}`);return;}
      localStorage.setItem('neverlauncher.desktop.settings', JSON.stringify(next));
      log('Web preview: localStorage fallback не является production configuration.');
    }
  }

  async function resetDesktopBinding() {
    if(signedProvisioning0352){log('Привязка подписана владельцем; сброс вручную запрещён.');return;}
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
    const oldDeviceId = accessTokenDeviceId(session.accessToken) || deviceKey?.deviceId;
    if (!oldDeviceId) throw new Error('Не удалось определить исходный trusted device.');
    if (mode === 'recover') session = await passkeyStepUp(session);

    // A timed-out completion may already have committed on the server. Reconcile
    // before staging rather than discarding the private key for the new identity.
    const reconciled = await reconcileStagedReplacement(session);
    if (reconciled) {
      log('Незавершённая замена ключа подтверждена сервером и восстановлена.');
      await loadManagedDevices(session);
      return;
    }
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
      // Do not destroy staged identity: HTTP completion may have committed despite a lost response.
      // Retry reconciliation with the SAME staged private key after restoring connectivity.
      if (serverCommitted) log('Backend завершил replacement; staged key сохранён для повторного commit/reconciliation после ошибки native storage.');
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

  async function certifyPlatformTPM0314(): Promise<void> {
    if (!authSession?.accessToken || !deviceKey?.deviceId ||
        deviceKey.keyBinding !== 'hardware' || deviceKey.keyAlgorithm !== 'p256' ||
        !/(Win|Linux)/i.test(navigator.platform)) throw new Error('Windows/Linux TPM device and authenticated bound session required');
    if (!windowsAkName0313.trim() || !windowsAkCert0313.includes('-----BEGIN CERTIFICATE-----')) {
      throw new Error('Provisioned Windows AK name / Linux AK persistent handle and issuer-certified AK PEM required');
    }
    if (tpmBusy0313) return;
    setTpmBusy0313(true);
    setTpmStatus0313('TPM2_Certify: challenge requested');
    try {
      const url = `/api/v1/auth/devices/${encodeURIComponent(deviceKey.deviceId)}/tpm-certify`;
      const response = await postDeviceJson(`${url}/begin`, authSession.accessToken);
      if (!response.ok) throw new Error(`TPM begin rejected HTTP ${response.status}: ${(await response.text()).slice(0,350)}`);
      const payload = await response.json();
      const challenge = payload.data ?? payload;
      if (challenge.format !== 'tpm2-certify-sha256-v1' || !challenge.challengeId ||
          !challenge.challenge || !challenge.tpmExtraDataSha256 || challenge.deviceId !== deviceKey.deviceId ||
          challenge.sessionId !== authSession.sessionId || challenge.bindingEpoch !== accessTokenBindingEpoch(authSession.accessToken)) {
        throw new Error('TPM server challenge/session/epoch/format mismatch');
      }
      setTpmStatus0313('TPM2_Certify: issuing native TPM command');
      const evidence = await callTauri<{
        tpm2bPublic: string; tpm2bAttest: string; tpmtSignature: string;
        akCertificatePem: string; intermediatesPem: string[];
      }>(/Linux/i.test(navigator.platform) ? 'linux_tpm_certify_0314' : 'windows_tpm_certify_0313', {
        backendUrl: settings.backendUrl, userId: authSession.userId,
        deviceId: deviceKey.deviceId, tpmExtraDataSha256: challenge.tpmExtraDataSha256,
        ...(/Linux/i.test(navigator.platform) ? { akHandle: windowsAkName0313.trim() } : { akKeyName: windowsAkName0313.trim() }),
        akCertificatePem: windowsAkCert0313.trim(),
        intermediatesPem: windowsAkChain0313.trim() ? [windowsAkChain0313.trim()] : [],
      });
      // Server consumes the challenge even if validation fails, preventing replay.
      const completed = await postDeviceJson(`${url}/complete`, authSession.accessToken, {
        challengeId: challenge.challengeId, challenge: challenge.challenge, evidence,
      });
      if (!completed.ok) throw new Error(`TPM verifier rejected evidence HTTP ${completed.status}: ${(await completed.text()).slice(0,350)}`);
      const resultJson = await completed.json();
      const result = resultJson.data ?? resultJson;
      if (result.verification !== 'tpm-ak-certified' || !result.rootId || !result.akFingerprint ||
          result.bindingEpoch !== challenge.bindingEpoch || result.measuredBoot !== 'not-verified') {
        throw new Error('Unexpected server verification semantics');
      }
      setTpmStatus0313(`tpm-ak-certified · CA=${result.rootId} · expires=${result.expiresAt} · Guard/PCR not verified`);
      log(`TPM Certify verified by backend: device=${deviceKey.deviceId}; CA=${result.rootId}; Guard/PCR not verified`);
      await loadManagedDevices();
    } catch (error) {
      setTpmStatus0313(`not-verified: ${String(error)}`);
      throw error;
    } finally {
      setTpmBusy0313(false);
    }
  }

  async function verifyMeasuredBoot0315(): Promise<void> {
    if (!authSession?.accessToken || !deviceKey?.deviceId || deviceKey.keyBinding !== 'hardware' || deviceKey.keyAlgorithm !== 'p256') {
      throw new Error('TPM measured boot requires a registered hardware P-256 device');
    }
    if (!measuredBootPolicyId0315.trim() || measuredBootPolicyId0315.length > 96 ||
        !/^[a-zA-Z0-9_.-]+$/.test(measuredBootPolicyId0315.trim())) {
      throw new Error('Введите идентификатор операторской PCR policy');
    }
    if (!windowsAkName0313.trim() || !windowsAkCert0313.includes('-----BEGIN CERTIFICATE-----')) {
      throw new Error('Настройте сертифицированный TPM Attestation Key');
    }
    if (measuredBootBusy0315) return;
    setMeasuredBootBusy0315(true);
    setMeasuredBootStatus0315('TPM Quote: запрашивается одноразовый challenge');
    try {
      const base = `/api/v1/auth/devices/${encodeURIComponent(deviceKey.deviceId)}/measured-boot`;
      const began = await postDeviceJson(`${base}/begin?policyId=${encodeURIComponent(measuredBootPolicyId0315.trim())}`, authSession.accessToken);
      if (!began.ok) throw new Error(`PCR policy / TPM Certify prerequisite rejected HTTP ${began.status}: ${(await began.text()).slice(0,350)}`);
      const beginJson = await began.json(); const challenge = beginJson.data ?? beginJson;
      if (challenge.format !== 'tpm2-quote-sha256-v1' || !challenge.tpmExtraDataSha256 ||
          !challenge.pcrSelection?.startsWith('sha256:') || !challenge.challengeId || !challenge.challenge ||
          challenge.sessionId !== authSession.sessionId || challenge.deviceId !== deviceKey.deviceId ||
          challenge.bindingEpoch !== accessTokenBindingEpoch(authSession.accessToken) ||
          challenge.policyId !== measuredBootPolicyId0315.trim()) {
        throw new Error('TPM Quote challenge/session/epoch/policy mismatch');
      }
      setMeasuredBootStatus0315(`TPM Quote: ${challenge.pcrSelection} · policy ${challenge.policyId}`);
      const evidence = await callTauri<{
        tpm2bAttest: string; tpmtSignature: string; pcrValues: Record<string,string>;
        akCertificatePem: string; intermediatesPem: string[];
      }>('measured_boot_quote_0315', {
        backendUrl: settings.backendUrl, userId: authSession.userId, deviceId: deviceKey.deviceId,
        tpmExtraDataSha256: challenge.tpmExtraDataSha256, pcrSelection: challenge.pcrSelection,
        akKey: windowsAkName0313.trim(), akCertificatePem: windowsAkCert0313.trim(),
        intermediatesPem: windowsAkChain0313.trim() ? [windowsAkChain0313.trim()] : [],
      });
      const completed = await postDeviceJson(`${base}/complete`,authSession.accessToken, {
        challengeId: challenge.challengeId, challenge: challenge.challenge, evidence,
      });
      if (!completed.ok) throw new Error(`TPM Quote verifier rejected HTTP ${completed.status}: ${(await completed.text()).slice(0,350)}`);
      const completedJson = await completed.json(); const result = completedJson.data ?? completedJson;
      if (result.verification !== 'tpm-quote-pcr-policy-verified' ||
          result.bindingEpoch !== challenge.bindingEpoch || result.policyHash !== challenge.policyHash ||
          result.guardRuntime !== 'not-verified') throw new Error('Unexpected measured-boot verification semantics');
      setMeasuredBootStatus0315(`PCR policy verified: ${result.policyId}; expires ${result.expiresAt}; Guard runtime not verified`);
      log(`Measured boot PCR Quote verified on server: device=${deviceKey.deviceId}, policy=${result.policyId}, digest=${result.pcrDigest}. Guard/runtime not verified.`);
    } catch (error) {
      setMeasuredBootStatus0315(`not-verified: ${String(error)}`);
      throw error;
    } finally {setMeasuredBootBusy0315(false);}
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
      throw new Error('Ключ уже привязан к другому server record. Автоматическое удаление запрещено: выполните восстановление с passkey и новой device identity.');
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
      body: JSON.stringify({ email, password, deviceId: 'desktop-client', ...(selectedAuthProvider0293 ? { providerId: selectedAuthProvider0293 } : {}) }),
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

  async function linkPasswordProvider0293(): Promise<void> {
    if (!authSession?.accessToken) throw new Error('Сначала войдите в NeverLauncher.');
    if (!linkedProvider0293 || !linkedIdentifier0293.trim() || !linkedPassword0293) throw new Error('Провайдер, идентификатор и пароль обязательны.');
    setLinkFeedback0293('');
    const response = await fetch(endpoint(`/api/v1/auth/providers/${encodeURIComponent(linkedProvider0293)}/link/password`), {
      method: 'POST',
      headers: { Authorization: `Bearer ${authSession.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: linkedIdentifier0293.trim(), password: linkedPassword0293 }),
    });
    if (!response.ok) throw new Error(`Внешняя identity не привязана: HTTP ${response.status}`);
    const payload = await response.json();
    const linked = payload?.data?.identity;
    if (payload?.data?.status !== 'linked' || linked?.provider !== linkedProvider0293 || !linked?.id) throw new Error('Backend не подтвердил привязку identity.');
    setLinkedPassword0293('');
    setLinkFeedback0293(`Привязана identity ${linked.provider} / ${linked.issuer} / ${linked.subject}.`);
    log(`Провайдер ${linked.provider} привязан с подтверждением внешних credentials.`);
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
    officialMinecraftClient.current?.clear();
    officialMinecraftClient.current = null;
    setOfficialProfile(null);
    setMinecraftIdentity('local');
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
    setOfflineStatus0358('Проверка подписанного кеша и целостности установленной сборки…');
    try {
      // Native verifier repeats owner binding, manifest signature, installed
      // release/preset, and SHA-256 validation before returning anything.
      const result = await callTauri<Manifest>('prepare_offline_launch_0358', {
        root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey,
        projectId: settings.projectId, profileId: settings.profileId, channel: settings.channel,
      });
      setManifest(result);
      setProfileServers([]);
      setLaunchPlan(null);
      setMinecraftIdentity('offline');
      setSettings(current => normalizedSettings({ ...current, offlineEnabled: true }));
      setOfflineStatus0358(`Offline готов: ${result.projectId}/${result.profileId} · ${result.version}. Доступ к защищённому серверу не предоставляется.`);
      log(`Offline: файлы установленной сборки ${result.version} проверены native SHA-256. Это не Minecraft entitlement.`);
    } catch (error) {
      const action=offlineRecovery0358(error);
      setMinecraftIdentity('local');
      setSettings(current => normalizedSettings({ ...current, offlineEnabled: false }));
      setOfflineStatus0358(`Offline недоступен: ${String(error)}. ${action}`);
      log(`Offline отклонён: ${String(error)}. ${action}`);
    }
  }

  function currentLaunchPreferences() {
    if (!manifest) throw new Error('Manifest не загружен');
    if (!['2.0','3.0'].includes(manifest.schemaVersion)) throw new Error('Desktop launch settings require Manifest v2/v3');
    const effective=offlineLaunchSettings0358(settings,minecraftIdentity === 'offline');
    return launchPreferences(effective, manifest.runtime.memory, Boolean(manifest.runtime.launch?.offlineMode), profileServers, false, minecraftIdentity === 'official');
  }

  async function loadManifest(projectId = selectedProject || settings.projectId, profileId = selectedProfile || settings.profileId) {
    setStage('manifest');
    try {
      const url = buildManifestUrl(projectId, profileId);
      if (!url) throw new Error('сначала выберите проект и профиль');
      const result = await callTauri<Manifest>('load_manifest', { url, pinnedPublicKey: settings.pinnedPublicKey });
      setRequirements0359(null);setRequirementsApproved0359('');setRequirementsError0359('');
      const actualRoot = settings.gameDirectory.includes(result.projectId)
        ? settings.gameDirectory : `${settings.gameDirectory || './.neverlauncher/projects'}/${result.projectId}/${result.profileId}`;
      const newRequirements=await callTauri<ReleaseRequirements0359>('preview_release_requirements_0359', {
        manifest:result,root:actualRoot,pinnedPublicKey:settings.pinnedPublicKey,componentPreset:null,
      });
      setRequirements0359(newRequirements);
      if(!newRequirements.requiresConfirmation)setRequirementsApproved0359(approvedSelectionIdentity0393(result,settings.componentPreset||''));
      setManifest(result);
      setMinecraftIdentity('local');
      setOfflineStatus0358('');
      // Do not erase the installed choice when a preset or component disappears.
      // The native migration preview compares this release against the verified
      // active release and requires explicit confirmation before installing.
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
      // Do not cache a merely fetched release. The active installed release
      // must be committed and verified before replacing the offline cache.
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
      setStage('failed');setRequirementsError0359(String(error));
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

  function recordTransferOutcome0354(result: DownloadResult, pending: PendingDownload | null): boolean {
    if (cancelledTransfer0354.current) {
      cancelledTransfer0354.current = false;
      setTransferFailure0354(null);
      setStage('idle');
      return false;
    }
    if (pending?.status === 'paused') {
      setTransferFailure0354(null);
      setStage('idle');
      return false;
    }
    if (result.failed > 0 || pending?.status === 'pending') {
      const reason = result.messages?.[0] || (result.failedFiles || [])[0] || 'download failed';
      setTransferFailure0354(recovery0354(reason));
      setStage('failed');
      return false;
    }
    setTransferFailure0354(null);
    setStage('ready');
    return true;
  }

  async function controlTransfer(action: 'pause' | 'cancel') {
    try {
      await callTauri('control_download_job', { root: settings.gameDirectory, action });
      log(action === 'pause' ? 'Запрошена пауза загрузки.' : 'Загрузка отменена.');
      if (action === 'cancel') {
        cancelledTransfer0354.current = true;
        setPendingJob(null);
        setTransferFailure0354(null);
      } else {
        setPendingJob(await callTauri<PendingDownload | null>('pending_download_job', {
          root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey,
        }));
      }
    } catch (error) { log(`Управление загрузкой: ${String(error)}`); }
  }

  async function resumeTransfer() {
    if (transferBusy || !pendingJob) return;
    cancelledTransfer0354.current = false;
    setTransferFailure0354(null);
    setDownloadProgress(null);
    setTransferBusy(true);
    try {
      const result = await callTauri<DownloadResult>('resume_download_job', { root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey });
      setDownload(result);
      const pending = await callTauri<PendingDownload | null>('pending_download_job', {
        root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey,
      });
      setPendingJob(pending);
      if (!recordTransferOutcome0354(result, pending)) return;
      if (manifest) {
        // The durable job stores the resolved choice; after resuming, reload
        // the verified installed selection instead of using stale UI settings.
        const installed=await callTauri<{installed:boolean;preset:string|null}>('installed_component_choice_0247',{
          manifest,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,
        });
        if(installed.installed){
          const chosen=installed.preset||'';
          await callTauri('save_installed_component_choice_0247',{
            manifest,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,componentPreset:chosen,
            config:normalizedSettings({...settings,componentPreset:chosen}),
          });
          patchSettings('componentPreset',chosen);
          setFiles(await callTauri<FileCheckResult[]>('check_files',{manifest,root:settings.gameDirectory,preset:chosen||null}));
          if (manifest.runtime.launch?.offlineMode) {
            await cacheSignedManifest(manifest).catch(error => log(`Offline кеш после resume не обновлён: ${String(error)}`));
          }
        }
      }
      log(`Возобновление: скачано ${result.downloaded}, ошибок ${result.failed}.`);
      setPendingJob(await callTauri<PendingDownload | null>('pending_download_job', { root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey }));
    } catch (error) {
      setStage('failed'); setTransferFailure0354(recovery0354(error));
      log(`Не удалось возобновить: ${String(error)}`);
    }
    finally { setTransferBusy(false); }
  }

  function ensureRequirementsApproved0359(active:Manifest) {
    ensureReleaseApproval0359(active,requirements0359,requirementsApproved0359,requirementsError0359,settings.componentPreset||'');
  }
  async function ensureNoPlayerConflicts0359(active:Manifest,preset:string){
    const result=await callTauri<PlayerConflictResult0359>('preview_player_conflicts_0359',{
      manifest:active,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,preset:preset||null,
    });
    if(result.files.length){
      throw new Error(`Найдены ${result.files.length} пользовательских файлов на путях новой сборки. Откройте «Загрузки» и сохраните их отдельно перед установкой.`);
    }
  }
  async function recheckChosenPreset0359() {
    if(!manifest)return;
    try {
      const newPreview=await callTauri<ReleaseRequirements0359>('preview_release_requirements_0359',{
        manifest,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,
        componentPreset:settings.componentPreset,
      });
      setRequirements0359(newPreview);setRequirementsApproved0359('');setRequirementsError0359('');
    }catch(error){setRequirementsError0359(String(error));}
  }
  function confirmRequirements0359() {
    if(!manifest||!requirements0359||requirements0359.blockers.length)return;
    const proposed=requirements0359.proposedPreset;
    if(proposed!==null && proposed!==settings.componentPreset){
      setSettings(current=>normalizedSettings({...current,componentPreset:proposed}));
    }
    setRequirementsApproved0359(approvedSelectionIdentity0393(manifest,proposed ?? (settings.componentPreset||'')));
    log(`Обновлённые требования ${requirements0359.targetVersion} приняты. Preset будет сохранён только после установки.`);
  }
  async function downloadFiles() {
    if (!manifest || transferBusy) return;
    try {ensureRequirementsApproved0359(manifest);await ensureNoPlayerConflicts0359(manifest,settings.componentPreset||'');}
    catch(error){setStage('failed');setTransferFailure0354(recovery0354(error));log(String(error));return;}
    cancelledTransfer0354.current = false;
    setTransferFailure0354(null);
    setStage('files');
    setTransferBusy(true);
    setDownloadProgress(null);
    try {
      const result = await callTauri<DownloadResult>('download_missing_files', {
        manifest, root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey, preset:settings.componentPreset||null,
      });
      setDownload(result);
      const pending = await callTauri<PendingDownload | null>('pending_download_job', {
        root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey,
      });
      setPendingJob(pending);
      if (!recordTransferOutcome0354(result, pending)) return;
      const verified = await callTauri<FileCheckResult[]>('check_files', {
        manifest, root: settings.gameDirectory,preset: settings.componentPreset||null,
      });
      setFiles(verified);
      if (verified.some(file => file.status !== 'ok' && file.status !== 'optional-missing')) {
        throw new Error('SHA-256 mismatch: проверка установленных файлов не пройдена');
      }
      // Persist the installed selection only after the signed release and
      // every selected file have been verified by the native runtime.
      await callTauri('save_installed_component_choice_0247', {
        manifest,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,
        componentPreset:settings.componentPreset||'',
        config:normalizedSettings(settings),
      });
      if (manifest.runtime.launch?.offlineMode) {
        await cacheSignedManifest(manifest).catch(error => log(`Offline кеш после установки не обновлён: ${String(error)}`));
      }
      log(`Загрузка подтверждена: ${result.downloaded} файлов; передано ${result.bytesDownloaded || 0} байт.`);
    } catch (error) {
      setStage('failed');
      setTransferFailure0354(recovery0354(error));
      log(`Загрузка не выполнена: ${String(error)}`);
    } finally {
      setTransferBusy(false);
      void callTauri<PendingDownload | null>('pending_download_job', { root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey }).then(setPendingJob).catch(() => {});
    }
  }

  // Commit exactly the previewed custom component plan, not a stale
  // settings closure. Persist the choice only after transactional install.
  async function installComponentSelection0247(choice: string): Promise<void> {
    if (!manifest || transferBusy) throw new Error('Установка уже выполняется или манифест не загружен');
    try {
      ensureReleaseApproval0359(manifest,requirements0359,requirementsApproved0359,requirementsError0359,choice);
    } catch(error) {
      if(requirements0359?.requiresConfirmation) {
        // The new candidate is a different signed selection. Force a new
        // native preview and explicit user approval before any file changes.
        try {
          const revised=await callTauri<ReleaseRequirements0359>('preview_release_requirements_0359',{
            manifest,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,componentPreset:choice,
          });
          setRequirements0359(revised);setRequirementsApproved0359('');setRequirementsError0359('');
          throw new Error('Выбор компонентов изменён: проверьте новое подтверждение перед установкой');
        } catch(recheckError) {
          if(String(recheckError).includes('Выбор компонентов изменён:'))throw recheckError;
          setRequirementsError0359(String(recheckError));throw recheckError;
        }
      }
      throw error;
    }
    await ensureNoPlayerConflicts0359(manifest,choice);
    setStage('files');setTransferBusy(true);setDownloadProgress(null);
    try {
      const result = await callTauri<DownloadResult>('download_missing_files', {
        manifest,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,preset:choice||null,
      });
      if(result.failed>0)throw new Error(`Не удалось загрузить ${result.failed} файлов`);
      const verified=await callTauri<FileCheckResult[]>('check_files',{
        manifest,root:settings.gameDirectory,preset:choice||null,
      });
      const invalid=verified.filter(file=>file.status!=='ok');
      if(invalid.length)throw new Error(`Установленный план содержит ${invalid.length} повреждённых/отсутствующих файлов`);
      // Native persistence verifies that the requested choice actually became
      // the active signed release before saving it in the desktop config.
      await callTauri('save_installed_component_choice_0247',{
        manifest,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,componentPreset:choice,
        config:normalizedSettings({...settings,componentPreset:choice}),
      });
      patchSettings('componentPreset',choice);
      if (manifest.runtime.launch?.offlineMode) {
        await cacheSignedManifest(manifest).catch(error => log(`Offline кеш выбранных компонентов не обновлён: ${String(error)}`));
      }
      setFiles(verified);setDownload(result);setStage('ready');
      log(`Компоненты установлены: ${result.downloaded} загружено, ${result.skipped} повторно использовано.`);
    }catch(error){setStage('failed');log(`Не удалось применить компоненты: ${String(error)}`);throw error;}
    finally{setTransferBusy(false);
      void callTauri<PendingDownload|null>('pending_download_job',{root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey}).then(setPendingJob).catch(()=>{});
    }
  }

  async function repairClient() {
    if (!manifest || transferBusy) {
      if (!manifest) log('Восстановление невозможно без манифеста профиля.');
      return;
    }
    cancelledTransfer0354.current = false;
    setTransferFailure0354(null);
    setStage('repair');
    setTransferBusy(true);
    setDownloadProgress(null);
    try {
      const result = await callTauri<RepairResult>('repair_client', { manifest, root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey,preset:settings.componentPreset||null });
      setRepairResult(result);
      setDownload(result.download);
      setFiles(result.after);
      const pending = await callTauri<PendingDownload | null>('pending_download_job', {
        root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey,
      });
      setPendingJob(pending);
      if (!recordTransferOutcome0354(result.download, pending)) return;
      if (result.status !== 'ready' || result.after.some(f => f.status !== 'ok' && f.status !== 'optional-missing')) {
        throw new Error('SHA-256 mismatch: repair did not restore all required files');
      }
      if (manifest.runtime.launch?.offlineMode) {
        await cacheSignedManifest(manifest).catch(error => log(`Offline кеш после repair не обновлён: ${String(error)}`));
      }
      log(`${result.message}: восстановлено ${result.repaired}, скачано ${result.download.downloaded}, ошибок ${result.download.failed}.`);
    } catch (error) {
      setStage('failed');
      setTransferFailure0354(recovery0354(error));
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
      // The native pointer is the authority after rollback. Restore BOTH the
      // manifest and its installed selection, never only the old UI dropdown.
      const restored=await callTauri<{manifest:Manifest;componentPreset:string}|null>('active_selection_02410',{
        root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,
      });
      if(restored){
        if(restored.manifest.projectId!==settings.projectId||restored.manifest.profileId!==settings.profileId||
           restored.manifest.channel!==settings.channel){
          throw new Error('Rollback restored another profile/channel; select that profile explicitly');
        }
        await callTauri('save_installed_component_choice_0247',{
          manifest:restored.manifest,root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,
          componentPreset:restored.componentPreset,
          config:normalizedSettings({...settings,componentPreset:restored.componentPreset}),
        });
        setManifest(restored.manifest);
        patchSettings('componentPreset',restored.componentPreset);
        setFiles(await callTauri<FileCheckResult[]>('check_files',{
          manifest:restored.manifest,root:settings.gameDirectory,preset:restored.componentPreset||null,
        }));
        log(`Rollback: восстановлен подписанный релиз ${restored.manifest.version} и его выбор компонентов.`);
      }else{setManifest(null);setFiles([]);log('Rollback: активный релиз отсутствует.');}
      setDownload(null);
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

  async function createContinuousGuardTicket(processId: string, minecraftAccessToken?: string): Promise<{ticket: string; attestationSha256: string}> {
    if (!authSession?.accessToken) throw new Error('Guard Attestation v2 требует активную Never session.');
    const userId = authSession.userId || accessTokenSubject(authSession.accessToken);
    const deviceId = accessTokenDeviceId(authSession.accessToken);
    if (!userId || !deviceId) throw new Error('Guard Attestation v2 требует trusted-device binding.');
    const key = deviceKey ?? await callTauri<DeviceKeyInfo | null>('device_key_status', { backendUrl: settings.backendUrl, userId });
    if (!key?.deviceId || key.deviceId !== deviceId || key.keyBinding !== 'hardware' || key.keyAlgorithm !== 'p256' || !key.hardwareBound) {
      throw new Error('Guard Attestation v2 требует hardware-bound P-256 device key текущего trusted device.');
    }
    const beginResponse = await postDeviceJson(`/api/v1/auth/devices/${encodeURIComponent(deviceId)}/guard-attest-v2/begin`, authSession.accessToken, {
      launcherVersion: DESKTOP_VERSION, minecraftAccessToken,
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
    if (!data?.verified || data.attestationVersion !== 2 || !data?.continuousGuardTicket || !data?.oneTime ||
        data.runtimePolicyEnforced !== true || data.runtimeAssurance !== 'device-signed-user-mode-observation') {
      throw new Error('Backend не подтвердил обязательную Guard Runtime Trust allowlist; запуск заблокирован.');
    }
    log(`Continuous Guard Attestation v2: прошла серверная runtime allowlist (user-mode evidence), hash=${String(data.continuousEvidenceSha256 || '').slice(0, 16)}…, cross-checks=${data.crossCheckCount ?? 0}.`);
    return {ticket: String(data.continuousGuardTicket), attestationSha256: String(data.attestationSha256)};
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

  async function createVerifiedPlanEvidence02412(guardAttestationSha256?: string) {
    if (!authSession?.accessToken || !settings.serverId) return undefined;
    const response = await fetch(endpoint('/api/v1/server-bridge/plan-challenge'), {
      method: 'POST',
      headers: {Authorization: `Bearer ${authSession.accessToken}`, 'Content-Type': 'application/json'},
      body: JSON.stringify({serverId:settings.serverId,projectId:settings.projectId,profileId:settings.profileId,channel:settings.channel}),
    });
    // The backend explicitly returns 412 when signed-plan enforcement is disabled.
    // All other failures, including missing/invalid policy, fail closed.
    if (response.status === 412) {
      const body = await response.text();
      if (body.includes('verified plan policy is disabled')) return undefined;
      throw new Error(`ServerBridge plan challenge denied: ${body}`);
    }
    const payload = await response.json().catch(()=>null);
    if (!response.ok) throw new Error(`ServerBridge plan challenge failed: ${response.status} ${JSON.stringify(payload)}`);
    const challenge=payload?.data;
    if (!challenge?.challengeId || !challenge?.challenge || !guardAttestationSha256) {
      throw new Error('NeverGuard v2 и одноразовый challenge обязательны для verified plan.');
    }
    const userId=authSession.userId || accessTokenSubject(authSession.accessToken);
    const deviceId=accessTokenDeviceId(authSession.accessToken);
    if (!userId || !deviceId) throw new Error('Device Trust session binding required for plan evidence');
    return callTauri('attest_verified_component_plan_02412', {request:{
      backendUrl:settings.backendUrl,userId,deviceId,sessionId:authSession.sessionId,
      bindingEpoch:accessTokenBindingEpoch(authSession.accessToken),serverId:settings.serverId,
      projectId:settings.projectId,profileId:settings.profileId,channel:settings.channel,
      root:settings.gameDirectory,pinnedPublicKey:settings.pinnedPublicKey,
      challengeId:challenge.challengeId,challenge:challenge.challenge,
      guardAttestationSha256,
    }});
  }

  async function createServerJoinAfterLaunch(username: string, minecraftAccessToken: string, continuousGuardTicket?: string, guardAttestationSha256?: string) {
    if (!authSession?.accessToken || !settings.serverId) return;
    if (!profileServers.some((server) => server.id === settings.serverId)) throw new Error('serverId отсутствует в серверном списке профиля');
    const planEvidence = await createVerifiedPlanEvidence02412(guardAttestationSha256);
    const response = await fetch(endpoint('/api/v1/session/join'), {
      method: 'POST',
      headers: { Authorization: `Bearer ${authSession.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, serverId: settings.serverId, projectId: settings.projectId, profileId: settings.profileId, channel: settings.channel, minecraftAccessToken, continuousGuardTicket, planEvidence }),
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
      const offlineSelection=offlineSelection0358(minecraftIdentity,settings);
      const launchMode = resolveLaunchMode0269({
        identity: minecraftIdentity, offlineAllowed: Boolean(manifest.runtime.launch?.offlineMode),
        autoEnter: preferences.autoEnter, serverId: offlineSelection.serverId,
        hasOfficialProfile: Boolean(officialProfile && officialMinecraftClient.current?.linked),
      });
      // Only cached signed Manifest v2 may be used when the backend is offline.
      // Never manufacture Minecraft access tokens for offline launches.
      let minecraftCredentials: MinecraftLaunchCredentials | undefined;
      let officialLaunchIdentity: {backendUrl:string;neverToken:string;neverSessionId:string} | undefined;
      if (launchMode === 'official' && preferences.offline) {
        throw new Error('Официальный Minecraft несовместим с offline-запуском.');
      }
      if (!preferences.offline) {
        const guardAttestationTicket = await createGuardLaunchTicket();
        if (launchMode === 'official') {
          if (!officialProfile || !officialMinecraftClient.current?.linked) throw new Error('Подключите официальный Minecraft-профиль в разделе авторизации.');
          if (!authSession?.accessToken || !authSession.sessionId) throw new Error('Необходимо войти в NeverLauncher.');
          officialLaunchIdentity = {backendUrl:settings.backendUrl,neverToken:authSession.accessToken,neverSessionId:authSession.sessionId};
        } else {
          minecraftCredentials = await createMinecraftLaunchSession(guardAttestationTicket);
        }
      }
      // Auto-enter needs its one-time ServerBridge ticket *before* Java receives
      // --server/--quickPlayMultiplayer, otherwise Minecraft can connect before
      // our post-launch join call. Policies requiring runtime attestation will
      // reject pre-join, in which case we fail closed instead of racing a join.
      if (preferences.autoEnter && minecraftCredentials && launchMode === 'local') {
        await createServerJoinAfterLaunch(minecraftCredentials.username, minecraftCredentials.accessToken);
      }
      const result = await callTauri<ProcessStatus>('launch_minecraft', {
        request: {
          manifest,
          authMode: launchMode === 'local' ? 'yggdrasil' : launchMode,
          root: settings.gameDirectory,
          javaPath: settings.javaPath || null,
          username: minecraftCredentials?.username || settings.username,
          minecraftCredentials: minecraftCredentials || null,
          officialIdentity: officialLaunchIdentity || null,
          pinnedPublicKey: settings.pinnedPublicKey,
          preferences,
          componentPreset:settings.componentPreset||null,
        },
      });
      let continuousGuardTicket: string | undefined;
      let guardAttestationSha256: string | undefined;
      if (!preferences.offline && result.windowsSensor) {
        try {
          const guard = await createContinuousGuardTicket(result.id, minecraftCredentials?.accessToken);
          continuousGuardTicket = guard.ticket;
          guardAttestationSha256 = guard.attestationSha256;
        } catch (attestationError) {
          await callTauri<ProcessStatus>('stop_runtime_process', { processId: result.id }).catch(() => undefined);
          throw new Error(`Windows runtime остановлен: Continuous Guard Attestation v2 не подтверждена: ${String(attestationError)}`);
        }
      }
      try {
        if (!preferences.offline && !preferences.autoEnter && minecraftCredentials && launchMode === 'local') {
          await createServerJoinAfterLaunch(minecraftCredentials.username, minecraftCredentials.accessToken, continuousGuardTicket, guardAttestationSha256);
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
      if (minecraftIdentity === 'offline') {
        const recovery=offlineRecovery0358(error);
        setOfflineStatus0358(`Offline запуск отклонён: ${String(error)}. ${recovery}`);
        log(`Offline запуск отклонён: ${String(error)}. ${recovery}`);
      } else {
        log(`Запуск не выполнен: ${String(error)}`);
      }
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

  async function previewDiagnostics03510() {
    setDiagnosticBusy03510(true); setDiagnosticStatus03510('');
    setDiagnosticConsent03510(false); setDiagnosticPreview03510(null);
    try {
      const preview = await callTauri<PlayerDiagnosticPreview03510>('preview_diagnostics_bundle_03510', { stage, logs });
      setDiagnosticPreview03510(preview);
      setDiagnosticStatus03510('Состав пакета проверен нативным процессом. Просмотрите поля перед экспортом или отправкой.');
    } catch (e) { setDiagnosticStatus03510(`Предпросмотр не выполнен: ${String(e)}`); }
    finally { setDiagnosticBusy03510(false); }
  }
  async function exportDiagnostics03510() {
    if (!diagnosticPreview03510) return;
    setDiagnosticBusy03510(true);
    try {
      const result = await callTauri<DiagnosticsExport>('export_diagnostics_bundle_03510', { reviewToken:diagnosticPreview03510.reviewToken });
      setDiagnosticStatus03510(`${result.message}: ${result.path}`);
      setDiagnosticPreview03510(null); setDiagnosticConsent03510(false);
    } catch (e) {setDiagnosticStatus03510(`Экспорт не выполнен: ${String(e)}`);}
    finally {setDiagnosticBusy03510(false);}
  }
  async function submitDiagnostics03510() {
    setDiagnosticBusy03510(true);
    try {
      const report=ensureReviewedDiagnostic03510(diagnosticPreview03510,diagnosticConsent03510,authSession?.accessToken);
      const destination=new URL(endpoint('/api/v1/diagnostics/reports'));
      if (destination.protocol!=='https:' && !(destination.protocol==='http:' && ['localhost','127.0.0.1','[::1]'].includes(destination.hostname))) {
        throw new Error('Для отправки отчёта требуется HTTPS Backend (HTTP допустим только для localhost).');
      }
      const response=await fetch(destination.toString(),{
        method:'POST', headers:{'Content-Type':'application/json',Authorization:`Bearer ${authSession!.accessToken}`},
        body:JSON.stringify({consent:true,report})
      });
      const payload=await response.json().catch(()=>({}));
      if (!response.ok) throw new Error(`Backend HTTP ${response.status}`);
      if (!/^[a-f0-9]{32}$/.test(String(payload.id||''))) throw new Error('Backend не подтвердил идентификатор отчёта. Проверьте поддержку перед повтором.');
      setDiagnosticStatus03510(`Отчёт принят поддержкой. ID: ${payload.id}`);
      setDiagnosticConsent03510(false);setDiagnosticPreview03510(null);
    } catch (e) {setDiagnosticStatus03510(`Отправка не выполнена: ${String(e)}. При сетевом сбое уточните получение у поддержки перед повтором.`);}
    finally {setDiagnosticBusy03510(false);}
  }

  async function openGameDirectory() {
    try {
      await callTauri<string>('open_game_directory', { root: settings.gameDirectory });
      log('Каталог клиента открыт.');
    } catch (error) {
      log(`Каталог клиента не открыт: ${String(error)}`);
    }
  }

  // 0.35.2: every step runs existing production API/native code. A failure
  // stops the wizard. No UI flag can substitute for native file verification.
  async function prepareFirstRun0352(){
    const p=signedProvisioning0352;
    if(!p||firstRunBusy0352)return;
    if(!authSession?.accessToken){setFirstRunError0352('Войдите в аккаунт проекта, затем продолжите подготовку.');setScreen('auth');return;}
    setFirstRunBusy0352(true);setFirstRunError0352('');
    try{
      setStage('connecting');
      await fetchBackendJson('/health');await fetchBackendJson('/ready');
      await fetchBackendJson('/api/v1/runtime/requirements');
      const projectPayload=await fetchBackendJson('/api/v1/projects');
      const projectItems:BackendProject[]=projectPayload?.items||projectPayload?.data?.items||[];
      if(!projectItems.some(item=>item.id===p.projectId))throw new Error('Подписанный проект недоступен этому аккаунту');
      setProjects(projectItems);setSelectedProject(p.projectId);
      setStage('profile');
      const profilePayload=await fetchBackendJson(`/api/v1/projects/${encodeURIComponent(p.projectId)}/profiles`);
      const profileItems:BackendProfile[]=profilePayload?.items||profilePayload?.data?.items||[];
      if(!profileItems.some(item=>item.id===p.profileId))throw new Error('Подписанный профиль недоступен этому аккаунту');
      setProfiles(profileItems);setSelectedProfile(p.profileId);
      setStage('manifest');
      const loaded=await callTauri<Manifest>('load_manifest',{url:p.manifestUrl,pinnedPublicKey:p.pinnedPublicKey});
      if(loaded.projectId!==p.projectId||loaded.profileId!==p.profileId||loaded.channel!==p.channel)
        throw new Error('Проверенный Manifest не соответствует подписанному профилю/каналу владельца');
      const signature=await callTauri<{valid:boolean}>('verify_manifest_signature',{manifest:loaded,pinnedPublicKey:p.pinnedPublicKey});
      if(!signature.valid)throw new Error('Ed25519-подпись Manifest недействительна');
      setManifest(loaded);setLaunchPlan(null);setLaunchResult(null);
      setStage('java');
      const check=await callTauri<SettingsCheck>('validate_desktop_settings',{
        gameDirectory:settings.gameDirectory,javaPath:settings.javaPath||null,memoryMb:settings.memoryMb,
      });
      if(!check.valid)throw new Error(`Системные требования: ${check.messages.join('; ')}`);
      setSettingsCheck(check);
      let java=await callTauri<JavaInfoResult>('check_java',{javaPath:settings.javaPath||null,requiredMajorVersion:loaded.runtime.java.majorVersion});
      if(!java.compatible&& !settings.javaPath&&loaded.runtime.java.distribution.toLowerCase()!=='system'){
        const installed=await callTauri<ManagedJavaResult>('ensure_profile_managed_java',{manifest:loaded,pinnedPublicKey:p.pinnedPublicKey});
        java=await callTauri<JavaInfoResult>('check_java',{javaPath:installed.javaExecutable,requiredMajorVersion:loaded.runtime.java.majorVersion});
        if(java.compatible)patchSettings('javaPath',installed.javaExecutable);
      }
      if(!java.compatible)throw new Error(`Java не подходит: ${java.message}`);
      setJavaInfo(java);
      const serversResponse=await fetchBackendJson(`/api/v1/projects/${encodeURIComponent(p.projectId)}/profiles/${encodeURIComponent(p.profileId)}/servers`);
      const availableServers=scopedServers(serversResponse?.data??serversResponse);
      if(p.serverId && !availableServers.some(server=>server.id===p.serverId))
        throw new Error('Сервер из подписанного bundle недоступен или отозван');
      setProfileServers(availableServers);
      setStage('files');setFirstRunStep0352('select');
      log('Профиль и требования проверены. Выберите сервер/моды и установите клиент.');
    }catch(error){setStage('failed');setFirstRunError0352(`Подготовка отклонена: ${String(error)}`);log(`0.35.2 first run: ${String(error)}`);}
    finally{setFirstRunBusy0352(false)}
  }

  async function installFirstRun0352(){
    const p=signedProvisioning0352;
    if(!p||!authSession?.accessToken||!manifest||firstRunBusy0352||transferBusy)return;
    setFirstRunBusy0352(true);setTransferBusy(true);setFirstRunError0352('');setStage('files');
    const selectedPreset=settings.componentPreset||'';
    try{
      if(manifest.projectId!==p.projectId||manifest.profileId!==p.profileId||manifest.channel!==p.channel)
        throw new Error('Выбранный релиз не совпадает с подписанной конфигурацией');
      const result=await callTauri<DownloadResult>('download_missing_files',{
        manifest,root:settings.gameDirectory,pinnedPublicKey:p.pinnedPublicKey,preset:selectedPreset||null,
      });
      setDownload(result);
      if(result.failed>0)throw new Error(`Не удалось скачать ${result.failed} файлов: ${(result.failedFiles||[]).slice(0,3).join(', ')}`);
      const checked=await callTauri<FileCheckResult[]>('check_files',{manifest,root:settings.gameDirectory,preset:selectedPreset||null});
      setFiles(checked);
      if(!checked.length||checked.some(item=>item.status!=='ok'))throw new Error('Проверка после установки обнаружила отсутствующие/повреждённые файлы');
      const config=normalizedSettings({...settings,projectId:p.projectId,profileId:p.profileId,
        backendUrl:p.backendUrl,manifestUrl:p.manifestUrl,channel:p.channel,pinnedPublicKey:p.pinnedPublicKey,
        ...(p.autoEnter?{serverId:p.serverId,serverHost:p.serverHost,serverPort:p.serverPort,autoEnter:true}:{}),
        onboardingCompleted:false});
      const native=await callTauri<DesktopBindingResult>('complete_first_run_0352',{config,manifest});
      const saved=await callTauri<DesktopSettings>('load_desktop_config');
      if(!saved.onboardingCompleted)throw new Error('Native verification не сохранила завершение');
      setSettings(normalizedSettings(saved));setFirstRunStep0352('complete');setStage('ready');
      if (manifest.runtime.launch?.offlineMode) {
        try { await cacheSignedManifest(manifest,saved.gameDirectory); }
        catch (error) {
          const message=`Подписанный offline-кеш не сохранён после установки: ${String(error)}`;
          setOfflineStatus0358(`${message}. ${offlineRecovery0358(error)}`);
          log(message);
        }
      }
      log(`Установка завершена и подтверждена Native (${checked.length} файлов): ${native.message}`);
    }catch(error){setStage('failed');setFirstRunError0352(`Установка не завершена: ${String(error)}. Используйте повторную попытку.`);log(`0.35.2 install: ${String(error)}`);}
    finally{setFirstRunBusy0352(false);setTransferBusy(false)}
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
    <>
    <a className="skipLink0357" href="#desktop-content0357">{translate0357.skip}</a>
    <main className="shell" style={signedProvisioning0352?.branding?{
      '--brand-accent':signedProvisioning0352.branding.accentColor||'#22c55e',
      '--brand-background':signedProvisioning0352.branding.backgroundColor||'#0f172a',
      '--brand-text':signedProvisioning0352.branding.textColor||'#e5e7eb',
    } as React.CSSProperties:undefined}>
      <aside className="sidebar">
        <div className="brand brandIdentity0355">
          {signedProvisioning0352?.branding?.iconPng&&<img src={`data:image/png;base64,${signedProvisioning0352.branding.iconPng}`} alt="" className="brandIcon0355"/>}
          {signedProvisioning0352?.displayName||"NeverLauncher"}
        </div>
        {signedProvisioning0352?.branding?.publisher&&<p className="brandPublisher0355">{signedProvisioning0352.branding.publisher}</p>}
        <div className="version">{DESKTOP_VERSION} · {translate0357.desktop}</div>
        <nav ref={navRef0357} aria-label={translate0357.nav} onKeyDown={event=>{
          const buttons=Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'));
          const current=buttons.indexOf(document.activeElement as HTMLButtonElement);
          const next=rovingNav0357(event.key,Math.max(current,0),buttons.length);
          if(next!==null){event.preventDefault();buttons[next]?.focus();}
        }}>
          {SCREENS0357.map((id,index) => <button key={id} disabled={!canNavigate0357(id,nativeConfigLoaded0357,Boolean(bootstrapError0352),Boolean(signedProvisioning0352),Boolean(settings.onboardingCompleted))} aria-current={screen===id?'page':undefined} className={screen === id ? 'active' : ''} onClick={() => setScreen(id)}>{translate0357.sections[index]}</button>)}
        </nav>
      </aside>

      <section className="content" id="desktop-content0357" ref={contentRef0357} tabIndex={-1} role="region" aria-label={`${translate0357.navStatus}: ${translate0357.sections[SCREENS0357.indexOf(screen)]}`}>
        <header className="hero brandHero0355" style={signedProvisioning0352?.branding?.splashPng?{
          backgroundImage:`linear-gradient(rgba(15,23,42,.82),rgba(15,23,42,.88)),url(data:image/png;base64,${signedProvisioning0352.branding.splashPng})`,
          backgroundSize:'cover',backgroundPosition:'center'}:undefined}>
          <div>
            {signedProvisioning0352?.branding?.logoPng&&<img className="brandLogo0355" src={`data:image/png;base64,${signedProvisioning0352.branding.logoPng}`} alt={signedProvisioning0352.displayName}/>}
            <p className="eyebrow">{translate0357.desktop}</p>
            <h1>{signedProvisioning0352?.branding?.displayName||'Движок запуска и восстановление клиента'}</h1>
            <p>{translate0357.subtitle}</p>
          </div>
          <div className="statusPill" role="status" aria-live="polite" aria-atomic="true">{ui0357.locale==='ru'?stageLabels[stage]:({idle:'Idle',connecting:'Connecting',session:'Session',project:'Project',profile:'Profile',manifest:'Manifest',java:'Java',files:'Files',repair:'Repair',cleanup:'Cleanup',ready:'Ready',launching:'Launching',running:'Running',failed:'Error'} as Record<Stage,string>)[stage]}</div>
        </header>

        {signedProvisioning0352?.branding && (signedProvisioning0352.branding.news?.length||0)>0 && <section className="brandNews0355" aria-label={translate0357.news}>
          <h2>{translate0357.news}</h2>
          <div className="brandNewsItems0355">{signedProvisioning0352.branding.news?.map((item,index)=><a key={index} href={item.url} onClick={(e)=>{e.preventDefault();void callTauri('open_external_https_0356',{url:item.url}).catch((error)=>log(`External link: ${String(error)}`));}}>{item.title}</a>)}</div>
        </section>}
        {signedProvisioning0352?.branding?.websiteUrl&&<p className="brandWebsite0355"><a href={signedProvisioning0352.branding.websiteUrl} onClick={(e)=>{e.preventDefault();void callTauri('open_external_https_0356',{url:signedProvisioning0352.branding!.websiteUrl}).catch((error)=>log(`External link: ${String(error)}`));}}>{translate0357.website}</a></p>}

        <section className="uiAccessibility0357" aria-label={translate0357.accessibility}>
          <label>{translate0357.language}<select aria-label={translate0357.language} value={ui0357.locale} onChange={e=>setUi0357(p=>({...p,locale:e.target.value==='en'?'en':'ru'}))}><option value="ru">Русский</option><option value="en">English</option></select></label>
          <label>{translate0357.zoom}<select aria-label={translate0357.zoom} value={ui0357.zoom} onChange={e=>setUi0357(p=>validateUISettings0357({...p,zoom:Number(e.target.value)},p.locale))}>{[80,90,100,110,125,150,175,200].map(value=><option key={value} value={value}>{value}%</option>)}</select></label>
          <label className="accessibilityCheck0357"><input type="checkbox" checked={ui0357.reducedMotion} onChange={e=>setUi0357(p=>({...p,reducedMotion:e.target.checked}))}/>{translate0357.motion}</label>
          <label className="accessibilityCheck0357"><input type="checkbox" checked={ui0357.highContrast} onChange={e=>setUi0357(p=>({...p,highContrast:e.target.checked}))}/>{translate0357.contrast}</label>
          <div className="nativeWindow0357"><span>{translate0357.os}: {nativeOS0357} · {translate0357.nativeScale}: {nativeUI0357 ? `${Math.round(nativeUI0357.scaleFactor*100)}%` : translate0357.auto}</span>
          <button type="button" onClick={()=>void callTauri('desktop_window_action_0357',{action:'minimize'}).catch(error=>log(String(error)))}>{translate0357.minimize}</button>
          <button type="button" onClick={()=>void callTauri('desktop_window_action_0357',{action:'toggleMaximized'}).catch(error=>log(String(error)))}>{translate0357.maximize}</button></div>
          <details><summary>{translate0357.shortcuts}</summary><p>{translate0357.shortcutHint}</p><p>{translate0357.languageInfo}</p></details>
        </section>
        <section className="toolbar">
          <button disabled={!normalActionsEnabled0357} onClick={runFullCheck}>{translate0357.check}</button>
          <button disabled={!normalActionsEnabled0357} onClick={persistDesktopConfig}>{translate0357.save}</button>
          <button disabled={!normalActionsEnabled0357} onClick={repairClient}>{translate0357.repair}</button>
          <button disabled={transferBusy||!normalActionsEnabled0357} onClick={rollbackClientRelease}>{translate0357.rollback}</button>
          <button disabled={!normalActionsEnabled0357} onClick={cleanUnusedFiles}>{translate0357.clean}</button>
          <button disabled={!normalActionsEnabled0357} onClick={buildPlan}>{translate0357.plan}</button>
          <button className="primary" disabled={transferBusy||!normalActionsEnabled0357} onClick={launch}>{translate0357.play}</button>
          <button disabled={!normalActionsEnabled0357} onClick={()=>{setScreen('diagnostics');void previewDiagnostics03510();}}>Предпросмотр диагностики</button>
        </section>

        {nativeConfigLoaded0357 && (!signedProvisioning0352 && !bootstrapError0352) && <section className="settings compact">
          <label>URL Backend<input value={settings.backendUrl} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('backendUrl', event.target.value)} /></label>
          <label>Переопределение URL манифеста<input value={settings.manifestUrl} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('manifestUrl', event.target.value)} placeholder="обычно пусто: используется /api/v1/projects/{project}/profiles/{profile}/manifest?channel=stable" /></label>
          <label>Каталог игры<input value={settings.gameDirectory} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('gameDirectory', event.target.value)} /></label>
          <label>Имя игрока<input value={settings.username} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('username', event.target.value)} /></label>
          <label>Память, МБ<input type="number" value={settings.memoryMb} min={Math.max(512, manifest?.runtime.memory?.minimumMb || 0)} max={Math.min(32768, manifest?.runtime.memory?.maximumMb || 32768)} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('memoryMb', Number(event.target.value))} /></label>
          <label>Канал<input value={settings.channel} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('channel', event.target.value)} /></label>
        </section>}

        <React.Suspense fallback={<section className="panel" role="status">{translate0357.loading}</section>}>
        {screen==='firstRun'&&nativeConfigLoaded0357&&signedProvisioning0352&&manifest&&firstRunStep0352==='select'&&<ConflictPreservation0359 manifest={manifest} root={settings.gameDirectory} pinnedPublicKey={settings.pinnedPublicKey} preset={settings.componentPreset||''} transferBusy={transferBusy} />}
        {screen === 'firstRun' && (!nativeConfigLoaded0357 ? <section className="panel" role="status">{ui0357.locale==='en'?'Checking native configuration…':'Проверка native-конфигурации…'}</section> : bootstrapError0352 ? <section className="panel" role="alert"><h3>{translate0357.fatal}</h3><p>{bootstrapError0352}</p><p>{translate0357.reinstall}</p></section> : signedProvisioning0352 ?
          <FirstRunSigned0352 locale0357={ui0357.locale} provisioning={signedProvisioning0352} settings={settings} session={authSession} busy={firstRunBusy0352} transferBusy={transferBusy} step={firstRunStep0352} error={firstRunError0352} manifest={manifest} servers={profileServers} progress={downloadProgress} onLogin={()=>setScreen('auth')} onPrepare={prepareFirstRun0352} onInstall={installFirstRun0352} onPlay={launch} onServer={(id:string)=>patchSettings('serverId',id)} onPreset={(value:string)=>patchSettings('componentPreset',value)} onComponents={()=>setScreen('profile')} /> :
          <FirstRunPanel settings={settings} patchSettings={patchSettings} bindingPolicy={bindingPolicy} checkBackend={checkBackend} loadProjects={loadProjects} loadProfiles={loadProfiles} persistDesktopConfig={persistDesktopConfig} resetDesktopBinding={resetDesktopBinding} selectedProject={selectedProject} selectedProfile={selectedProfile} />) }
        {screen === 'overview' && <Overview readiness={readiness} backendStatus={backendStatus} manifest={manifest} javaInfo={javaInfo} fileSummary={fileSummary} launchPlan={launchPlan} readinessContract={readinessContract} diagnosticsPolicy={diagnosticsPolicy} />}
        {screen === 'auth' && signedProvisioning0352 && !settings.onboardingCompleted && <section className="panel"><button className="primary" onClick={()=>setScreen('firstRun')}>{translate0357.back}</button></section>}
        {screen === 'auth' && <AuthPanel email={email} setEmail={setEmail} password={password} setPassword={setPassword} session={authSession} deviceKey={deviceKey} deviceTrustStatus={deviceTrustStatus} managedDevices={managedDevices} checkBackend={checkBackend} loginDesktop={loginDesktop} refreshDesktopSession={refreshDesktopSession} logoutDesktop={logoutDesktop} restoreSession={restoreSession} refreshDeviceKeyStatus={refreshDeviceKeyStatus} loadManagedDevices={loadManagedDevices} renameManagedDevice={renameManagedDevice} revokeManagedDevice={revokeManagedDevice} revokeOtherManagedDevices={revokeOtherManagedDevices} replaceDesktopDeviceKey={replaceDesktopDeviceKey} macOSTrust0316={macOSTrust0316} authProviders0293={authProviders0293} routing0293={routing0293} selectedAuthProvider0293={selectedAuthProvider0293} setSelectedAuthProvider0293={setSelectedAuthProvider0293} authProviderError0293={authProviderError0293} setAuthProviderError0293={setAuthProviderError0293} linkedProvider0293={linkedProvider0293} setLinkedProvider0293={setLinkedProvider0293} linkedIdentifier0293={linkedIdentifier0293} setLinkedIdentifier0293={setLinkedIdentifier0293} linkedPassword0293={linkedPassword0293} setLinkedPassword0293={setLinkedPassword0293} linkFeedback0293={linkFeedback0293} setLinkFeedback0293={setLinkFeedback0293} linkPasswordProvider0293={linkPasswordProvider0293} />}
        {screen === 'auth' && /(Win|Linux)/i.test(navigator.platform) && <section className="panel">
          <h3>Windows/Linux TPM Key Attestation (0.31.4)</h3>
          <p>TPM2_Certify для существующего зарегистрированного P-256 ключа. AK должен быть заранее выпущен доверенным TPM Attestation CA. Windows использует Platform Crypto Provider; Linux — предварительно provisioned persistent TPM AK handle 0x81xxxxxx. Это не проверка Guard/PCR и не античит.</p>
          <div className="settings">
            <label>{/Linux/i.test(navigator.platform) ? "Linux AK persistent handle (0x81xxxxxx)" : "Имя AK в Windows Platform Crypto Provider"}<input value={windowsAkName0313} onChange={e=>setWindowsAkName0313(e.target.value)} placeholder={/Linux/i.test(navigator.platform) ? "0x81010001" : "Имя AK в PCP"} /></label>
            <label>AK X.509 leaf certificate PEM<textarea rows={4} value={windowsAkCert0313} onChange={e=>setWindowsAkCert0313(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></label>
            <label>Промежуточный сертификат PEM (если нужен)<textarea rows={3} value={windowsAkChain0313} onChange={e=>setWindowsAkChain0313(e.target.value)} /></label>
          </div>
          <button disabled={tpmBusy0313 || !authSession || !deviceKey?.deviceId || deviceKey.keyBinding !== 'hardware' || deviceKey.keyAlgorithm !== 'p256'} onClick={() => certifyPlatformTPM0314().catch((e:Error)=>log(`TPM Certify: ${String(e)}`))}>{tpmBusy0313 ? 'Проверка TPM…' : 'Подтвердить TPM-происхождение'}</button>
          <p role="status">{tpmStatus0313}</p>
          <h4>Measured Boot / PCR Verification (0.31.5)</h4>
          <p>Отдельная проверка TPM Quote и разрешённых PCR через серверную политику. Требуется ранее подтверждённый TPM Certify в этой же device/session epoch. Смена PCR policy, AK, сессии или устройства аннулирует текущую проверку. Это не доказательство целостности JVM, Guard или защиты от пользовательской инъекции.</p>
          <label>Идентификатор разрешённой PCR policy<input value={measuredBootPolicyId0315} onChange={e=>setMeasuredBootPolicyId0315(e.target.value)} placeholder="approved-boot-linux-2026" /></label>
          <button disabled={tpmBusy0313 || measuredBootBusy0315 || !authSession || !deviceKey?.deviceId || deviceKey.keyBinding !== 'hardware' || deviceKey.keyAlgorithm !== 'p256'} onClick={() => verifyMeasuredBoot0315().catch((e:Error)=>log(`TPM Quote: ${String(e)}`))}>
            {measuredBootBusy0315 ? 'Проверка PCR…' : 'Проверить Measured Boot по TPM Quote'}
          </button>
          <p role="status">{measuredBootStatus0315}</p>
          <small>Linux: необходимы /dev/tpmrm0, tpm2-tools 5.x и AK на TPM persistent handle. Windows: пустая auth-сессия PCP-ключа. Несовместимые TPM/AK завершаются отказом без аппаратного assurance. AK root policy задаётся оператором на Backend.</small>
        </section>}
        {screen === 'auth' && authSession && deviceKey?.deviceId && accessTokenDeviceId(authSession.accessToken) === deviceKey.deviceId && <HWIDRisk0299 backendUrl={settings.backendUrl} token={authSession.accessToken} deviceId={deviceKey.deviceId} />}
        {screen === 'auth' && authSession?.accessToken && officialMinecraftClient.current && <>
          <OfficialMinecraftPanel0257 key={`${settings.backendUrl}|${authSession.sessionId}`} client={officialMinecraftClient.current} linkedProfile={officialProfile} onLinked={(p)=>{setOfficialProfile(p); if (!p) setMinecraftIdentity('local');}} />
          <section className="panel"><label>Режим запуска Minecraft <select value={minecraftIdentity} onChange={e=>{
            const mode=e.target.value as GameLaunchMode0269;
            if(mode==='offline'){ void loadCachedOfflineManifest(); return; }
            setMinecraftIdentity(mode);
            patchSettings('offlineEnabled', false);
            if (mode !== 'local') patchSettings('serverId', '');
          }}>
            <option value="local">Project Yggdrasil (Never identity / ServerBridge)</option>
            <option value="official" disabled={!officialProfile}>Official Minecraft (Microsoft) {officialProfile?.name||''}</option>
            <option value="offline" disabled={!manifest?.runtime.launch?.offlineMode}>Offline (разрешённый подписанным профилем)</option>
          </select></label><p>Official использует Mojang sessionserver; Yggdrasil — подписанный authlib-injector. Offline не позволяет входить на online-mode сервер.</p></section>
        </>}
        {screen === 'textures' && <TexturesPanel0258 backendUrl={settings.backendUrl} token={authSession?.accessToken||''} officialClient={officialMinecraftClient.current} officialProfile={officialProfile} onOfficialProfile={(p)=>{setOfficialProfile(p);if(!p)setMinecraftIdentity('local');}} identityMode={minecraftIdentity === 'official' ? 'official' : 'local'} />}
        {screen === 'projects' && signedProvisioning0352 ? <section className="panel">Проект закреплён подписанным bundle: {signedProvisioning0352.projectId}</section> : screen === 'projects' && <ProjectPanel projects={projects} selectedProject={selectedProject} setSelectedProject={selectProject} loadProjects={loadProjects} loadProfiles={loadProfiles} />}
        {requirementsError0359 && <section className="panel" role="alert"><strong>Обновление заблокировано:</strong> {requirementsError0359}</section>}
        {manifest&&requirements0359?.requiresConfirmation&&requirementsApproved0359!==approvedSelectionIdentity0393(manifest,settings.componentPreset||'')&&<section className="panel" role="alert" aria-label="Изменения требований подписанной сборки">
          <h3>Изменились требования сборки · {requirements0359.installedVersion} → {requirements0359.targetVersion}</h3>
          <ul>{requirements0359.changes.map(change=><li key={change}>{change}</li>)}</ul>
          {requirements0359.blockers.length>0&&<p>Блокирующие изменения: {requirements0359.blockers.join('; ')}. Выберите совместимый preset в разделе «Опциональные моды».</p>}
          <button disabled={transferBusy} onClick={()=>void recheckChosenPreset0359()}>Проверить выбранный preset</button>
          <button className="primary" disabled={requirements0359.blockers.length>0||transferBusy} onClick={confirmRequirements0359}>Принять требования и продолжить</button>
        </section>}
        {screen === 'profile' && <ProfilePanel profiles={profiles} selectedProfile={selectedProfile} setSelectedProfile={selectProfile} loadManifest={loadManifest} manifest={manifest} componentPreset={settings.componentPreset||""} pinnedPublicKey={settings.pinnedPublicKey} root={settings.gameDirectory} transferBusy={transferBusy} installSelection={installComponentSelection0247} />}
        {screen === 'download' && manifest && <ConflictPreservation0359 manifest={manifest} root={settings.gameDirectory} pinnedPublicKey={settings.pinnedPublicKey} preset={settings.componentPreset||''} transferBusy={transferBusy} />}
        {screen === 'download' && <DownloadPanel locale0357={ui0357.locale} files={files} download={download} downloadProgress={downloadProgress} transferBusy={transferBusy} pendingJob={pendingJob} transferFailure={transferFailure0354} controlTransfer={controlTransfer} resumeTransfer={resumeTransfer} repairResult={repairResult} cleanResult={cleanResult} verifyFiles={verifyFiles} downloadFiles={downloadFiles} repairClient={repairClient} rollbackClientRelease={rollbackClientRelease} cleanUnusedFiles={cleanUnusedFiles} fileSummary={fileSummary} />}
        {screen === 'migration' && <PlayerMigration0339
          manifest={manifest} pinnedPublicKey={settings.pinnedPublicKey}
          componentPreset={settings.componentPreset || ''} transferBusy={transferBusy}
          applyDisplayPreferences={async (suggestion) => {
            const next = normalizedSettings({ ...settings, projectId: selectedProject || settings.projectId,
              profileId: selectedProfile || settings.profileId,
              ...(suggestion.fullscreen != null ? { fullscreen: suggestion.fullscreen } : {}),
              ...(suggestion.screenWidth != null ? { screenWidth: suggestion.screenWidth } : {}),
              ...(suggestion.screenHeight != null ? { screenHeight: suggestion.screenHeight } : {}),
            });
            await callTauri('save_desktop_config', { config: next });
            setSettings(next);
          }}
          onAdopted={() => { log('Проверенные файлы прежней установки добавлены в content cache.'); void verifyFiles(); }}
        />}
        {screen === 'settings' && <SettingsPanel locale0357={ui0357.locale} settings={settings} patchSettings={patchSettings} validateSettings={validateSettings} settingsCheck={settingsCheck} checkJavaRuntime={checkJavaRuntime} javaInfo={javaInfo} openGameDirectory={openGameDirectory} manifest={manifest} profileServers={profileServers} loadProfileServers={loadProfileServers} loadCachedOfflineManifest={loadCachedOfflineManifest} cacheSignedManifest={cacheSignedManifest} offlineStatus0358={offlineStatus0358} minecraftIdentity={minecraftIdentity} setMinecraftIdentity={setMinecraftIdentity} />}
        {screen === 'extensions' && <DesktopExtensions0209 backendUrl={settings.backendUrl} token={authSession?.accessToken ?? ''} projectId={selectedProject || settings.projectId} gameDirectory={settings.gameDirectory} log={log} />}
        {screen === 'logs' && <LogsPanel logs={logs} launchPlan={launchPlan} launchResult={launchResult} launchHistory={launchHistory} refreshLaunchHistory={refreshLaunchHistory} stopRuntimeProcess={stopRuntimeProcess} />}
        {screen === 'diagnostics' && <DiagnosticsPanel previewDiagnostics={previewDiagnostics03510} exportDiagnostics={exportDiagnostics03510} submitDiagnostics={submitDiagnostics03510} preview={diagnosticPreview03510} consent={diagnosticConsent03510} setConsent={setDiagnosticConsent03510} busy={diagnosticBusy03510} status={diagnosticStatus03510} signedIn={!!authSession?.accessToken} />}
        </React.Suspense>
      </section>
    </main>
    </>
  );
}


function FirstRunSigned0352({locale0357,provisioning:p,settings,session,busy,transferBusy,step,error,manifest,servers,progress,onLogin,onPrepare,onInstall,onPlay,onServer,onPreset,onComponents}:any){
  const cat:ComponentCatalog|undefined=manifest?.componentCatalog;
  const presets=cat?.presets||[];
  const t=tr0357((locale0357||'ru') as Locale0357);
  return <section className="panel" aria-label={t.firstRun}>
    <h3>{p.displayName} — {t.firstRun}</h3>
    <p>{t.firstRunLead}</p>
    <p><strong>{t.firstRunProject}:</strong> {p.projectId} · <strong>{t.firstRunProfile}:</strong> {p.profileId} · <strong>{t.firstRunChannel}:</strong> {p.channel}</p>
    <ol className="firstRunSteps0352"><li>{t.firstRunSteps[0]}</li><li>{t.firstRunSteps[1]} — {session?t.done:t.need}</li><li>{t.firstRunSteps[2]} — {step==='start'?t.pending:t.verified}</li><li>{t.firstRunSteps[3]} — {step==='select'?t.available:step==='complete'?t.done:t.pending}</li><li>{t.firstRunSteps[4]} — {step==='complete'?t.done:t.unverified}</li><li>{t.firstRunSteps[5]}</li></ol>
    {error&&<p role="alert" className="firstRunError0352">{error}</p>}
    <div className="toolbar inline">
      {!session&&<button className="primary" onClick={onLogin}>{t.signIn}</button>}
      {session&&step==='start'&&<button className="primary" disabled={busy} onClick={onPrepare}>{busy?t.checking:t.requirements}</button>}
    </div>
    {session&&step==='select'&&manifest&&<>
      <h4>{t.serverMods}</h4>
      <div className="settings"><label>{t.serverLabel}<select value={settings.serverId||''} disabled={Boolean(p.serverId)} onChange={e=>onServer(e.target.value)}><option value="">{t.noAuto}</option>{servers.map((server:ScopedServer)=><option key={server.id} value={server.id}>{server.name}</option>)}</select></label>
      <label>{t.modPreset}<select value={settings.componentPreset||''} onChange={e=>onPreset(e.target.value)}><option value="">{t.defaultPreset}</option>{presets.map((pr:{id:string;name:string})=><option key={pr.id} value={pr.id}>{pr.name}</option>)}</select></label></div>
      <p>{manifest.minecraft.version} · {manifest.minecraft.loader} · {manifest.files.length} файлов. Фактические зависимости и конфликты проверит NeverRuntime перед установкой.</p>
      <div className="toolbar inline"><button onClick={onComponents}>{t.detailMods}</button><button className="primary" disabled={busy||transferBusy} onClick={onInstall}>{busy||transferBusy?t.installing:t.install}</button></div>
      {progress&&<div role="status"><p>{progress.phase}: {progress.completed+progress.skipped} из {progress.totalFiles} файлов</p><progress max={Math.max(progress.totalFiles,1)} value={progress.completed+progress.skipped} /></div>}
    </>}
    {step==='complete'&&<div><h4>{t.installed}</h4><p>{t.installedDetail}</p><button className="primary" onClick={onPlay}>{t.play}</button></div>}
  </section>;
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

function AuthPanel({ email, setEmail, password, setPassword, session, deviceKey, deviceTrustStatus, managedDevices, checkBackend, loginDesktop, refreshDesktopSession, logoutDesktop, restoreSession, refreshDeviceKeyStatus, loadManagedDevices, renameManagedDevice, revokeManagedDevice, revokeOtherManagedDevices, replaceDesktopDeviceKey, macOSTrust0316, authProviders0293, routing0293, selectedAuthProvider0293, setSelectedAuthProvider0293, authProviderError0293, setAuthProviderError0293, linkedProvider0293, setLinkedProvider0293, linkedIdentifier0293, setLinkedIdentifier0293, linkedPassword0293, setLinkedPassword0293, linkFeedback0293, setLinkFeedback0293, linkPasswordProvider0293 }: any) {
  return <section className="panel"><h3>Вход, сессия и Device Management</h3><p>NeverLauncher {DESKTOP_VERSION} регистрирует отдельную device identity, подтверждает владение ключом и для hardware P-256 выполняет challenge-response proof-of-possession (это НЕ удалённая TPM attestation). Стандартный профиль доступен с подтверждённым устройством и сессией; строгий профиль требует верифицированного аппаратного происхождения и Guard evidence и не выдаётся без независимо проверенного Guard evidence. В этой версии revoke необратим для старого ключа: Backend отзывает связанные Never/refresh/Minecraft-сессии, инвалидирует незавершённые device challenges и ServerBridge joins. Повторное подключение отозванной установки требует нового device key.</p><div className="settings"><label>Электронная почта / идентификатор<input value={email} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setEmail(event.target.value)} /></label><label>Пароль<input type="password" value={password} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setPassword(event.target.value)} /></label><label>Провайдер авторизации<select value={selectedAuthProvider0293} onChange={(event: React.ChangeEvent<HTMLSelectElement>) => setSelectedAuthProvider0293(event.target.value)}><option value="">Автоматический выбор (правила Backend)</option>{authProviders0293.filter((item: AuthProvider0293) => item.capabilities.includes('password-auth')).map((item: AuthProvider0293) => <option key={item.id} value={item.id} disabled={!item.healthy}>{item.displayName} ({item.id}){!item.healthy ? ' — недоступен' : ''}</option>)}</select></label></div><p>Маршрутизация: default={routing0293.defaultProvider || 'не задан'}, {routing0293.requireExplicitProvider ? 'неизвестный идентификатор требует явного провайдера' : 'fallback при ошибке авторизации запрещён'}. {authProviderError0293}</p><div className="toolbar inline"><button onClick={checkBackend}>Проверить Backend</button><button onClick={() => loginDesktop().catch((error: Error) => { setAuthProviderError0293(String(error)); console.error(error); })}>Войти</button><button onClick={() => refreshDesktopSession().catch((error: Error) => console.error(error))}>Обновить сессию</button><button onClick={() => logoutDesktop().catch((error: Error) => console.error(error))}>Выйти</button><button onClick={restoreSession}>Проверить восстановление сессии</button><button onClick={() => refreshDeviceKeyStatus().catch((error: Error) => console.error(error))}>Проверить device key</button>{session && <button onClick={() => loadManagedDevices().catch((error: Error) => console.error(error))}>Обновить устройства</button>}{session && deviceKey?.deviceId && <button onClick={() => replaceDesktopDeviceKey('rotate').catch((error: Error) => console.error(error))}>Ротировать ключ</button>}{session && <button onClick={() => replaceDesktopDeviceKey('recover').catch((error: Error) => console.error(error))}>Восстановить ключ</button>}{session && <button className="danger" onClick={() => revokeOtherManagedDevices().catch((error: Error) => console.error(error))}>Отозвать остальные</button>}</div>{session && <div className="settings"><h4>Привязать внешний password provider</h4><p>Необходима активная Never-сессия и свежая проверка внешнего пароля; email сам по себе не подтверждает владение identity.</p><label>Provider<select value={linkedProvider0293} onChange={(event: React.ChangeEvent<HTMLSelectElement>) => setLinkedProvider0293(event.target.value)}><option value="">Выберите провайдера</option>{authProviders0293.filter((item: AuthProvider0293) => item.id !== 'local' && item.capabilities.includes('password-auth') && item.healthy).map((item: AuthProvider0293) => <option key={item.id} value={item.id}>{item.displayName} ({item.id})</option>)}</select></label><label>Внешний идентификатор<input value={linkedIdentifier0293} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setLinkedIdentifier0293(event.target.value)} /></label><label>Пароль внешнего провайдера<input type="password" value={linkedPassword0293} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setLinkedPassword0293(event.target.value)} /></label><button onClick={() => linkPasswordProvider0293().catch((error: Error) => { setLinkedPassword0293(''); setLinkFeedback0293(String(error)); })}>Подтвердить и связать</button><p role="status">{linkFeedback0293}</p></div>}{macOSTrust0316 && <p role="status">macOS Device Trust: Secure Enclave — {macOSTrust0316.localSecureEnclave}; App Attest — {macOSTrust0316.appAttest}; remote provenance — {macOSTrust0316.remoteDeviceKeyProvenance}; strict — {macOSTrust0316.strictProfile}. При утрате ключа используйте восстановление через passkey; оно отзывает прежнюю identity и требует повторной аттестации нового ключа. Локальные сигналы не доказывают серверу происхождение ключа.</p>}<pre>{JSON.stringify({ session: session ? { email: session.email, userId: session.userId, sessionId: session.sessionId, status: 'активна', refreshToken: 'скрыт' } : null, deviceTrust: deviceTrustStatus, deviceKey: deviceKey ? { deviceId: deviceKey.deviceId ?? null, fingerprint: deviceKey.fingerprint, algorithm: deviceKey.keyAlgorithm, keyBinding: deviceKey.keyBinding, hardwareProvider: deviceKey.hardwareProvider || null, hardwareBound: deviceKey.hardwareBound, storageBackend: deviceKey.storageBackend, privateKeyExposedToFrontend: deviceKey.privateKeyExposedToFrontend } : null }, null, 2)}</pre>{session && <div className="deviceList">{managedDevices.map((device: ManagedDevice) => <article className={`deviceCard ${device.current ? 'currentDevice' : ''}`} key={device.id}><div><strong>{device.name}{device.current ? ' · текущее' : ''}</strong><span>{device.status} · {device.keyAlgorithm}/{device.keyBinding}{device.hardwareProvider ? ` · ${device.hardwareProvider}` : ''}</span><small>{device.platform || 'platform n/a'} · {device.clientVersion || 'version n/a'} · last seen: {device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleString() : '—'}</small><small>fingerprint: {device.keyFingerprint.slice(0, 20)}… · attestation: {device.attestationState || 'unattested'}</small><small>Device Trust: standard <strong>{device.trustAssessment?.profileDecisions?.standard?.result ?? 'unknown'}</strong> · strict <strong>{device.trustAssessment?.profileDecisions?.strict?.result ?? 'unknown'}</strong> · remote provenance {device.trustAssessment?.remoteHardwareProvenance ?? 'not-verified'}</small><small>Strict profile: {device.trustAssessment?.profileDecisions?.strict?.reasonCodes?.join(', ') || 'нет проверенного заключения'} · восстановление: {device.trustAssessment?.profileDecisions?.strict?.recoveryAction ?? 'не определено'}</small>{device.status === 'revoked' && <small>revoked: {device.revokedAt ? new Date(device.revokedAt).toLocaleString() : '—'} · {device.revokedReason || 'reason n/a'}{device.replacedByDeviceId ? ` · replaced by ${device.replacedByDeviceId}` : ''}</small>}</div>{device.status === 'active' && <div className="deviceActions"><button onClick={() => renameManagedDevice(device).catch((error: Error) => console.error(error))}>Переименовать</button><button className="danger" onClick={() => revokeManagedDevice(device).catch((error: Error) => console.error(error))}>{device.current ? 'Отозвать текущее' : 'Отозвать'}</button></div>}</article>)}</div>}</section>;
}

function ActionPanel({ title, description, actions }: { title: string; description: string; actions: [string, () => void | Promise<void>][] }) {
  return <section className="panel"><h3>{title}</h3><p>{description}</p><div className="toolbar inline">{actions.map(([label, action]) => <button key={label} onClick={action}>{label}</button>)}</div></section>;
}

function ProjectPanel({ projects, selectedProject, setSelectedProject, loadProjects, loadProfiles }: any) {
  return <section className="panel"><h3>Проекты</h3><p>Список проектов загружается из Backend API.</p><div className="toolbar inline"><button onClick={loadProjects}>Загрузить проекты</button><button onClick={() => loadProfiles(selectedProject)}>Загрузить профили</button></div><div className="list">{projects.map((project: BackendProject) => <button key={project.id} className={selectedProject === project.id ? 'row activeRow' : 'row'} onClick={() => setSelectedProject(project.id)}><strong>{project.title ?? project.name ?? project.id}</strong><span>{project.id}</span></button>)}</div></section>;
}

function ProfilePanel({profiles,selectedProfile,setSelectedProfile,loadManifest,manifest,componentPreset,pinnedPublicKey,root,transferBusy,installSelection}:any){
  const cat:ComponentCatalog|undefined=manifest?.componentCatalog;
  return <section className="panel"><h3>Профиль и компоненты</h3><div className="toolbar inline"><button onClick={loadManifest}>Загрузить манифест</button></div>
    <div className="list">{profiles.map((profile:BackendProfile)=><button key={profile.id} className={selectedProfile===profile.id?'row activeRow':'row'} onClick={()=>setSelectedProfile(profile.id)}><strong>{profile.title??profile.name??profile.id}</strong><span>{profile.loader??'vanilla'}</span></button>)}</div>
    {manifest&&cat&&<>
      <ComponentChooser0247 manifest={manifest} componentPreset={componentPreset} pinnedPublicKey={pinnedPublicKey} root={root} transferBusy={transferBusy} installSelection={installSelection} topologyLabel={(c)=>componentTopologyLabel(cat,c as CatalogComponent)}/>
      <ComponentPortability02410 manifest={manifest} root={root} pinnedPublicKey={pinnedPublicKey} transferBusy={transferBusy} installSelection={installSelection}/>
    </>}
    <pre>{manifest?JSON.stringify({projectId:manifest.projectId,profileId:manifest.profileId,version:manifest.version,files:manifest.files.length,catalogDigest:cat?.digest},null,2):'Манифест не загружен.'}</pre>
  </section>;
}

function ConflictPreservation0359({manifest,root,pinnedPublicKey,preset,transferBusy}:
  {manifest:Manifest;root:string;pinnedPublicKey:string;preset:string;transferBusy:boolean}){
  const [preview,setPreview]=useState<PlayerConflictResult0359|null>(null);
  const [error,setError]=useState('');
  const [busy,setBusy]=useState(false);
  const [archive,setArchive]=useState('');
  async function refresh(){
    setError('');
    const result=await callTauri<PlayerConflictResult0359>('preview_player_conflicts_0359',{
      manifest,root,pinnedPublicKey,preset:preset||null,
    });
    setPreview(result);
  }
  useEffect(()=>{let active=true;
    setPreview(null);setArchive('');setError('');
    callTauri<PlayerConflictResult0359>('preview_player_conflicts_0359',{
      manifest,root,pinnedPublicKey,preset:preset||null,
    }).then(r=>{if(active)setPreview(r);}).catch(e=>{if(active)setError(String(e));});
    return ()=>{active=false;};
  },[manifest,root,pinnedPublicKey,preset]);
  async function preserve(){
    if(!preview?.files.length||busy||transferBusy)return;
    setBusy(true);setError('');
    try {
      const result=await callTauri<PlayerConflictResult0359>('preserve_player_conflicts_0359',{
        manifest,root,pinnedPublicKey,preset:preset||null,expected:preview.files,
      });
      setArchive(result.archiveDirectory||'');
      await refresh();
    }catch(e){setError(String(e));}
    finally{setBusy(false);}
  }
  return <section className="panel" aria-label="Сохранение пользовательских файлов">
    <h3>Пользовательские файлы при обновлении</h3>
    {preview===null&&!error&&<p role="status">Проверка конфликтов с подписанной сборкой…</p>}
    {preview?.files.length===0&&<p>Новый релиз не занимает пути существующих пользовательских файлов.</p>}
    {preview&&preview.files.length>0&&<>
      <p role="alert">Подписанный релиз использует {preview.files.length} путей с файлами игрока. Автоматическая установка заблокирована до их сохранения.</p>
      <ul>{preview.files.map(f=><li key={f.path}>{f.path} — {f.size} байт · SHA-256 {f.sha256.slice(0,16)}…</li>)}</ul>
      <p>После подтверждения файлы перемещаются в отдельный каталог с индексом и контрольными суммами. Они не удаляются.</p>
      <button className="primary" disabled={transferBusy||busy} onClick={()=>void preserve()}>{busy?'Сохранение…':'Сохранить файлы отдельно'}</button>
    </>}
    <button disabled={transferBusy||busy} onClick={()=>void refresh().catch(e=>setError(String(e)))}>Обновить список</button>
    {archive&&<p role="status">Файлы сохранены в {archive}. Теперь можно устанавливать обновление.</p>}
    {error&&<p role="alert">{error}</p>}
  </section>;
}

function DownloadPanel({ locale0357, files, download, downloadProgress, transferBusy, repairResult, cleanResult,
  verifyFiles, downloadFiles, repairClient, rollbackClientRelease, cleanUnusedFiles, fileSummary,
  pendingJob, controlTransfer, resumeTransfer, transferFailure }: any) {
  const progress = progress0354(downloadProgress as DownloadProgress | null);
  const t=tr0357((locale0357||'ru') as Locale0357);
  const native = downloadProgress as DownloadProgress | null;
  const handled = native ? native.completed + native.failed + native.skipped : 0;
  const total = native?.totalFiles || 0;
  const failure = transferFailure as Recovery0354 | null;
  const canCancel = !transferBusy || (progress?.canInterrupt ?? true);
  const retry = () => pendingJob ? resumeTransfer() : downloadFiles();
  return <section className="panel">
    <h3>{t.downloadsTitle}</h3>
    <p>{t.downloadsLead}</p>
    <div className="toolbar inline">
      <button disabled={transferBusy} onClick={verifyFiles}>{t.verifyFiles}</button>
      <button disabled={transferBusy} onClick={downloadFiles}>{t.downloadMissing}</button>
      <button disabled={transferBusy} onClick={repairClient}>{t.repairFiles}</button>
      <button disabled={transferBusy} onClick={rollbackClientRelease}>{t.rollbackFiles}</button>
      <button disabled={transferBusy} onClick={cleanUnusedFiles}>{t.quarantine}</button>
      {transferBusy && (progress?.canInterrupt ?? true) && <button onClick={() => controlTransfer('pause')}>{t.pause}</button>}
      {(transferBusy || pendingJob) && <button disabled={!canCancel} onClick={() => controlTransfer('cancel')}>{t.cancel}</button>}
      {!transferBusy && pendingJob && <button onClick={resumeTransfer}>{t.resume}</button>}
    </div>
    {pendingJob && <p role="status">Сохранённое задание: {pendingJob.projectId}/{pendingJob.profileId} · {pendingJob.status === 'paused' ? 'на паузе' : pendingJob.status === 'pending' ? 'ожидает повтора' : 'в процессе'} · {pendingJob.totalFiles} файлов.</p>}
    {progress && <div className="transferStatus">
      <h4 role="status" aria-live="polite">{progress.label}</h4>
      <progress style={{width:'100%'}} max={100} value={progress.percent} aria-label={t.verifiedBytes} />
      <p><strong>{progress.percent}%</strong> подтверждено по SHA-256 · {progress.verified} из {progress.expected} · обработано файлов {handled}/{total}</p>
      <div className="transferMetrics">
        <span>{t.speed}: <strong>{progress.speed}</strong></span>
        <span>{t.remaining}: <strong>{progress.eta}</strong></span>
        <span>{t.network}: <strong>{progress.received}</strong></span>
        <span>{t.cache}: <strong>{native?.cacheHits || 0} файлов</strong></span>
      </div>
      {native?.currentFile && <p>{t.currentFile}: <code>{native.currentFile}</code></p>}
      {native?.phase === 'publishing' && <p>{t.publishing}</p>}
    </div>}
    {failure && <div className="transferFailure" role="alert">
      <h4>{failure.title}</h4>
      <p>{failure.explanation}</p>
      <p><strong>{t.recommended}:</strong> {failure.instruction}</p>
      {failure.action === 'retry' && <button disabled={transferBusy} onClick={retry}>{t.retry}</button>}
      {failure.action === 'repair' && <button disabled={transferBusy} onClick={repairClient}>{t.repairFiles}</button>}
    </div>}
    {download && <p>Последняя операция: скачано {download.downloaded}, пропущено {download.skipped}, ошибок {download.failed}. {download.failed ? 'Требуется повтор или восстановление.' : ''}</p>}
    <p>Исправно: {fileSummary.ok}; проблем: {fileSummary.broken}; всего: {fileSummary.total}.</p>
    {repairResult && <p>Восстановление: {repairResult.message}</p>}
    {cleanResult && <details><summary>Результаты очистки</summary><pre>{JSON.stringify(cleanResult,null,2)}</pre></details>}
    {files.some((f:FileCheckResult) => f.status !== 'ok') && <details><summary>Проблемные файлы</summary><ul>{files.filter((f:FileCheckResult) => f.status !== 'ok').slice(0,30).map((f:FileCheckResult)=><li key={f.path}>{f.path}: {f.status}</li>)}</ul></details>}
  </section>;
}

function SettingsPanel({ locale0357, settings, patchSettings, validateSettings, settingsCheck, checkJavaRuntime, javaInfo, openGameDirectory, manifest, profileServers, loadProfileServers, loadCachedOfflineManifest, cacheSignedManifest, offlineStatus0358, minecraftIdentity, setMinecraftIdentity }: any) {
  const t = tr0357((locale0357 || 'ru') as Locale0357);
  return <section className="panel"><h3>{t.settingsTitle}</h3>
    <div className="settings">
      <label>{t.java}<input value={settings.javaPath} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('javaPath', e.target.value)} placeholder="auto / managed Java" /></label>
      <label>{t.memory}<input type="number" min={Math.max(512, manifest?.runtime.memory?.minimumMb || 512)} max={Math.min(32768, manifest?.runtime.memory?.maximumMb || 32768)} value={settings.memoryMb} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('memoryMb', Number(e.target.value))} /></label>
      <label>{t.width}<input type="number" min={640} max={7680} value={settings.screenWidth} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('screenWidth', Number(e.target.value))} /></label>
      <label>{t.height}<input type="number" min={480} max={4320} value={settings.screenHeight} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('screenHeight', Number(e.target.value))} /></label>
      <label className="checkSetting"><input type="checkbox" checked={settings.fullscreen} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('fullscreen', e.target.checked)} /> {t.fullscreen}</label>
      <label className="checkSetting"><input type="checkbox" checked={settings.autoEnter} disabled={minecraftIdentity === 'offline'} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('autoEnter', e.target.checked)} /> {t.autoEnter}</label>
      <label>{t.server}<select value={settings.serverId || ''} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => patchSettings('serverId', e.target.value)}><option value="">{t.noServer}</option>{profileServers.map((server: ScopedServer) => <option value={server.id} key={server.id}>{server.name} ({server.kind})</option>)}</select></label>
      {settings.autoEnter && <><label>{t.host}<input value={settings.serverHost} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('serverHost', e.target.value)} placeholder="mc.example.org" /></label><label>{t.port}<input type="number" min={1} max={65535} value={settings.serverPort} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('serverPort', Number(e.target.value))} /></label></>}
      <label className="checkSetting"><input type="checkbox" checked={minecraftIdentity === 'offline'} disabled={!manifest?.runtime.launch?.offlineMode} onChange={(e: React.ChangeEvent<HTMLInputElement>) => {if(e.target.checked){void loadCachedOfflineManifest();}else{setMinecraftIdentity('local');patchSettings('offlineEnabled',false);}}} /> {t.offline}</label>
      <label className="checkSetting"><input type="checkbox" checked={Boolean(settings.sentryDiagnosticsEnabled)} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('sentryDiagnosticsEnabled', e.target.checked)} /> {t.sentry}</label>
      <label className="checkSetting"><input type="checkbox" checked={Boolean(settings.discordPresenceEnabled)} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('discordPresenceEnabled', e.target.checked)} /> {t.discord}</label>
      {settings.discordPresenceEnabled && <>
        <label>Discord Application ID<input value={settings.discordApplicationId || ''} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('discordApplicationId', e.target.value)} placeholder="123456789012345678" /></label>
        <label>Ссылка кнопки активности (HTTPS, необязательно)<input value={settings.discordActionUrl || ''} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('discordActionUrl', e.target.value)} placeholder="https://example.org" /></label>
      </>}
      <label>{t.key}<input value={settings.pinnedPublicKey} onChange={(e: React.ChangeEvent<HTMLInputElement>) => patchSettings('pinnedPublicKey', e.target.value)} /></label>
    </div>
    <div className="toolbar inline"><button onClick={validateSettings}>{t.validate}</button><button onClick={checkJavaRuntime}>{t.checkJava}</button><button onClick={openGameDirectory}>{t.openDir}</button><button onClick={() => loadProfileServers().catch(console.error)}>{t.updateServers}</button><button onClick={() => cacheSignedManifest().catch(console.error)}>{t.saveCache}</button><button onClick={loadCachedOfflineManifest}>{t.loadCache}</button></div>
    <p role="status" aria-live="polite">{offlineStatus0358}</p>
    <p>Server browser показывает узлы ServerBridge, а не игровые DNS-адреса. Для auto-enter укажите публичный адрес выбранного сервера. Offline не выдаёт серверные сессии и требует локальный проверенный Manifest и файлы.</p>
    <pre>{settingsCheck ? JSON.stringify(settingsCheck, null, 2) : javaInfo ? JSON.stringify(javaInfo, null, 2) : 'Настройки ещё не проверены.'}</pre>
  </section>;
}

function LogsPanel({ logs, launchPlan, launchResult, launchHistory, refreshLaunchHistory, stopRuntimeProcess }: any) {
  return <section className="grid two"><article className="panel"><h3>План запуска</h3><pre>{launchPlan?.commandPreview ?? 'План запуска ещё не собран.'}</pre>{launchPlan?.deterministicSha256 && <small>Resolved plan SHA-256: <code>{launchPlan.deterministicSha256}</code></small>}</article><article className="panel"><h3>Результат запуска</h3><p>{launchResult?.message ?? 'Запуск ещё не выполнялся.'}</p><small>{launchResult?.logPath ?? 'Лог появится после запуска.'}</small><div className="toolbar inline"><button onClick={refreshLaunchHistory}>Обновить историю запусков</button>{launchResult && ['running', 'stopping'].includes(launchResult.state) && <button onClick={stopRuntimeProcess}>Остановить процесс</button>}</div></article><article className="panel"><h3>История запусков</h3><pre>{JSON.stringify(launchHistory, null, 2)}</pre></article><article className="panel wide"><h3>Журнал лаунчера</h3><ul>{logs.map((entry: string) => <li key={entry}>{entry}</li>)}</ul></article></section>;
}

function DiagnosticsPanel({ previewDiagnostics, exportDiagnostics, submitDiagnostics, preview, consent, setConsent, busy, status, signedIn }: any) {
  return <section className="panel" aria-label="Диагностика и поддержка">
    <h3>Диагностика и поддержка</h3>
    <p>Нативный процесс преобразует журналы в категории событий. Исходные тексты журналов, токены, пути, имена пользователей и URL не входят в пакет. Никакой отчёт не отправляется автоматически.</p>
    <button disabled={busy} onClick={previewDiagnostics}>Сформировать предпросмотр</button>
    {preview && <>
      <h4>Состав пакета перед отправкой</h4>
      <pre aria-label="Предпросмотр обезличенного отчёта">{JSON.stringify(preview.report,null,2)}</pre>
      <div className="toolbar inline"><button disabled={busy} onClick={exportDiagnostics}>Сохранить пакет локально</button></div>
      <label className="checkSetting"><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)} /> Я проверил(а) указанные поля и разрешаю отправить именно этот отчёт в поддержку владельца проекта.</label>
      <button disabled={busy||!signedIn||!consent} onClick={submitDiagnostics}>Отправить в поддержку</button>
      {!signedIn && <p>Для отправки войдите в аккаунт. Локальный экспорт доступен без входа.</p>}
    </>}
    {status && <p role="status" aria-live="polite">{status}</p>}
  </section>;
}

// The idle prewarm is not part of the critical authentication/render path.
prewarmDesktop03011();
ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(<App />);

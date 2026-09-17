import React, { useEffect, useMemo, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { invoke } from '@tauri-apps/api/core';
import './styles.css';

type Stage = 'idle' | 'connecting' | 'session' | 'project' | 'profile' | 'manifest' | 'java' | 'files' | 'repair' | 'cleanup' | 'ready' | 'launching' | 'running' | 'failed';
type Screen = 'firstRun' | 'overview' | 'auth' | 'projects' | 'profile' | 'download' | 'settings' | 'logs' | 'diagnostics';

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
  serverId?: string;
  configPath?: string;
};

type ManifestFile = { path: string; size: number; sha256: string; url: string; required: boolean; executable?: boolean };
type Manifest = {
  schemaVersion: string;
  projectId: string;
  profileId: string;
  channel: string;
  version: string;
  minecraft: { version: string; loader: string; mainClass?: string; gameArgs?: string[] };
  runtime: {
    java: { majorVersion: number; distribution: string; allowCustomPath?: boolean };
    jvmArgs?: string[];
    memory?: { minimumMb: number; recommendedMb: number; maximumMb: number };
    launch?: { mainClass?: string; classpathStrategy?: string; nativesDirectory?: string; offlineMode?: boolean };
  };
  files: ManifestFile[];
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
type DownloadResult = { downloaded: number; skipped: number; failed: number; repaired?: number; bytesDownloaded?: number; failedFiles?: string[]; messages: string[] };
type LaunchPlan = { javaExecutable: string; workingDirectory: string; mainClass: string; classpathEntries: string[]; jvmArgs: string[]; gameArgs: string[]; commandPreview: string };
type ProcessStatus = { id: string; pid?: number; state: 'running' | 'stopping' | 'exited' | string; startedAt: string; finishedAt?: string; exitCode?: number; success?: boolean; logPath: string; message: string };
type RepairResult = { status: string; before: FileCheckResult[]; download: DownloadResult; after: FileCheckResult[]; repaired: number; message: string };
type CleanUnusedResult = { moved: number; preserved: number; quarantineDir: string; messages: string[] };
type LaunchHistoryEntry = { startedAt: string; projectId: string; profileId: string; version: string; success: boolean; exitCode?: number; logPath: string; message: string };
type BackendProject = { id: string; title?: string; name?: string; homepage?: string; profilesEndpoint?: string };
type BackendProfile = { id: string; title?: string; name?: string; loader?: string; defaultChannel?: string; description?: string };
type DesktopReadiness = { schemaVersion?: string; toolVersion?: string; status?: string; checks?: Record<string, string>; requiredScreens?: string[]; actions?: string[] };
type DesktopDiagnosticsPolicy = { schemaVersion?: string; toolVersion?: string; status?: string; privacyMode?: string; sections?: string[]; export?: Record<string, unknown> };
type DesktopBindingPolicy = { schemaVersion?: string; toolVersion?: string; status?: string; required?: string[]; storage?: Record<string, unknown>; manifestUrlTemplate?: string; checks?: string[] };
type DesktopBindingResult = { status: string; configPath: string; gameDirectory: string; message: string };
type AuthSession = { accessToken: string; refreshToken: string; sessionId: string; email: string; userId: string; expiresAt?: string };
type DeviceKeyInfo = { userId: string; publicKey: string; fingerprint: string; deviceId?: string; createdAtUnix: number; storageBackend: string; keyAlgorithm: string; keyBinding: string; hardwareProvider: string; hardwareBound: boolean; privateKeyExposedToFrontend: boolean };
type DeviceSignatureResult = { fingerprint: string; publicKey: string; signature: string; keyAlgorithm: string; keyBinding: string; hardwareProvider: string; hardwareBound: boolean };
type MinecraftLaunchCredentials = { username: string; uuid: string; accessToken: string; userType: string; authServerBaseUrl: string };

type SettingsCheck = { valid: boolean; status: string; messages: string[]; normalizedGameDirectory: string };
type DiagnosticsExport = { path: string; message: string };

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
    memoryMb: Number(settings.memoryMb || 4096),
  };
}

function App() {
  const [settings, setSettings] = useState<DesktopSettings>(() => loadSettings());
  const [screen, setScreen] = useState<Screen>(settings.backendUrl ? 'overview' : 'firstRun');
  const [stage, setStage] = useState<Stage>('idle');
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [javaInfo, setJavaInfo] = useState<JavaInfoResult | null>(null);
  const [files, setFiles] = useState<FileCheckResult[]>([]);
  const [download, setDownload] = useState<DownloadResult | null>(null);
  const [repairResult, setRepairResult] = useState<RepairResult | null>(null);
  const [cleanResult, setCleanResult] = useState<CleanUnusedResult | null>(null);
  const [launchHistory, setLaunchHistory] = useState<LaunchHistoryEntry[]>([]);
  const [launchPlan, setLaunchPlan] = useState<LaunchPlan | null>(null);
  const [launchResult, setLaunchResult] = useState<ProcessStatus | null>(null);
  const [logs, setLogs] = useState<string[]>([`NeverLauncher Desktop ${DESKTOP_VERSION}: product-клиент ожидает first-run подключение к Backend API.`]);
  const [backendStatus, setBackendStatus] = useState<string>('не проверен');
  const [projects, setProjects] = useState<BackendProject[]>([]);
  const [profiles, setProfiles] = useState<BackendProfile[]>([]);
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

  useEffect(() => {
    callTauri<DesktopSettings>('load_desktop_config')
      .then((config) => {
        const next = normalizedSettings({ ...config, manifestUrl: '' });
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

  function patchSettings(key: keyof DesktopSettings, value: string | number) {
    setSettings((current) => normalizedSettings({ ...current, [key]: value }));
  }

  function selectProject(projectId: string) {
    setSelectedProject(projectId);
    setSelectedProfile('');
    setSettings((current) => normalizedSettings({ ...current, projectId, profileId: '' }));
  }

  function selectProfile(profileId: string) {
    setSelectedProfile(profileId);
    const profile = profiles.find((item) => item.id === profileId);
    setSettings((current) => normalizedSettings({ ...current, profileId, channel: profile?.defaultChannel || current.channel || 'stable' }));
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

  function accessTokenSubject(token: string): string {
    try {
      const part = token.split('.')[1];
      if (!part) return '';
      const normalized = part.replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
      const payload = JSON.parse(atob(padded));
      return typeof payload?.sub === 'string' ? payload.sub : '';
    } catch {
      return '';
    }
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
      const replacement = await callTauri<DeviceKeyInfo>('reset_device_key', { backendUrl: settings.backendUrl, userId: session.userId });
      setDeviceKey(replacement);
      log('Server device record отсутствует или отозван; локальная identity заменена новым ключом в OS secure storage.');
      return registerDesktopDeviceKey(session, replacement);
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
      await ensureDesktopDeviceTrust(next);
    } catch (error) {
      setDeviceTrustStatus('ошибка');
      log(`Device Trust не активирован: ${String(error)}`);
    }
  }

  async function rotateDesktopSession(session: AuthSession): Promise<AuthSession> {
    if (!session.refreshToken) throw new Error('нет refresh token: выполните вход заново');
    const response = await fetch(endpoint('/api/v1/auth/refresh'), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refreshToken: session.refreshToken }),
    });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    const payload = await response.json();
    const next: AuthSession = { ...session, accessToken: payload.data.tokens.accessToken, refreshToken: payload.data.tokens.refreshToken, sessionId: payload.data.session.id, userId: session.userId || accessTokenSubject(payload.data.tokens.accessToken) };
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
      setReadinessContract({ readiness, status, apiVersion: 'v1', runtime: 'NeverRuntime' });
      setDiagnosticsPolicy(diagnostics ?? null);
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
          try { await ensureDesktopDeviceTrust(normalized); } catch (error) { setDeviceTrustStatus('ошибка'); log(`Device Trust при восстановлении не подтверждён: ${String(error)}`); }
        }
      } catch {
        const rotated = await rotateDesktopSession({ ...stored, userId: stored.userId || accessTokenSubject(stored.accessToken) });
        log('Access token истёк; сессия восстановлена через ротацию refresh token из системного хранилища учётных данных.');
        if (rotated.userId) {
          try { await ensureDesktopDeviceTrust(rotated); } catch (error) { setDeviceTrustStatus('ошибка'); log(`Device Trust после refresh не подтверждён: ${String(error)}`); }
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

  async function loadManifest(projectId = selectedProject || settings.projectId, profileId = selectedProfile || settings.profileId) {
    setStage('manifest');
    try {
      const url = buildManifestUrl(projectId, profileId);
      if (!url) throw new Error('сначала выберите проект и профиль');
      const result = await callTauri<Manifest>('load_manifest', { url, pinnedPublicKey: settings.pinnedPublicKey });
      setManifest(result);
      setSelectedProject(result.projectId);
      setSelectedProfile(result.profileId);
      setLaunchPlan(null);
      setLaunchResult(null);
      log(`Манифест загружен: ${result.projectId}/${result.profileId}/${result.version}.`);
      if (!settings.gameDirectory.includes(result.projectId)) {
        setSettings((current) => normalizedSettings({ ...current, gameDirectory: `${current.gameDirectory || './.neverlauncher/projects'}/${result.projectId}/${result.profileId}`, projectId: result.projectId, profileId: result.profileId, channel: result.channel || current.channel }));
      }
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
      const required = activeManifest?.runtime.java.majorVersion ?? 17;
      const distribution = activeManifest?.runtime.java.distribution || 'temurin';
      let result = await callTauri<JavaInfoResult>('check_java', {
        javaPath: settings.javaPath || null,
        requiredMajorVersion: required,
      });
      if (!result.compatible && !settings.javaPath && distribution.toLowerCase() !== 'system') {
        const managed = await callTauri<ManagedJavaResult>('ensure_managed_java', {
          requiredMajorVersion: required,
          distribution,
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
      const result = await callTauri<FileCheckResult[]>('check_files', { manifest, root: settings.gameDirectory });
      setFiles(result);
      const broken = result.filter((file) => file.status !== 'ok').length;
      log(broken === 0 ? 'Файлы клиента проверены.' : `Нужно исправить файлов: ${broken}.`);
    } catch (error) {
      setStage('failed');
      log(`Проверка файлов не выполнена: ${String(error)}`);
    }
  }

  async function repairClient() {
    if (!manifest) {
      log('Восстановление невозможно без манифеста профиля.');
      return;
    }
    setStage('repair');
    try {
      const result = await callTauri<RepairResult>('repair_client', { manifest, root: settings.gameDirectory, pinnedPublicKey: settings.pinnedPublicKey });
      setRepairResult(result);
      setDownload(result.download);
      setFiles(result.after);
      log(`${result.message}: восстановлено ${result.repaired}, скачано ${result.download.downloaded}, ошибок ${result.download.failed}.`);
    } catch (error) {
      setStage('failed');
      log(`Восстановление завершилось ошибкой: ${String(error)}`);
    }
  }

  async function cleanUnusedFiles() {
    if (!manifest) {
      log('Очистка невозможна без манифеста профиля.');
      return;
    }
    setStage('cleanup');
    try {
      const result = await callTauri<CleanUnusedResult>('clean_unused_files', { manifest, root: settings.gameDirectory });
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
      });
      setLaunchPlan(result);
      setStage('ready');
      log('План запуска собран.');
    } catch (error) {
      setStage('failed');
      log(`План запуска не собран: ${String(error)}`);
    }
  }

  async function createMinecraftLaunchSession(): Promise<MinecraftLaunchCredentials> {
    if (!authSession?.accessToken) throw new Error('Для запуска Minecraft требуется активная Never session.');
    const response = await fetch(endpoint('/api/v1/minecraft/session'), {
      method: 'POST',
      headers: { Authorization: `Bearer ${authSession.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ clientToken: `desktop-${authSession.sessionId}` }),
    });
    if (!response.ok) throw new Error(`Не удалось получить Minecraft session: ${response.status} ${response.statusText}`);
    const payload = await response.json();
    const data = payload.data ?? payload;
    if (!data.accessToken || !data.profile?.id || !data.profile?.name) throw new Error('Backend вернул неполную Minecraft session.');
    return { username: data.profile.name, uuid: data.profile.id, accessToken: data.accessToken, userType: 'mojang', authServerBaseUrl: settings.backendUrl.trim().replace(/\/$/, '') };
  }

  async function createServerJoinBeforeLaunch(username: string) {
    if (!authSession?.accessToken || !settings.serverId) {
      log('Создание сессии входа ServerBridge пропущено: нет активной сессии или serverId. Для защищённого сервера заполните serverId в настройках.');
      return;
    }
    const response = await fetch(endpoint('/api/v1/session/join'), {
      method: 'POST',
      headers: { Authorization: `Bearer ${authSession.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, serverId: settings.serverId, projectId: settings.projectId, profileId: settings.profileId, channel: settings.channel }),
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
      const minecraftCredentials = await createMinecraftLaunchSession();
      await createServerJoinBeforeLaunch(minecraftCredentials.username);
      const result = await callTauri<ProcessStatus>('launch_minecraft', {
        manifest,
        root: settings.gameDirectory,
        javaPath: settings.javaPath || null,
        username: minecraftCredentials.username,
        minecraftCredentials,
        pinnedPublicKey: settings.pinnedPublicKey,
      });
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
            ['download', 'Загрузка'], ['settings', 'Настройки'], ['logs', 'Логи'], ['diagnostics', 'Диагностика'],
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
          <button onClick={cleanUnusedFiles}>Очистить лишнее</button>
          <button onClick={buildPlan}>Собрать план запуска</button>
          <button className="primary" onClick={launch}>Играть</button>
          <button onClick={exportDiagnostics}>Экспорт диагностики</button>
        </section>

        <section className="settings compact">
          <label>URL Backend<input value={settings.backendUrl} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('backendUrl', event.target.value)} /></label>
          <label>Переопределение URL манифеста<input value={settings.manifestUrl} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('manifestUrl', event.target.value)} placeholder="обычно пусто: используется /api/v1/projects/{project}/profiles/{profile}/manifest?channel=stable" /></label>
          <label>Каталог игры<input value={settings.gameDirectory} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('gameDirectory', event.target.value)} /></label>
          <label>Имя игрока<input value={settings.username} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('username', event.target.value)} /></label>
          <label>Память, МБ<input type="number" value={settings.memoryMb} min={512} max={32768} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('memoryMb', Number(event.target.value))} /></label>
          <label>Канал<input value={settings.channel} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('channel', event.target.value)} /></label>
        </section>

        {screen === 'firstRun' && <FirstRunPanel settings={settings} patchSettings={patchSettings} bindingPolicy={bindingPolicy} checkBackend={checkBackend} loadProjects={loadProjects} loadProfiles={loadProfiles} persistDesktopConfig={persistDesktopConfig} resetDesktopBinding={resetDesktopBinding} selectedProject={selectedProject} selectedProfile={selectedProfile} /> }
        {screen === 'overview' && <Overview readiness={readiness} backendStatus={backendStatus} manifest={manifest} javaInfo={javaInfo} fileSummary={fileSummary} launchPlan={launchPlan} readinessContract={readinessContract} diagnosticsPolicy={diagnosticsPolicy} />}
        {screen === 'auth' && <AuthPanel email={email} setEmail={setEmail} password={password} setPassword={setPassword} session={authSession} deviceKey={deviceKey} deviceTrustStatus={deviceTrustStatus} checkBackend={checkBackend} loginDesktop={loginDesktop} refreshDesktopSession={refreshDesktopSession} logoutDesktop={logoutDesktop} restoreSession={restoreSession} refreshDeviceKeyStatus={refreshDeviceKeyStatus} />}
        {screen === 'projects' && <ProjectPanel projects={projects} selectedProject={selectedProject} setSelectedProject={selectProject} loadProjects={loadProjects} loadProfiles={loadProfiles} />}
        {screen === 'profile' && <ProfilePanel profiles={profiles} selectedProfile={selectedProfile} setSelectedProfile={selectProfile} loadManifest={loadManifest} manifest={manifest} />}
        {screen === 'download' && <DownloadPanel files={files} download={download} repairResult={repairResult} cleanResult={cleanResult} verifyFiles={verifyFiles} repairClient={repairClient} cleanUnusedFiles={cleanUnusedFiles} fileSummary={fileSummary} />}
        {screen === 'settings' && <SettingsPanel settings={settings} patchSettings={patchSettings} validateSettings={validateSettings} settingsCheck={settingsCheck} checkJavaRuntime={checkJavaRuntime} javaInfo={javaInfo} openGameDirectory={openGameDirectory} />}
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
        <pre>{launchPlan?.commandPreview ?? 'План запуска ещё не собран.'}</pre>
      </section>
    </>
  );
}

function AuthPanel({ email, setEmail, password, setPassword, session, deviceKey, deviceTrustStatus, checkBackend, loginDesktop, refreshDesktopSession, logoutDesktop, restoreSession, refreshDeviceKeyStatus }: any) {
  return <section className="panel"><h3>Вход, сессия и Device Trust</h3><p>NeverLauncher {DESKTOP_VERSION} использует non-exportable P-256 device identity в Secure Enclave/TPM, если доступен hardware backend; иначе явно остаётся на Ed25519 + native OS secure storage. После session-bind hardware key проходит отдельный одноразовый challenge-response attestation с ограниченным freshness window. Private key не передаётся React или Backend; эта проверка подтверждает владение зарегистрированным hardware key, но не выдаёт себя за vendor TPM/Secure Enclave remote provenance.</p><div className="settings"><label>Электронная почта<input value={email} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setEmail(event.target.value)} /></label><label>Пароль<input type="password" value={password} onChange={(event: React.ChangeEvent<HTMLInputElement>) => setPassword(event.target.value)} /></label></div><div className="toolbar inline"><button onClick={checkBackend}>Проверить Backend</button><button onClick={() => loginDesktop().catch((error: Error) => console.error(error))}>Войти</button><button onClick={() => refreshDesktopSession().catch((error: Error) => console.error(error))}>Обновить сессию</button><button onClick={() => logoutDesktop().catch((error: Error) => console.error(error))}>Выйти</button><button onClick={restoreSession}>Проверить восстановление сессии</button><button onClick={() => refreshDeviceKeyStatus().catch((error: Error) => console.error(error))}>Проверить device key</button></div><pre>{JSON.stringify({ session: session ? { email: session.email, userId: session.userId, sessionId: session.sessionId, status: 'активна', refreshToken: 'скрыт' } : null, deviceTrust: deviceTrustStatus, deviceKey: deviceKey ? { deviceId: deviceKey.deviceId ?? null, fingerprint: deviceKey.fingerprint, algorithm: deviceKey.keyAlgorithm, keyBinding: deviceKey.keyBinding, hardwareProvider: deviceKey.hardwareProvider || null, hardwareBound: deviceKey.hardwareBound, storageBackend: deviceKey.storageBackend, privateKeyExposedToFrontend: deviceKey.privateKeyExposedToFrontend } : null }, null, 2)}</pre></section>;
}

function ActionPanel({ title, description, actions }: { title: string; description: string; actions: [string, () => void | Promise<void>][] }) {
  return <section className="panel"><h3>{title}</h3><p>{description}</p><div className="toolbar inline">{actions.map(([label, action]) => <button key={label} onClick={action}>{label}</button>)}</div></section>;
}

function ProjectPanel({ projects, selectedProject, setSelectedProject, loadProjects, loadProfiles }: any) {
  return <section className="panel"><h3>Проекты</h3><p>Список проектов загружается из Backend API.</p><div className="toolbar inline"><button onClick={loadProjects}>Загрузить проекты</button><button onClick={() => loadProfiles(selectedProject)}>Загрузить профили</button></div><div className="list">{projects.map((project: BackendProject) => <button key={project.id} className={selectedProject === project.id ? 'row activeRow' : 'row'} onClick={() => setSelectedProject(project.id)}><strong>{project.title ?? project.name ?? project.id}</strong><span>{project.id}</span></button>)}</div></section>;
}

function ProfilePanel({ profiles, selectedProfile, setSelectedProfile, loadManifest, manifest }: any) {
  return <section className="panel"><h3>Профиль</h3><p>Выберите профиль и загрузите манифест.</p><div className="toolbar inline"><button onClick={loadManifest}>Загрузить манифест</button></div><div className="list">{profiles.map((profile: BackendProfile) => <button key={profile.id} className={selectedProfile === profile.id ? 'row activeRow' : 'row'} onClick={() => setSelectedProfile(profile.id)}><strong>{profile.title ?? profile.name ?? profile.id}</strong><span>{profile.loader ?? 'загрузчик не указан'} · {profile.defaultChannel ?? 'stable'}</span></button>)}</div><pre>{manifest ? JSON.stringify({ projectId: manifest.projectId, profileId: manifest.profileId, version: manifest.version, files: manifest.files.length }, null, 2) : 'Манифест не загружен.'}</pre></section>;
}

function DownloadPanel({ files, download, repairResult, cleanResult, verifyFiles, repairClient, cleanUnusedFiles, fileSummary }: any) {
  return <section className="panel"><h3>Загрузка, восстановление и очистка</h3><p>Проверка SHA-256, восстановление отсутствующих/повреждённых файлов и безопасная очистка через карантин.</p><div className="toolbar inline"><button onClick={verifyFiles}>Проверить файлы</button><button onClick={repairClient}>Восстановить повреждённое</button><button onClick={cleanUnusedFiles}>Переместить лишнее в карантин</button></div><p>Исправно: {fileSummary.ok}; проблем: {fileSummary.broken}; всего: {fileSummary.total}.</p><pre>{JSON.stringify({ download, repair: repairResult ? { status: repairResult.status, repaired: repairResult.repaired, message: repairResult.message } : null, cleanup: cleanResult, files: files.slice(0, 20) }, null, 2)}</pre></section>;
}

function SettingsPanel({ settings, patchSettings, validateSettings, settingsCheck, checkJavaRuntime, javaInfo, openGameDirectory }: any) {
  return <section className="panel"><h3>Настройки запуска</h3><div className="settings"><label>Путь к Java<input value={settings.javaPath} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('javaPath', event.target.value)} placeholder="java" /></label><label>Закреплённый публичный ключ Ed25519<input value={settings.pinnedPublicKey} onChange={(event: React.ChangeEvent<HTMLInputElement>) => patchSettings('pinnedPublicKey', event.target.value)} /></label></div><div className="toolbar inline"><button onClick={validateSettings}>Проверить настройки</button><button onClick={checkJavaRuntime}>Проверить Java</button><button onClick={openGameDirectory}>Открыть каталог клиента</button></div><pre>{settingsCheck ? JSON.stringify(settingsCheck, null, 2) : javaInfo ? JSON.stringify(javaInfo, null, 2) : 'Настройки ещё не проверены.'}</pre></section>;
}

function LogsPanel({ logs, launchPlan, launchResult, launchHistory, refreshLaunchHistory, stopRuntimeProcess }: any) {
  return <section className="grid two"><article className="panel"><h3>План запуска</h3><pre>{launchPlan?.commandPreview ?? 'План запуска ещё не собран.'}</pre></article><article className="panel"><h3>Результат запуска</h3><p>{launchResult?.message ?? 'Запуск ещё не выполнялся.'}</p><small>{launchResult?.logPath ?? 'Лог появится после запуска.'}</small><div className="toolbar inline"><button onClick={refreshLaunchHistory}>Обновить историю запусков</button>{launchResult && ['running', 'stopping'].includes(launchResult.state) && <button onClick={stopRuntimeProcess}>Остановить процесс</button>}</div></article><article className="panel"><h3>История запусков</h3><pre>{JSON.stringify(launchHistory, null, 2)}</pre></article><article className="panel wide"><h3>Журнал лаунчера</h3><ul>{logs.map((entry: string) => <li key={entry}>{entry}</li>)}</ul></article></section>;
}

function DiagnosticsPanel({ exportDiagnostics, readinessContract, diagnosticsPolicy, settingsCheck }: any) {
  return <section className="panel"><h3>Диагностика</h3><p>Экспортирует локальный диагностический пакет без токенов и серверных секретов. Политика берётся из <code>/api/v1/diagnostics/policy</code>.</p><div className="toolbar inline"><button onClick={exportDiagnostics}>Экспортировать диагностический пакет</button></div><pre>{JSON.stringify({ readinessContract, diagnosticsPolicy, settingsCheck }, null, 2)}</pre></section>;
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(<App />);

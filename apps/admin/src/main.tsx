import React, { useEffect, useMemo, useState } from 'react';
import ReactDOM from 'react-dom/client';
import './styles.css';

type ApiEnvelope<T> = { data?: T; error?: { message?: string } };
type Section = { id: string; title: string; endpoint?: string; permission?: string };
type ProductionUIData = { sections?: Section[]; primaryFlow?: string[]; toolVersion?: string };
type LoginResponse = { token?: string; refreshToken?: string; sessionId?: string; user?: Record<string, unknown>; status?: string; transactionToken?: string; publicKey?: PublicKeyCredentialRequestOptionsJSON };
type PublicKeyCredentialRequestOptionsJSON = { challenge: string; rpId?: string; timeout?: number; userVerification?: UserVerificationRequirement; allowCredentials?: Array<{ type: PublicKeyCredentialType; id: string; transports?: AuthenticatorTransport[] }> };
type PublicKeyCredentialCreationOptionsJSON = { challenge: string; rp: PublicKeyCredentialRpEntity; user: { id: string; name: string; displayName: string }; pubKeyCredParams: PublicKeyCredentialParameters[]; timeout?: number; excludeCredentials?: Array<{ type: PublicKeyCredentialType; id: string; transports?: AuthenticatorTransport[] }>; authenticatorSelection?: AuthenticatorSelectionCriteria; attestation?: AttestationConveyancePreference };
type PasskeyBegin = { transactionToken: string; publicKey: PublicKeyCredentialRequestOptionsJSON | PublicKeyCredentialCreationOptionsJSON; expiresInSeconds?: number };
type PasskeySessionResponse = { status?: string; accessToken?: string; session?: { id?: string }; tokens?: { accessToken?: string; refreshToken?: string }; user?: Record<string, unknown> };
type DashboardData = { status?: string; metrics?: Record<string, number>; projects?: any[]; profiles?: any[]; channels?: any[]; users?: any[]; audit?: any[] };
type SessionView = { id: string; device: string; deviceId?: string; provider?: string; status?: string; riskState?: string; lastIp?: string; lastSeenAt?: string; expiresAt?: string; current?: boolean };

type ProjectForm = { id: string; name: string; description: string; homepage: string; repository: string; defaultChannel: string };
type ProfileForm = { projectId: string; id: string; name: string; description: string; loader: string; preset: string; isDefault: boolean };
type ChannelForm = { projectId: string; id: string; name: string; description: string; protected: boolean };
type UserForm = { id: string; email: string; displayName: string; roleId: string; password: string };
type PackageForm = { projectId: string; profileId: string; channel: string; version: string; packageId: string; path: string; sha256: string };

const TOOL_VERSION = __NEVERLAUNCHER_VERSION__;

const fallbackSections: Section[] = [
  { id: 'dashboard', title: 'Обзор' },
  { id: 'projects', title: 'Проекты' },
  { id: 'profiles', title: 'Профили' },
  { id: 'channels', title: 'Каналы' },
  { id: 'packages', title: 'Релизы и файлы' },
  { id: 'releases', title: 'Релизы' },
  { id: 'users', title: 'Пользователи' },
  { id: 'roles', title: 'Роли' },
  { id: 'audit', title: 'Аудит' },
  { id: 'storage', title: 'Хранилище' },
  { id: 'server-bridge', title: 'ServerBridge' },
  { id: 'diagnostics', title: 'Диагностика' },
  { id: 'backup-restore', title: 'Резервное копирование' },
];

const endpointBySection: Record<string, string> = {
  dashboard: '/api/v1/admin/overview',
  projects: '/api/v1/projects',
  profiles: '/api/v1/projects/{projectId}/profiles',
  channels: '/api/v1/projects/{projectId}/channels',
  packages: '/api/v1/projects/{projectId}/versions',
  releases: '/api/v1/projects/{projectId}/versions',
  users: '/api/v1/admin/users',
  roles: '/api/v1/admin/roles',
  audit: '/api/v1/admin/audit',
  storage: '/api/v1/admin/storage/health',
  'server-bridge': '/api/v1/server-bridge/servers',
  diagnostics: '/api/v1/operations/diagnostics',
  'backup-restore': '/api/v1/operations/backup',
};

async function requestJSON<T>(backendUrl: string, path: string, token?: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string> | undefined) };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (init.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${backendUrl.replace(/\/$/, '')}${path}`, { ...init, headers });
  const payload = (await response.json().catch(() => ({}))) as ApiEnvelope<T> | T;
  if (!response.ok) {
    const msg = (payload as ApiEnvelope<T>).error?.message ?? `${response.status} ${response.statusText}`;
    throw new Error(msg);
  }
  if ((payload as ApiEnvelope<T>).data !== undefined) return (payload as ApiEnvelope<T>).data as T;
  return payload as T;
}

function b64urlToBuffer(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function bufferToB64url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value);
  let raw = '';
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function creationOptionsFromJSON(input: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptions {
  return {
    ...input,
    challenge: b64urlToBuffer(input.challenge),
    user: { ...input.user, id: b64urlToBuffer(input.user.id) },
    excludeCredentials: input.excludeCredentials?.map((item) => ({ ...item, id: b64urlToBuffer(item.id) })),
  };
}

function requestOptionsFromJSON(input: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions {
  return {
    ...input,
    challenge: b64urlToBuffer(input.challenge),
    allowCredentials: input.allowCredentials?.map((item) => ({ ...item, id: b64urlToBuffer(item.id) })),
  };
}

async function createPasskeyCredential(input: PublicKeyCredentialCreationOptionsJSON) {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('Этот браузер не поддерживает WebAuthn/passkeys.');
  const credential = await navigator.credentials.create({ publicKey: creationOptionsFromJSON(input) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error('Authenticator не вернул WebAuthn registration credential.');
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
      attestationObject: bufferToB64url(credential.response.attestationObject),
      transports: credential.response.getTransports?.() ?? [],
    },
  };
}

async function getPasskeyAssertion(input: PublicKeyCredentialRequestOptionsJSON) {
  if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('Этот браузер не поддерживает WebAuthn/passkeys.');
  const credential = await navigator.credentials.get({ publicKey: requestOptionsFromJSON(input) });
  if (!(credential instanceof PublicKeyCredential) || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error('Authenticator не вернул WebAuthn assertion.');
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
      authenticatorData: bufferToB64url(credential.response.authenticatorData),
      signature: bufferToB64url(credential.response.signature),
      userHandle: credential.response.userHandle ? bufferToB64url(credential.response.userHandle) : undefined,
    },
  };
}

function MetricCard({ label, value }: { label: string; value: number | string }) {
  return <article className="card"><h3>{label}</h3><div className="metric">{value}</div></article>;
}

function DataTable({ payload }: { payload: Record<string, unknown> | null }) {
  const rows = useMemo(() => Object.entries(payload ?? {}).filter(([key]) => !['schemaVersion', 'toolVersion'].includes(key)), [payload]);
  if (!payload) return <p className="muted">Данные раздела ещё не загружены.</p>;
  return <table className="table"><tbody>{rows.map(([key, value]) => <tr key={key}><th>{key}</th><td><pre>{JSON.stringify(value, null, 2)}</pre></td></tr>)}</tbody></table>;
}

function TextInput({ label, value, onChange, type = 'text' }: { label: string; value: string; onChange: (value: string) => void; type?: string }) {
  return <label className="field"><span>{label}</span><input value={value} type={type} onChange={(event) => onChange(event.target.value)} /></label>;
}

function App() {
  const [backendUrl, setBackendUrl] = useState(localStorage.getItem('neverlauncher.backendUrl') ?? window.location.origin);
  const [token, setToken] = useState(sessionStorage.getItem('neverlauncher.admin.token') ?? '');
  const [refreshToken, setRefreshToken] = useState(sessionStorage.getItem('neverlauncher.admin.refreshToken') ?? '');
  const [sessionId, setSessionId] = useState(sessionStorage.getItem('neverlauncher.admin.sessionId') ?? '');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [mfaPolicy, setMfaPolicy] = useState<'optional' | 'required' | 'phishing-resistant'>('optional');
  const [active, setActive] = useState('dashboard');
  const [productionUI, setProductionUI] = useState<ProductionUIData>({ sections: fallbackSections, toolVersion: TOOL_VERSION });
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [payload, setPayload] = useState<Record<string, unknown> | null>(null);
  const [status, setStatus] = useState('offline');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionView[]>([]);

  const [projectForm, setProjectForm] = useState<ProjectForm>({ id: 'neverlauncher-project', name: 'Проект NeverLauncher', description: 'Production-проект Minecraft', homepage: '', repository: '', defaultChannel: 'stable' });
  const [profileForm, setProfileForm] = useState<ProfileForm>({ projectId: 'neverlauncher-project', id: 'vanilla-java21', name: 'Vanilla Java 21', description: 'Production-профиль клиента', loader: 'vanilla', preset: 'recommended', isDefault: true });
  const [channelForm, setChannelForm] = useState<ChannelForm>({ projectId: 'neverlauncher-project', id: 'stable', name: 'stable', description: 'Стабильный production-канал', protected: true });
  const [userForm, setUserForm] = useState<UserForm>({ id: '', email: 'operator@neverlauncher.local', displayName: 'Оператор', roleId: 'viewer', password: 'Смените-этот-пароль' });
  const [packageForm, setPackageForm] = useState<PackageForm>({ projectId: 'neverlauncher-project', profileId: 'vanilla-java21', channel: 'stable', version: `${TOOL_VERSION}-client`, packageId: '', path: 'mods/example.jar', sha256: '' });
  const [packageFile, setPackageFile] = useState<File | null>(null);

  const sections = productionUI.sections?.length ? productionUI.sections : fallbackSections;
  const selectedProjectId = projectForm.id || profileForm.projectId || channelForm.projectId || 'project-required';
  const activeEndpoint = useMemo(() => {
    if (active === 'profiles') return `/api/v1/projects/${encodeURIComponent(profileForm.projectId || selectedProjectId)}/profiles`;
    if (active === 'channels') return `/api/v1/projects/${encodeURIComponent(channelForm.projectId || selectedProjectId)}/channels`;
    return (endpointBySection[active] ?? '/api/v1/admin/overview').replace('{projectId}', encodeURIComponent(selectedProjectId));
  }, [active, profileForm.projectId, channelForm.projectId, selectedProjectId]);
  const metrics = dashboard?.metrics ?? {};

  useEffect(() => { localStorage.setItem('neverlauncher.backendUrl', backendUrl); }, [backendUrl]);
  useEffect(() => { token ? sessionStorage.setItem('neverlauncher.admin.token', token) : sessionStorage.removeItem('neverlauncher.admin.token'); }, [token]);
  useEffect(() => { refreshToken ? sessionStorage.setItem('neverlauncher.admin.refreshToken', refreshToken) : sessionStorage.removeItem('neverlauncher.admin.refreshToken'); }, [refreshToken]);
  useEffect(() => { sessionId ? sessionStorage.setItem('neverlauncher.admin.sessionId', sessionId) : sessionStorage.removeItem('neverlauncher.admin.sessionId'); }, [sessionId]);

  function applyPasskeySession(data: PasskeySessionResponse, preserveRefresh = false) {
    const nextToken = data.tokens?.accessToken ?? data.accessToken;
    if (!nextToken) throw new Error('Backend не вернул Never access token.');
    setToken(nextToken);
    if (data.tokens?.refreshToken !== undefined) setRefreshToken(data.tokens.refreshToken);
    else if (!preserveRefresh) setRefreshToken('');
    if (data.session?.id) setSessionId(data.session.id);
    setStatus('online');
  }

  async function finishPasskeyMFA(data: LoginResponse) {
    if (!data.transactionToken || !data.publicKey) throw new Error('Backend запросил passkey MFA без WebAuthn transaction.');
    const credential = await getPasskeyAssertion(data.publicKey);
    const completed = await requestJSON<PasskeySessionResponse>(backendUrl, '/api/v1/auth/passkeys/mfa/complete', undefined, { method: 'POST', body: JSON.stringify({ transactionToken: data.transactionToken, deviceId: 'admin-browser', credential }) });
    applyPasskeySession(completed);
    setMessage('Вход завершён passkey MFA. Сессия имеет phishing-resistant authentication strength.');
  }

  async function login() {
    setError(null); setMessage(null);
    const data = await requestJSON<LoginResponse>(backendUrl, '/api/v1/admin/login', undefined, { method: 'POST', body: JSON.stringify({ email, password, totp: totp || undefined, recoveryCode: recoveryCode || undefined }) });
    if (data.status === 'mfa-required') {
      await finishPasskeyMFA(data);
      return;
    }
    if (!data.token) throw new Error('Backend не вернул access token.');
    setToken(data.token);
    setRefreshToken(data.refreshToken ?? '');
    setSessionId(data.sessionId ?? '');
    setStatus('online');
    setMessage(`Вход выполнен: ${String(data.user?.email ?? email)}`);
  }

  async function passwordlessPasskeyLogin() {
    setError(null); setMessage(null);
    const begin = await requestJSON<PasskeyBegin>(backendUrl, '/api/v1/auth/passkeys/login/begin', undefined, { method: 'POST' });
    const credential = await getPasskeyAssertion(begin.publicKey as PublicKeyCredentialRequestOptionsJSON);
    const completed = await requestJSON<PasskeySessionResponse>(backendUrl, '/api/v1/auth/passkeys/login/complete', undefined, { method: 'POST', body: JSON.stringify({ transactionToken: begin.transactionToken, deviceId: 'admin-browser', credential }) });
    applyPasskeySession(completed);
    setMessage('Выполнен passwordless вход по passkey.');
  }

  async function registerPasskey() {
    if (!token) throw new Error('Сначала войдите в NeverLauncher.');
    const begin = await requestJSON<PasskeyBegin>(backendUrl, '/api/v1/auth/passkeys/register/begin', token, { method: 'POST' });
    const credential = await createPasskeyCredential(begin.publicKey as PublicKeyCredentialCreationOptionsJSON);
    const completed = await requestJSON<PasskeySessionResponse>(backendUrl, '/api/v1/auth/passkeys/register/complete', token, { method: 'POST', body: JSON.stringify({ transactionToken: begin.transactionToken, friendlyName: 'Admin browser passkey', credential }) });
    applyPasskeySession(completed, true);
    setMessage('Passkey зарегистрирован и текущая сессия повышена до phishing-resistant.');
  }

  async function stepUpPasskey() {
    if (!token) throw new Error('Сначала войдите в NeverLauncher.');
    const begin = await requestJSON<PasskeyBegin>(backendUrl, '/api/v1/auth/passkeys/step-up/begin', token, { method: 'POST' });
    const credential = await getPasskeyAssertion(begin.publicKey as PublicKeyCredentialRequestOptionsJSON);
    const completed = await requestJSON<PasskeySessionResponse>(backendUrl, '/api/v1/auth/passkeys/step-up/complete', token, { method: 'POST', body: JSON.stringify({ transactionToken: begin.transactionToken, deviceId: 'admin-browser', credential }) });
    applyPasskeySession(completed, true);
    setMessage('Passkey step-up выполнен. Критические операции разблокированы на ограниченное время.');
  }

  async function saveMfaPolicy() {
    if (!token) throw new Error('Сначала войдите в NeverLauncher.');
    const data = await requestJSON<{ requirement?: string }>(backendUrl, '/api/v1/auth/mfa/policy', token, { method: 'PUT', body: JSON.stringify({ requirement: mfaPolicy }) });
    setMfaPolicy((data.requirement as typeof mfaPolicy) ?? mfaPolicy);
    setMessage(`MFA policy сохранена: ${data.requirement ?? mfaPolicy}.`);
  }

  async function refreshSession() {
    if (!refreshToken) throw new Error('refreshToken отсутствует: выполните вход заново');
    const data = await requestJSON<any>(backendUrl, '/api/v1/auth/refresh', undefined, { method: 'POST', body: JSON.stringify({ refreshToken }) });
    setToken(data.tokens.accessToken);
    setRefreshToken(data.tokens.refreshToken);
    setSessionId(data.session.id);
    setMessage('Сессия обновлена, refresh token ротирован сервером.');
  }

  async function logout() {
    if (token) await requestJSON<any>(backendUrl, '/api/v1/admin/logout', token, { method: 'POST' }).catch(() => undefined);
    setToken(''); setRefreshToken(''); setSessionId(''); setDashboard(null); setPayload(null); setMessage('Сессия завершена.');
  }

  async function loadSessions(currentToken = token) {
    if (!currentToken) { setSessions([]); return; }
    const data = await requestJSON<{ items?: SessionView[] }>(backendUrl, '/api/v1/auth/sessions', currentToken);
    setSessions(data.items ?? []);
  }

  async function renameSession(item: SessionView) {
    if (!token) throw new Error('Сначала войдите в NeverLauncher.');
    const nextName = window.prompt('Название устройства', item.device || item.deviceId || 'Устройство');
    if (!nextName) return;
    await requestJSON(backendUrl, `/api/v1/auth/sessions/${encodeURIComponent(item.id)}`, token, { method: 'PATCH', body: JSON.stringify({ device: nextName }) });
    await loadSessions();
    setMessage('Название устройства обновлено.');
  }

  async function revokeSession(item: SessionView) {
    if (!token) throw new Error('Сначала войдите в NeverLauncher.');
    await requestJSON(backendUrl, `/api/v1/auth/sessions/${encodeURIComponent(item.id)}`, token, { method: 'DELETE' });
    if (item.current) { setToken(''); setRefreshToken(''); setSessionId(''); setSessions([]); setMessage('Текущая сессия отозвана.'); return; }
    await loadSessions();
    setMessage('Сессия отозвана.');
  }

  async function revokeOtherSessions() {
    if (!token) throw new Error('Сначала войдите в NeverLauncher.');
    await requestJSON(backendUrl, '/api/v1/auth/sessions/revoke-others', token, { method: 'POST' });
    await loadSessions();
    setMessage('Все остальные сессии отозваны.');
  }

  async function loadDashboard(currentToken = token) {
    const dash = currentToken ? await requestJSON<DashboardData>(backendUrl, '/api/v1/admin/overview', currentToken) : null;
    setProductionUI({ sections: fallbackSections, toolVersion: TOOL_VERSION });
    setDashboard(dash);
    setStatus('online');
  }

  async function loadActive() {
    setError(null); setPayload(null);
    const publicSections = new Set(['platform']);
    if (!token && !publicSections.has(active)) {
      setPayload({ status: 'auth-required', message: `Для этого раздела нужна серверная сессия администратора NeverLauncher ${TOOL_VERSION}.` });
      return;
    }
    const data = await requestJSON<Record<string, unknown>>(backendUrl, activeEndpoint, token || undefined);
    setPayload(data);
  }

  useEffect(() => {
    let cancelled = false;
    loadDashboard().catch((err: Error) => {
      if (!cancelled) { setStatus('offline'); setError(err.message); setProductionUI({ sections: fallbackSections, toolVersion: TOOL_VERSION }); }
    });
    return () => { cancelled = true; };
  }, [backendUrl, token]);

  useEffect(() => {
    let cancelled = false;
    loadActive().catch((err: Error) => { if (!cancelled) setError(err.message); });
    return () => { cancelled = true; };
  }, [backendUrl, active, activeEndpoint, token]);

  async function runAction(label: string, fn: () => Promise<unknown>) {
    setError(null); setMessage(null);
    const result = await fn();
    setMessage(`${label}: выполнено`);
    setPayload(result as Record<string, unknown>);
    await loadDashboard().catch(() => undefined);
  }

  async function createPackage() {
    const result = await requestJSON<any>(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(packageForm.projectId)}/versions`, token, { method: 'POST', body: JSON.stringify({ profileId: packageForm.profileId, channel: packageForm.channel, version: packageForm.version }) });
    const id = result.id ?? '';
    setPackageForm((current) => ({ ...current, packageId: id }));
    return result;
  }

  async function uploadPackageFile() {
    if (!packageForm.packageId) throw new Error('Сначала создайте пакет и получите его ID.');
    if (!packageFile) throw new Error('Выберите файл для загрузки.');
    const body = new FormData();
    body.append('path', packageForm.path || packageFile.name);
    if (packageForm.sha256) body.append('sha256', packageForm.sha256);
    body.append('file', packageFile);
    const response = await fetch(`${backendUrl.replace(/\/$/, '')}/api/v1/admin/projects/${encodeURIComponent(packageForm.projectId)}/versions/${encodeURIComponent(packageForm.packageId)}/files`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload?.error?.message ?? `${response.status} ${response.statusText}`);
    return payload.data ?? payload;
  }

  const packagePanel = token ? <section className="card wide">
    <h2>Конвейер пакетов и релизов {TOOL_VERSION}</h2>
    <p className="muted">Создание пакета, multipart-загрузка в хранилище, проверка SHA-256 и публикация манифеста в релизный канал.</p>
    <div className="formGrid">
      <article className="subcard">
        <h3>Пакет</h3>
        <TextInput label="ID проекта" value={packageForm.projectId} onChange={(projectId) => setPackageForm({ ...packageForm, projectId })} />
        <TextInput label="ID профиля" value={packageForm.profileId} onChange={(profileId) => setPackageForm({ ...packageForm, profileId })} />
        <TextInput label="Канал" value={packageForm.channel} onChange={(channel) => setPackageForm({ ...packageForm, channel })} />
        <TextInput label="Версия" value={packageForm.version} onChange={(version) => setPackageForm({ ...packageForm, version })} />
        <TextInput label="ID пакета" value={packageForm.packageId} onChange={(packageId) => setPackageForm({ ...packageForm, packageId })} />
        <div className="buttonRow"><button onClick={() => runAction('Создание пакета', createPackage).catch((err) => setError(err.message))}>Создать пакет</button><button disabled={!packageForm.packageId} onClick={() => runAction('Проверка пакета', () => requestJSON(backendUrl, `/api/v1/projects/${encodeURIComponent(packageForm.projectId)}/versions`, token)).catch((err) => setError(err.message))}>Проверить</button><button disabled={!packageForm.packageId} onClick={() => runAction('Smoke-проверка пакета', () => requestJSON(backendUrl, `/api/v1/admin/storage/health`, token)).catch((err) => setError(err.message))}>Smoke-проверка</button><button disabled={!packageForm.packageId} onClick={() => runAction('Публикация пакета', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(packageForm.projectId)}/versions/${encodeURIComponent(packageForm.packageId)}/publish`, token, { method: 'POST' })).catch((err) => setError(err.message))}>Опубликовать</button></div>
      </article>
      <article className="subcard">
        <h3>Файл</h3>
        <TextInput label="Путь в клиенте" value={packageForm.path} onChange={(path) => setPackageForm({ ...packageForm, path })} />
        <TextInput label="Ожидаемый SHA-256 (необязательно)" value={packageForm.sha256} onChange={(sha256) => setPackageForm({ ...packageForm, sha256 })} />
        <label className="field"><span>Файл</span><input type="file" onChange={(event) => setPackageFile(event.target.files?.[0] ?? null)} /></label>
        <div className="buttonRow"><button disabled={!packageForm.packageId || !packageFile} onClick={() => runAction('Загрузка файла пакета', uploadPackageFile).catch((err) => setError(err.message))}>Загрузить файл</button></div>
      </article>
    </div>
  </section> : null;

  const crudPanel = token ? <section className="card wide">
    <h2>Рабочие CRUD-формы</h2>
    <div className="formGrid">
      <article className="subcard">
        <h3>Проект</h3>
        <TextInput label="ID" value={projectForm.id} onChange={(id) => setProjectForm({ ...projectForm, id })} />
        <TextInput label="Название" value={projectForm.name} onChange={(name) => setProjectForm({ ...projectForm, name })} />
        <TextInput label="Описание" value={projectForm.description} onChange={(description) => setProjectForm({ ...projectForm, description })} />
        <TextInput label="Домашняя страница" value={projectForm.homepage} onChange={(homepage) => setProjectForm({ ...projectForm, homepage })} />
        <TextInput label="Репозиторий" value={projectForm.repository} onChange={(repository) => setProjectForm({ ...projectForm, repository })} />
        <TextInput label="Канал по умолчанию" value={projectForm.defaultChannel} onChange={(defaultChannel) => setProjectForm({ ...projectForm, defaultChannel })} />
        <div className="buttonRow"><button onClick={() => runAction('Создание проекта', () => requestJSON(backendUrl, '/api/v1/admin/projects', token, { method: 'POST', body: JSON.stringify(projectForm) })).catch((err) => setError(err.message))}>Создать</button><button onClick={() => runAction('Обновление проекта', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(projectForm.id)}`, token, { method: 'PATCH', body: JSON.stringify(projectForm) })).catch((err) => setError(err.message))}>Обновить</button></div>
      </article>
      <article className="subcard">
        <h3>Профиль</h3>
        <TextInput label="ID проекта" value={profileForm.projectId} onChange={(projectId) => setProfileForm({ ...profileForm, projectId })} />
        <TextInput label="ID" value={profileForm.id} onChange={(id) => setProfileForm({ ...profileForm, id })} />
        <TextInput label="Название" value={profileForm.name} onChange={(name) => setProfileForm({ ...profileForm, name })} />
        <TextInput label="Описание" value={profileForm.description} onChange={(description) => setProfileForm({ ...profileForm, description })} />
        <TextInput label="Загрузчик" value={profileForm.loader} onChange={(loader) => setProfileForm({ ...profileForm, loader })} />
        <TextInput label="Предустановка" value={profileForm.preset} onChange={(preset) => setProfileForm({ ...profileForm, preset })} />
        <label className="check"><input type="checkbox" checked={profileForm.isDefault} onChange={(event) => setProfileForm({ ...profileForm, isDefault: event.target.checked })} /> Профиль по умолчанию</label>
        <div className="buttonRow"><button onClick={() => runAction('Создание профиля', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(profileForm.projectId)}/profiles`, token, { method: 'POST', body: JSON.stringify(profileForm) })).catch((err) => setError(err.message))}>Создать</button><button onClick={() => runAction('Обновление профиля', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(profileForm.projectId)}/profiles/${encodeURIComponent(profileForm.id)}`, token, { method: 'PATCH', body: JSON.stringify(profileForm) })).catch((err) => setError(err.message))}>Обновить</button></div>
      </article>
      <article className="subcard">
        <h3>Канал</h3>
        <TextInput label="ID проекта" value={channelForm.projectId} onChange={(projectId) => setChannelForm({ ...channelForm, projectId })} />
        <TextInput label="ID" value={channelForm.id} onChange={(id) => setChannelForm({ ...channelForm, id })} />
        <TextInput label="Название" value={channelForm.name} onChange={(name) => setChannelForm({ ...channelForm, name })} />
        <TextInput label="Описание" value={channelForm.description} onChange={(description) => setChannelForm({ ...channelForm, description })} />
        <label className="check"><input type="checkbox" checked={channelForm.protected} onChange={(event) => setChannelForm({ ...channelForm, protected: event.target.checked })} /> Защищённый канал</label>
        <div className="buttonRow"><button onClick={() => runAction('Создание канала', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(channelForm.projectId)}/channels`, token, { method: 'POST', body: JSON.stringify(channelForm) })).catch((err) => setError(err.message))}>Создать</button><button onClick={() => runAction('Обновление канала', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(channelForm.projectId)}/channels/${encodeURIComponent(channelForm.id)}`, token, { method: 'PATCH', body: JSON.stringify(channelForm) })).catch((err) => setError(err.message))}>Обновить</button></div>
      </article>
      <article className="subcard">
        <h3>Пользователь</h3>
        <TextInput label="ID для изменения" value={userForm.id} onChange={(id) => setUserForm({ ...userForm, id })} />
        <TextInput label="Электронная почта" value={userForm.email} onChange={(email) => setUserForm({ ...userForm, email })} />
        <TextInput label="Отображаемое имя" value={userForm.displayName} onChange={(displayName) => setUserForm({ ...userForm, displayName })} />
        <TextInput label="ID роли" value={userForm.roleId} onChange={(roleId) => setUserForm({ ...userForm, roleId })} />
        <TextInput label="Пароль" type="password" value={userForm.password} onChange={(password) => setUserForm({ ...userForm, password })} />
        <div className="buttonRow"><button onClick={() => runAction('Создание пользователя', () => requestJSON(backendUrl, '/api/v1/admin/users', token, { method: 'POST', body: JSON.stringify(userForm) })).catch((err) => setError(err.message))}>Создать</button><button disabled={!userForm.id} onClick={() => runAction('Обновление пользователя', () => requestJSON(backendUrl, `/api/v1/admin/users/${encodeURIComponent(userForm.id)}`, token, { method: 'PATCH', body: JSON.stringify(userForm) })).catch((err) => setError(err.message))}>Обновить</button><button disabled={!userForm.id} onClick={() => runAction('Отключение пользователя', () => requestJSON(backendUrl, `/api/v1/admin/users/${encodeURIComponent(userForm.id)}/disable`, token, { method: 'POST' })).catch((err) => setError(err.message))}>Отключить</button><button disabled={!userForm.id} onClick={() => runAction('Включение пользователя', () => requestJSON(backendUrl, `/api/v1/admin/users/${encodeURIComponent(userForm.id)}/enable`, token, { method: 'POST' })).catch((err) => setError(err.message))}>Включить</button></div>
      </article>
    </div>
  </section> : null;


  return <main className="layout">
    <aside className="sidebar">
      <div className="brand">NeverLauncher Admin</div>
      <div className="version">Версия {productionUI.toolVersion ?? TOOL_VERSION} · API v1 · токены в sessionStorage · подписанный релизный поток</div>
      <nav className="nav" aria-label="Разделы панели управления">
        {sections.map((section) => <button className={active === section.id ? 'active' : ''} key={section.id} onClick={() => setActive(section.id)}>{section.title}</button>)}
      </nav>
    </aside>
    <section className="main">
      <header className="header">
        <div><h1>NeverLauncher Admin · API v1</h1><p>{`Рабочая панель NeverLauncher ${TOOL_VERSION}: проекты, профили, каналы, пользователи, подписанный релизный поток, multipart-загрузка, ServerBridge, диагностика и резервное копирование через единый /api/v1.`}</p></div>
        <span className={`badge ${status === 'online' ? 'ok' : 'warn'}`}>Backend: {status === 'online' ? 'доступен' : 'недоступен'}</span>
      </header>
      <section className="card wide">
        <label className="field"><span>URL Backend</span><input value={backendUrl} onChange={(event) => setBackendUrl(event.target.value)} /></label>
        <p className="muted"><code>{activeEndpoint}</code></p>
        <div className="loginRow"><input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="почта администратора" /><input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="пароль" type="password" /><input value={totp} onChange={(event) => setTotp(event.target.value)} placeholder="TOTP (необязательно)" /><input value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} placeholder="код восстановления (необязательно)" /><button onClick={() => login().catch((err: Error) => setError(err.message))}>{token ? 'Войти заново' : 'Войти'}</button><button onClick={() => passwordlessPasskeyLogin().catch((err: Error) => setError(err.message))}>Войти по passkey</button>{token && <button onClick={() => refreshSession().catch((err: Error) => setError(err.message))}>Обновить сессию</button>}{token && <button onClick={() => logout().catch((err: Error) => setError(err.message))}>Выйти</button>}</div>
        {token && <div className="passkeyRow"><button onClick={() => registerPasskey().catch((err: Error) => setError(err.message))}>Добавить passkey</button><button onClick={() => stepUpPasskey().catch((err: Error) => setError(err.message))}>Подтвердить passkey</button><select aria-label="MFA policy" value={mfaPolicy} onChange={(event) => setMfaPolicy(event.target.value as typeof mfaPolicy)}><option value="optional">MFA optional</option><option value="required">MFA required</option><option value="phishing-resistant">Phishing-resistant</option></select><button onClick={() => saveMfaPolicy().catch((err: Error) => setError(err.message))}>Сохранить MFA policy</button></div>}
        {sessionId && <p className="muted">Активная серверная сессия: <code>{sessionId}</code></p>}
        {token && <div className="passkeyRow"><button onClick={() => loadSessions().catch((err: Error) => setError(err.message))}>Сессии</button><button onClick={() => revokeOtherSessions().catch((err: Error) => setError(err.message))}>Выйти на других устройствах</button></div>}
        {token && sessions.length > 0 && <div className="sessionList">{sessions.map((item) => <article className="subcard" key={item.id}><strong>{item.device || item.deviceId || 'Устройство'}{item.current ? ' · текущая' : ''}</strong><p className="muted">{item.provider ?? 'local'} · risk: {item.riskState ?? 'normal'} · {item.lastIp ?? 'IP неизвестен'}</p><div className="buttonRow"><button onClick={() => renameSession(item).catch((err: Error) => setError(err.message))}>Переименовать</button><button onClick={() => revokeSession(item).catch((err: Error) => setError(err.message))}>{item.current ? 'Завершить' : 'Отозвать'}</button></div></article>)}</div>}
        {message && <p className="success">{message}</p>}
        {error && <p className="error">{error}</p>}
      </section>
      <section className="grid"><MetricCard label="Проекты" value={metrics.projects ?? '—'} /><MetricCard label="Профили" value={metrics.profiles ?? '—'} /><MetricCard label="Каналы" value={metrics.channels ?? '—'} /><MetricCard label="Аудит" value={metrics.auditEvents ?? '—'} /><MetricCard label="Состояние" value={dashboard?.status ?? status} /></section>
      {crudPanel}
      {packagePanel}
      <section className="card wide"><h2>{sections.find((section) => section.id === active)?.title ?? active}</h2><DataTable payload={payload} /></section>
      <section className="card wide"><h2>Основной сценарий</h2><div className="workflow">{(productionUI.primaryFlow ?? ['вход', 'создание проекта', 'изменение проекта', 'создание профиля', 'изменение профиля', 'создание канала', 'изменение канала', 'создание пользователя', 'публикация stable', 'проверка аудита']).map((step) => <span key={step}>{step}</span>)}</div></section>
    </section>
  </main>;
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(<App />);

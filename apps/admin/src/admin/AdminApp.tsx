import React, { useEffect, useState } from 'react';
import { AdminExtensions } from '../admin_extensions_0208';
import { RegistryWorkspace } from './RegistryWorkspace';
import { OperationsWorkspace } from './OperationsWorkspace';
import { BackendOperations0289 } from './BackendOperations0289';
import { BackendNoticeInbox0289 } from './BackendNoticeInbox0289';
import { ReleaseWorkspace } from './ReleaseWorkspace';
import { requireValidatedPackage0390, type PackageValidation0390 } from './package-validation-0390';
import { ProfileManagementWorkspace } from './ProfileManagementWorkspace';
import { ProfileEditor0382 } from './ProfileEditor0382';
import { ProjectAccessWorkspace0387 } from './ProjectAccessWorkspace0387';
import { JobMonitor } from './JobMonitor';
import { MigrationCenter0331 } from './MigrationCenter0331';
import { BackupWorkspace } from './BackupWorkspace';
import { SessionsDevicesWorkspace } from './SessionsDevicesWorkspace';
import { AuditWorkspace } from './AuditWorkspace';
import { ConfigWorkspace } from './ConfigWorkspace';
import { OfficialProviderWorkspace02611 } from './OfficialProviderWorkspace02611';
import { AuthProviderWizard02910 } from './AuthProviderWizard02910';
import { requestJSON, ApiError } from '../api/client';
import { AdminApi, type AdminOverview } from '../api/admin';
import { MetricCard, TextInput } from '../components/primitives';
import { ServerBridgeWorkspace } from './ServerBridgeWorkspace';
import { ServerBridgeClient, gameCommandPermissions, type BridgeCommandType, type ServerBridgeNode } from '../api/serverbridge';
import { nodeForContext0383, nodeState0383, profileNodes0383 } from './server-selection-0383';
import { TextureManagement0259 } from './TextureManagement0259';
import { BrandingStudio0355 } from './BrandingStudio0355';
import { SupportDiagnostics03510 } from './SupportDiagnostics03510';
import { ResourceGrid } from '../components/ResourceGrid';
import { useAdminRoute, navigate, replaceAdminRoute, adminHref } from './routing';
import { contextStorageKey, readSavedContext, saveContext, resolveProjectContext } from './project-context-0381';
import { sections, endpointForSection } from './sections';
import { can, canSeeSection, type AdminIdentity } from './permissions';
import { createPasskeyCredential, getPasskeyAssertion, type PublicKeyCredentialRequestOptionsJSON, type PublicKeyCredentialCreationOptionsJSON, type PasskeyBegin, type PasskeySessionResponse } from './passkeys';

type LoginResponse = { token?: string; refreshToken?: string; sessionId?: string; user?: Record<string, unknown>; status?: string; transactionToken?: string; publicKey?: PublicKeyCredentialRequestOptionsJSON };
type DashboardData = Partial<AdminOverview> & { metrics?: Record<string, number> };
type SessionView = { id: string; device: string; deviceId?: string; provider?: string; status?: string; riskState?: string; lastIp?: string; lastSeenAt?: string; expiresAt?: string; current?: boolean };
type TrustedDeviceView = { id: string; userId: string; name: string; status: string; trustState?: string; keyAlgorithm?: string; keyBinding?: string; hardwareProvider?: string; keyFingerprint?: string; lastSeenAt?: string; revokedAt?: string; revokedReason?: string; attestationState?: string; revocationPermanent?: boolean };


type ProjectForm = { id: string; name: string; description: string; homepage: string; repository: string; defaultChannel: string };
type ChannelForm = { projectId: string; id: string; name: string; description: string; protected: boolean };
type UserForm = { id: string; email: string; displayName: string; roleId: string; password: string };
type PackageForm = { projectId: string; profileId: string; channel: string; version: string; packageId: string; path: string; sha256: string };
const TOOL_VERSION = __NEVERLAUNCHER_VERSION__;

export function AdminApp() {
  const [backendUrl, setBackendUrl] = useState(localStorage.getItem('neverlauncher.backendUrl') ?? window.location.origin);
  const [token, setToken] = useState(sessionStorage.getItem('neverlauncher.admin.token') ?? '');
  const [refreshToken, setRefreshToken] = useState(sessionStorage.getItem('neverlauncher.admin.refreshToken') ?? '');
  const [sessionId, setSessionId] = useState(sessionStorage.getItem('neverlauncher.admin.sessionId') ?? '');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [totp, setTotp] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [mfaPolicy, setMfaPolicy] = useState<'optional' | 'required' | 'phishing-resistant'>('optional');
  const route = useAdminRoute();
  const active = route.section;
  const [identity, setIdentity] = useState<AdminIdentity | null>(null);
  const [selectedRecordId, setSelectedRecordId] = useState('');
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [dashboardScope, setDashboardScope] = useState('');
  const [payload, setPayload] = useState<Record<string, unknown> | null>(null);
  const [status, setStatus] = useState('offline');
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<SessionView[]>([]);
  const [devices, setDevices] = useState<TrustedDeviceView[]>([]);
  const [bridgeInventory, setBridgeInventory] = useState<{projectId:string;nodes:ServerBridgeNode[] | null;readAt:number;error:string} | null>(null);
  const [bridgeClock, setBridgeClock] = useState(Date.now());

  const [projectForm, setProjectForm] = useState<ProjectForm>({ id: '', name: '', description: '', homepage: '', repository: '', defaultChannel: 'stable' });
  const [channelForm, setChannelForm] = useState<ChannelForm>({ projectId: '', id: '', name: '', description: '', protected: false });
  const [userForm, setUserForm] = useState<UserForm>({ id: '', email: '', displayName: '', roleId: 'viewer', password: '' });
  const [packageForm, setPackageForm] = useState<PackageForm>({ projectId: '', profileId: '', channel: 'stable', version: '', packageId: '', path: '', sha256: '' });
  const [packageFile, setPackageFile] = useState<File | null>(null);
  const availableProjects = dashboard?.projects ?? [];
  // IDs from URL and localStorage are preferences, not authorization. Overview is
  // access-filtered by the Backend and is the only source for resolving them.
  const ownerStorageKey = identity ? contextStorageKey(backendUrl, identity.user.id) : '';
  const savedContext = ownerStorageKey ? readSavedContext(localStorage, ownerStorageKey) : {projectId:'',profileId:'',channelId:''};
  const baseOwnerContext = resolveProjectContext(route, savedContext, {
    projects: availableProjects, profiles: dashboard?.profiles ?? [], channels: dashboard?.channels ?? [],
  });
  const projectNodes = bridgeInventory?.projectId === baseOwnerContext.projectId ? bridgeInventory.nodes : null;
  const ownerContext = resolveProjectContext(route, savedContext, {
    projects: availableProjects, profiles: dashboard?.profiles ?? [], channels: dashboard?.channels ?? [],
    ...(projectNodes ? { servers: projectNodes } : {}),
  });
  const selectedProjectId = ownerContext.projectId;
  const selectedProfileId = dashboardScope === selectedProjectId ? ownerContext.profileId : '';
  const selectedChannelId = dashboardScope === selectedProjectId ? ownerContext.channelId : '';
  const selectedServer = projectNodes ? nodeForContext0383(projectNodes, selectedProjectId, ownerContext.serverId) : null;
  const selectedServerId = selectedServer?.id ?? '';
  const bridgeInventoryFresh = !!bridgeInventory && bridgeInventory.projectId === selectedProjectId &&
    !!bridgeInventory.nodes && bridgeClock - bridgeInventory.readAt < 45_000;
  const selectedServerState = selectedServer ? nodeState0383(selectedServer, bridgeInventoryFresh, bridgeClock) : null;
  const activeEndpoint = endpointForSection(active, selectedProjectId);
  const mayRead = canSeeSection(identity, active, selectedProjectId);
  const canProjectWrite = can(identity, 'project:write', selectedProjectId);
  const canPrepare = can(identity, 'release:prepare', selectedProjectId);
  const canPublish = can(identity, 'release:publish', selectedProjectId);
  const canFileWrite = can(identity, 'file:write', selectedProjectId);
  const mayManageUsers = can(identity, 'users:manage');
  const metrics = { projects: availableProjects.length, profiles: dashboard?.profiles?.length ?? 0,
    channels: dashboard?.channels?.length ?? 0, auditEvents: dashboard?.audit?.length ?? 0 };
  function chooseProject(id: string) {
    if (!availableProjects.some(p => p.id === id)) return;
    navigate(active, {projectId:id, profileId:'', channelId:'', serverId:''});
    setSelectedRecordId('');
    setPayload(null);
  }
  function selectRecord(row: Record<string, unknown>) {
    const id = String(row.id ?? '');
    setSelectedRecordId(id);
    if (active === 'profiles' && id) navigate(active, {profileId:id});
    if (active === 'channels' && id) navigate(active, {channelId:id});
    if ((active === 'packages' || active === 'releases') && typeof row.profileId === 'string' && row.profileId)
      navigate(active, {profileId:row.profileId, ...(typeof row.channel === 'string' ? {channelId:row.channel} : {})});
    if (active === 'projects') {
      if (id) chooseProject(id);
      setProjectForm({ id, name: String(row.name ?? ''), description: String(row.description ?? ''), homepage: String(row.homepage ?? ''), repository: String(row.repository ?? ''), defaultChannel: String(row.defaultChannel ?? 'stable') });
    } else if (active === 'profiles') {
      // The profile editor is driven by the selected Backend profile, not local copies.
    } else if (active === 'channels') {
      setChannelForm({ projectId: selectedProjectId, id, name: String(row.name ?? ''), description: String(row.description ?? ''), protected: row.protected === true });
    } else if (active === 'users') {
      setUserForm({ id, email: String(row.email ?? ''), displayName: String(row.displayName ?? ''), roleId: String(row.roleId ?? ''), password: '' });
    } else if (active === 'releases' || active === 'packages') {
      setPackageForm(prev => ({ ...prev, projectId: selectedProjectId, packageId: id, version: String(row.version ?? ''), profileId: String(row.profileId ?? ''), channel: String(row.channel ?? 'stable') }));
    }
  }

  // Live Backend view. A failed request never leaves a stale success-shaped inventory.
  useEffect(() => {
    if (!token || !baseOwnerContext.projectId || !can(identity, 'project:read', baseOwnerContext.projectId)) {
      setBridgeInventory(null); return;
    }
    const projectId = baseOwnerContext.projectId;
    let alive = true;
    const api = new ServerBridgeClient(backendUrl, token);
    setBridgeInventory(null);
    async function refresh() {
      try {
        const result = await api.overview(projectId);
        if (alive) setBridgeInventory({projectId, nodes:(result.nodes ?? []).filter(n => n.projectId === projectId), readAt:Date.now(), error:''});
      } catch (e) {
        if (alive) setBridgeInventory({projectId, nodes:null, readAt:0, error:e instanceof Error ? e.message : String(e)});
      }
    }
    void refresh();
    const timer = window.setInterval(() => { if (!document.hidden) void refresh(); }, 15_000);
    const clockTimer = window.setInterval(() => setBridgeClock(Date.now()), 5_000);
    return () => {alive = false;window.clearInterval(timer);window.clearInterval(clockTimer);};
  }, [backendUrl, token, baseOwnerContext.projectId, identity?.user.id]);
  async function chooseServer(id: string) {
    if (!id) {navigate(active,{serverId:''});return;}
    if (!selectedProjectId || !can(identity,'project:read',selectedProjectId)) return;
    let nodes = bridgeInventoryFresh ? projectNodes : null;
    // Immediately after enrollment the parent inventory may predate the new node.
    // Re-read the authoritative project inventory before accepting its context.
    if (!nodes || !nodeForContext0383(nodes,selectedProjectId,id)) {
      try {
        const projectId=selectedProjectId;
        const result=await new ServerBridgeClient(backendUrl,token).overview(projectId);
        nodes=(result.nodes ?? []).filter(n=>n.projectId===projectId);
        setBridgeInventory({projectId,nodes,readAt:Date.now(),error:''});
      } catch (e) {
        setError(`Не удалось подтвердить выбранный узел ServerBridge: ${e instanceof Error?e.message:String(e)}`);
        return;
      }
    }
    const server=nodeForContext0383(nodes,selectedProjectId,id);
    if (!server) {setError('Сервер не найден в выбранном проекте.');return;}
    const boundProfile=server.profileId && (dashboard?.profiles??[]).some(p=>p.projectId===selectedProjectId && p.id===server.profileId) ? server.profileId : '';
    navigate(active,{serverId:server.id,profileId:boundProfile});
  }

  // Canonicalize only after the authenticated access-filtered overview arrives.
  // A removed project/profile/channel cannot survive as a live selection.
  useEffect(() => {
    if (!ownerStorageKey || !dashboard || (ownerContext.projectId && dashboardScope !== ownerContext.projectId)) return;
    if (route.serverId && !projectNodes && bridgeInventory?.projectId !== ownerContext.projectId) return;
    saveContext(localStorage, ownerStorageKey, ownerContext);
    if (route.projectId !== ownerContext.projectId || (route.profileId || '') !== ownerContext.profileId || (route.channelId || '') !== ownerContext.channelId || (route.serverId || '') !== (ownerContext.serverId || ''))
      replaceAdminRoute(active, ownerContext);
  }, [ownerStorageKey, dashboard, dashboardScope, ownerContext.projectId, ownerContext.profileId, ownerContext.channelId,
      ownerContext.serverId, projectNodes, bridgeInventory?.projectId, route.projectId, route.profileId, route.channelId, route.serverId, active]);
  useEffect(() => {
    if (!selectedProjectId) return;
    setChannelForm(f => ({ ...f, projectId: selectedProjectId, id: '', name: '' }));
    setPackageForm(f => ({ ...f, projectId: selectedProjectId, profileId: '', packageId: '', version: '' }));
  }, [selectedProjectId]);

  // The simple package form and the Release Workspace consume the same
  // validated selection. Moving between tabs must not force manual ID entry.
  useEffect(() => {
    if (!selectedProjectId || dashboardScope !== selectedProjectId) return;
    setPackageForm(current => {
      const channel = selectedChannelId || 'stable';
      const matches = current.projectId === selectedProjectId && current.profileId === selectedProfileId && current.channel === channel;
      return matches ? current : {...current,projectId:selectedProjectId,profileId:selectedProfileId,channel,
        packageId:'',version:'',path:'',sha256:''};
    });
  }, [selectedProjectId, dashboardScope, selectedProfileId, selectedChannelId]);

  // Restored deep-links select their resource without requiring a second click.
  useEffect(() => {
    if (active === 'profiles') setSelectedRecordId(selectedProfileId);
    else if (active === 'channels') setSelectedRecordId(selectedChannelId);
  }, [active, selectedProfileId, selectedChannelId]);

  // A deep-link selection also opens the corresponding editable form after
  // the authenticated resource list has finished loading.
  useEffect(() => {
    const rawItems = payload?.items;
    const rows = Array.isArray(rawItems) ? rawItems : [];
    if (active === 'channels' && selectedChannelId) {
      const item = rows.find((x: unknown) => x && typeof x === 'object' && (x as {id?:string}).id === selectedChannelId) as Record<string,unknown>|undefined;
      if (item && (!item.projectId || item.projectId === selectedProjectId))
        setChannelForm({projectId:selectedProjectId,id:selectedChannelId,name:String(item.name??''),description:String(item.description??''),protected:item.protected===true});
    }
  }, [active,selectedProjectId,selectedProfileId,selectedChannelId,payload]);

  useEffect(() => { localStorage.setItem('neverlauncher.backendUrl', backendUrl); }, [backendUrl]);
  useEffect(() => { token ? sessionStorage.setItem('neverlauncher.admin.token', token) : sessionStorage.removeItem('neverlauncher.admin.token'); }, [token]);
  useEffect(() => { refreshToken ? sessionStorage.setItem('neverlauncher.admin.refreshToken', refreshToken) : sessionStorage.removeItem('neverlauncher.admin.refreshToken'); }, [refreshToken]);
  useEffect(() => { sessionId ? sessionStorage.setItem('neverlauncher.admin.sessionId', sessionId) : sessionStorage.removeItem('neverlauncher.admin.sessionId'); }, [sessionId]);

  function applyPasskeySession(data: PasskeySessionResponse, preserveRefresh = false) {
    const nextToken = data.tokens?.accessToken ?? data.accessToken;
    if (!nextToken) throw new Error('Backend не вернул Never access token.');
    setToken(nextToken);
    setPassword(''); setTotp(''); setRecoveryCode('');
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
    setPassword(''); setTotp(''); setRecoveryCode('');
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
    // A logout must not leave pending player/server mutations for another
    // principal using the same browser profile.
    for (const key of Object.keys(sessionStorage)) {
      if (key.startsWith('neverlauncher.bridge.pending.') || key.startsWith('neverlauncher.bridge.monitor.') || key.startsWith('neverlauncher.owner.0388.bridge.')) sessionStorage.removeItem(key);
    }
    setToken(''); setRefreshToken(''); setSessionId(''); setDashboard(null); setIdentity(null); setPayload(null); setSessions([]); setDevices([]); setMessage('Сессия завершена.');
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

  async function loadTrustedDevices(currentToken = token) {
    if (!currentToken) { setDevices([]); return; }
    const data = await requestJSON<{ items?: TrustedDeviceView[] }>(backendUrl, '/api/v1/admin/auth/devices', currentToken);
    setDevices(data.items ?? []);
  }

  async function revokeTrustedDevice(item: TrustedDeviceView) {
    if (!token) throw new Error('Сначала войдите в NeverLauncher.');
    if (item.status === 'revoked') return;
    const reason = window.prompt('Причина необратимого отзыва устройства', 'admin-device-revoke');
    if (reason === null) return;
    if (!window.confirm(`Отозвать устройство ${item.name || item.id}? Старый device key больше нельзя будет зарегистрировать повторно.`)) return;
    const data = await requestJSON<{ revokedSessions?: number; revokedMinecraftSessions?: number; invalidatedChallenges?: number }>(backendUrl, `/api/v1/admin/auth/devices/${encodeURIComponent(item.id)}/revoke`, token, { method: 'POST', body: JSON.stringify({ reason }) });
    await loadTrustedDevices();
    setMessage(`Устройство отозвано: sessions=${data.revokedSessions ?? 0}, minecraft=${data.revokedMinecraftSessions ?? 0}, challenges=${data.invalidatedChallenges ?? 0}. Если Backend требует fresh phishing-resistant step-up, сначала нажмите «Подтвердить passkey».`);
  }

  async function loadDashboard(currentToken = token) {
    if (!currentToken) { setDashboard(null); setIdentity(null); setStatus('offline'); return; }
    const api = new AdminApi(backendUrl, currentToken);
    const user = await api.me();
    const dash = await api.overview(selectedProjectId || undefined).catch((err: unknown) => {
      if (err instanceof ApiError && err.status === 403) return { projects: [], profiles: [], channels: [], versions: [], files: [], users: [], audit: [] };
      throw err;
    });
    setIdentity(user); setDashboardScope(selectedProjectId || dash.projects?.[0]?.id || ''); setDashboard(dash); setStatus('online');
  }

  async function loadActive() {
    if (!token || !mayRead || ['release-workspace','job-monitor','migration-center','backup-restore','devices','audit','config','official-provider','auth-provider-wizard','branding-studio','diagnostics'].includes(active) || (['profiles','channels','packages','releases'].includes(active) && !selectedProjectId)) { setPayload(null); return; }
    const result = await requestJSON<Record<string, unknown>>(backendUrl, activeEndpoint, token);
    setPayload(result);
  }

  useEffect(() => {
    let live = true;
    setDashboard(null); setIdentity(null); setPayload(null);
    if (!token) { setStatus('offline'); return; }
    const api = new AdminApi(backendUrl, token);
    const requestedProjectId = selectedProjectId;
    api.me().then(async user => {
      const dash = await api.overview(requestedProjectId || undefined).catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 403) return { projects: [], profiles: [], channels: [], versions: [], files: [], users: [], audit: [] };
        throw err;
      });
      return [user, dash] as const;
    }).then(([user, dash]) => {
      if (!live) return;
      setIdentity(user); setDashboardScope(requestedProjectId || dash.projects?.[0]?.id || ''); setDashboard(dash); setStatus('online'); setError(null);
    }).catch((err: Error) => { if (live) { setError(err.message); setStatus('offline'); } });
    return () => { live = false; };
  }, [backendUrl, token]);

  useEffect(() => {
    if (!token || !identity || !selectedProjectId) return;
    let live = true;
    new AdminApi(backendUrl, token).overview(selectedProjectId)
      .then(data => { if (live) { setDashboardScope(selectedProjectId); setDashboard(data); } })
      .catch((err: Error) => { if (live) setError(err.message); });
    return () => { live = false; };
  }, [backendUrl, token, identity, selectedProjectId]);

  useEffect(() => {
    let live = true;
    setPayload(null); setSelectedRecordId(active === 'profiles' ? selectedProfileId : active === 'channels' ? selectedChannelId : '');
    if (!token || !mayRead || ['release-workspace','job-monitor','migration-center','backup-restore','devices','audit','config','official-provider','auth-provider-wizard','branding-studio','diagnostics'].includes(active) || (['profiles', 'channels', 'packages', 'releases'].includes(active) && !selectedProjectId)) return;
    requestJSON<Record<string, unknown>>(backendUrl, activeEndpoint, token)
      .then(result => { if (live) { setPayload(result); setError(null); } })
      .catch((err: Error) => { if (live) setError(err.message); });
    return () => { live = false; };
  }, [backendUrl, active, activeEndpoint, token, mayRead, selectedProjectId]);

  async function runAction(label: string, fn: () => Promise<unknown>) {
    setError(null); setMessage(null);
    const result = await fn();
    setMessage(`${label}: выполнено`);
    setPayload(result as Record<string, unknown>);
    await loadDashboard().catch(() => undefined);
    await loadActive().catch(() => undefined);
  }

  async function createProject() {
    setError(null); setMessage(null);
    const id = projectForm.id.trim();
    if (!id || !projectForm.name.trim()) throw new Error('Укажите ID и название проекта.');
    const result = await requestJSON(backendUrl, '/api/v1/admin/projects', token,
      {method:'POST',body:JSON.stringify(projectForm)});
    // The new project must be present in an authenticated overview before it
    // can become the active scope. Never mark a failed refresh as success.
    const overview = await new AdminApi(backendUrl, token).overview(id);
    if (!overview.projects?.some(p => p.id === id)) throw new Error('Проект создан, но недоступен текущему пользователю. Проверьте права и обновите список.');
    setDashboardScope(id); setDashboard(overview);
    setSelectedRecordId(id);
    navigate('projects', {projectId:id,profileId:'',channelId:'',serverId:''});
    setMessage(`Проект ${id} создан и выбран. Можно перейти к профилям, серверам и сборкам.`);
    return result;
  }

  async function createPackage() {
    if (!selectedProjectId) throw new Error('Выберите проект.');
    const result = await requestJSON<any>(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(selectedProjectId)}/versions`, token, { method: 'POST', body: JSON.stringify({ profileId: packageForm.profileId, channel: packageForm.channel, version: packageForm.version }) });
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
    const response = await fetch(`${backendUrl.replace(/\/$/, '')}/api/v1/admin/projects/${encodeURIComponent(selectedProjectId)}/versions/${encodeURIComponent(packageForm.packageId)}/files`, { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload?.error?.message ?? `${response.status} ${response.statusText}`);
    return payload.data ?? payload;
  }

  const packagePanel = token && (active === 'packages' || active === 'releases') && (canPrepare || canPublish || canFileWrite) ? <section className="card wide">
    <h2>Конвейер пакетов и релизов {TOOL_VERSION}</h2>
    <p className="muted">Создание пакета, загрузка и проверка SHA-256. Публикация и откат выполняются через мастер с preview, durable job и подтверждённым channel head.</p>
    <div className="formGrid">
      <article className="subcard">
        <h3>Пакет</h3>
        <TextInput label="ID проекта" value={selectedProjectId} readOnly onChange={() => undefined} />
        <TextInput label="ID профиля" value={packageForm.profileId} onChange={(profileId) => setPackageForm({ ...packageForm, profileId })} />
        <TextInput label="Канал" value={packageForm.channel} onChange={(channel) => setPackageForm({ ...packageForm, channel })} />
        <TextInput label="Версия" value={packageForm.version} onChange={(version) => setPackageForm({ ...packageForm, version })} />
        <TextInput label="ID пакета" value={packageForm.packageId} onChange={(packageId) => setPackageForm({ ...packageForm, packageId })} />
        <div className="buttonRow"><button disabled={!canPrepare || !selectedProjectId || !packageForm.profileId.trim() || !packageForm.version.trim()} onClick={() => runAction('Создание пакета', createPackage).catch((err) => setError(err.message))}>Создать пакет</button><button disabled={!canPrepare || !packageForm.packageId} onClick={() => runAction('Проверка пакета', async () => requireValidatedPackage0390(await requestJSON<PackageValidation0390>(backendUrl, `/api/v1/packages/${encodeURIComponent(packageForm.packageId)}/validate`, token, { method: 'POST' }))).catch((err) => setError(err.message))}>Проверить</button><button disabled={!canPrepare || !packageForm.packageId} onClick={() => runAction('Integrity check пакета', () => requestJSON(backendUrl, `/api/v1/packages/${encodeURIComponent(packageForm.packageId)}/integrity-check`, token, { method: 'POST' })).catch((err) => setError(err.message))}>Integrity check</button><button disabled={!canPublish || !selectedProjectId} onClick={() => navigate('release-workspace')}>Открыть мастер публикации и отката</button></div>
      </article>
      <article className="subcard">
        <h3>Файл</h3>
        <TextInput label="Путь в клиенте" value={packageForm.path} onChange={(path) => setPackageForm({ ...packageForm, path })} />
        <TextInput label="Ожидаемый SHA-256 (необязательно)" value={packageForm.sha256} onChange={(sha256) => setPackageForm({ ...packageForm, sha256 })} />
        <label className="field"><span>Файл</span><input type="file" onChange={(event) => setPackageFile(event.target.files?.[0] ?? null)} /></label>
        <div className="buttonRow"><button disabled={!canFileWrite || !packageForm.packageId || !packageFile} onClick={() => runAction('Загрузка файла пакета', uploadPackageFile).catch((err) => setError(err.message))}>Загрузить файл</button></div>
      </article>
    </div>
  </section> : null;

  const crudPanel = token && ['projects','profiles','channels','users'].includes(active) && mayRead ? <section className="card wide">
    <h2>Рабочие CRUD-формы</h2>
    <div className="formGrid">
      {active === 'projects' && (can(identity, 'project:write') || canProjectWrite) && <article className="subcard">
        <h3>Проект</h3>
        <TextInput label="ID" value={projectForm.id} onChange={(id) => setProjectForm({ ...projectForm, id })} />
        <TextInput label="Название" value={projectForm.name} onChange={(name) => setProjectForm({ ...projectForm, name })} />
        <TextInput label="Описание" value={projectForm.description} onChange={(description) => setProjectForm({ ...projectForm, description })} />
        <TextInput label="Домашняя страница" value={projectForm.homepage} onChange={(homepage) => setProjectForm({ ...projectForm, homepage })} />
        <TextInput label="Репозиторий" value={projectForm.repository} onChange={(repository) => setProjectForm({ ...projectForm, repository })} />
        <TextInput label="Канал по умолчанию" value={projectForm.defaultChannel} onChange={(defaultChannel) => setProjectForm({ ...projectForm, defaultChannel })} />
        <div className="buttonRow"><button disabled={!can(identity, 'project:write') || !projectForm.id.trim() || !projectForm.name.trim()} onClick={() => createProject().catch((err: Error) => setError(err.message))}>Создать</button><button disabled={!canProjectWrite || !projectForm.id || projectForm.id !== selectedProjectId} onClick={() => runAction('Обновление проекта', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(projectForm.id)}`, token, { method: 'PATCH', body: JSON.stringify(projectForm) })).catch((err) => setError(err.message))}>Обновить</button></div>
      </article>}
      {active === 'profiles' && selectedProfileId && <article className="subcard" aria-label="Связь профиля с реальными серверами"><h3>ServerBridge для профиля {selectedProfileId}</h3>
        {!bridgeInventoryFresh ? <p role="status">Сведения ServerBridge недоступны или устарели. Связь с сервером не подтверждена.</p> :
          profileNodes0383(projectNodes ?? [],selectedProjectId,selectedProfileId).length === 0 ? <p>Для профиля нет зарегистрированных узлов. Регистрация выполняется в ServerBridge с profileId этого профиля.</p> :
          <ul>{profileNodes0383(projectNodes ?? [],selectedProjectId,selectedProfileId).map(n => <li key={n.id}><button onClick={()=>{navigate('server-bridge',{serverId:n.id,profileId:n.profileId});}}>{n.name || n.id}</button> — {nodeState0383(n,true,bridgeClock).label}</li>)}</ul>}
      </article>}
      {active === 'profiles' && canProjectWrite && <ProfileEditor0382 backendUrl={backendUrl} token={token} projectId={selectedProjectId}
        selectedProfile={(dashboard?.profiles??[]).find(p=>p.projectId===selectedProjectId && p.id===selectedProfileId)}
        onChanged={async()=>{await loadDashboard();await loadActive();}}
        onCreated={id=>navigate('profiles',{projectId:selectedProjectId,profileId:id})} />}
      {active === 'profiles' && canProjectWrite && <ProfileManagementWorkspace backendUrl={backendUrl} token={token} projectId={selectedProjectId} sourceProfileId={selectedProfileId || selectedRecordId} onCreated={id=>navigate('profiles',{projectId:selectedProjectId,profileId:id})} onChanged={async () => { await loadDashboard(); await loadActive(); }} />}
      {active === 'channels' && canProjectWrite && <article className="subcard">
        <h3>Канал</h3>
        <TextInput label="ID проекта" value={selectedProjectId} readOnly onChange={() => undefined} />
        <TextInput label="ID" value={channelForm.id} onChange={(id) => setChannelForm({ ...channelForm, id })} />
        <TextInput label="Название" value={channelForm.name} onChange={(name) => setChannelForm({ ...channelForm, name })} />
        <TextInput label="Описание" value={channelForm.description} onChange={(description) => setChannelForm({ ...channelForm, description })} />
        <label className="check"><input type="checkbox" checked={channelForm.protected} onChange={(event) => setChannelForm({ ...channelForm, protected: event.target.checked })} /> Защищённый канал</label>
        <div className="buttonRow"><button disabled={!channelForm.id.trim() || !channelForm.name.trim() || !selectedProjectId} onClick={() => runAction('Создание канала', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(selectedProjectId)}/channels`, token, { method: 'POST', body: JSON.stringify(channelForm) })).catch((err) => setError(err.message))}>Создать</button><button disabled={!channelForm.id || !selectedProjectId} onClick={() => runAction('Обновление канала', () => requestJSON(backendUrl, `/api/v1/admin/projects/${encodeURIComponent(selectedProjectId)}/channels/${encodeURIComponent(channelForm.id)}`, token, { method: 'PATCH', body: JSON.stringify(channelForm) })).catch((err) => setError(err.message))}>Обновить</button></div>
      </article>}
      {active === 'users' && mayManageUsers && <ProjectAccessWorkspace0387 backendUrl={backendUrl} token={token} projectId={selectedProjectId} onStepUp={stepUpPasskey} onChanged={async()=>{await loadDashboard();await loadActive();}} />}
      {active === 'users' && mayManageUsers && <article className="subcard">
        <h3>Учётная запись (глобальные настройки)</h3>
        <TextInput label="ID для изменения" value={userForm.id} onChange={(id) => setUserForm({ ...userForm, id })} />
        <TextInput label="Электронная почта" value={userForm.email} onChange={(email) => setUserForm({ ...userForm, email })} />
        <TextInput label="Отображаемое имя" value={userForm.displayName} onChange={(displayName) => setUserForm({ ...userForm, displayName })} />
        <TextInput label="ID роли" value={userForm.roleId} onChange={(roleId) => setUserForm({ ...userForm, roleId })} />
        <TextInput label="Пароль" type="password" value={userForm.password} onChange={(password) => setUserForm({ ...userForm, password })} />
        <div className="buttonRow"><button disabled={!userForm.email.trim() || !userForm.password || !userForm.roleId} onClick={() => runAction('Создание пользователя', () => requestJSON(backendUrl, '/api/v1/admin/users', token, { method: 'POST', body: JSON.stringify(userForm) })).catch((err) => setError(err.message))}>Создать</button><button disabled={!userForm.id} onClick={() => runAction('Обновление пользователя', () => requestJSON(backendUrl, `/api/v1/admin/users/${encodeURIComponent(userForm.id)}`, token, { method: 'PATCH', body: JSON.stringify({ email: userForm.email, displayName: userForm.displayName, roleId: userForm.roleId }) })).catch((err) => setError(err.message))}>Обновить</button><button disabled={!userForm.id} onClick={() => runAction('Отключение пользователя', () => requestJSON(backendUrl, `/api/v1/admin/users/${encodeURIComponent(userForm.id)}/disable`, token, { method: 'POST' })).catch((err) => setError(err.message))}>Отключить</button><button disabled={!userForm.id} onClick={() => runAction('Включение пользователя', () => requestJSON(backendUrl, `/api/v1/admin/users/${encodeURIComponent(userForm.id)}/enable`, token, { method: 'POST' })).catch((err) => setError(err.message))}>Включить</button></div>
      </article>}
    </div>
  </section> : null;


  return <main className="layout">
    <aside className="sidebar">
      <div className="brand">NeverLauncher Admin</div>
      <div className="version">Версия {TOOL_VERSION} · API v1 · токены в sessionStorage · подписанный релизный поток</div>
      <nav className="nav" aria-label="Разделы панели управления">
        {sections.filter(section => canSeeSection(identity, section.id, selectedProjectId)).map(section => <button aria-current={active === section.id ? 'page' : undefined} className={active === section.id ? 'active' : ''} key={section.id} onClick={() => navigate(section.id)}>{section.title}</button>)}
      </nav>
    </aside>
    <section className="main">
      <header className="header">
        <div><h1>NeverLauncher Admin · API v1</h1><p>{`Рабочая панель NeverLauncher ${TOOL_VERSION}: проекты, профили, каналы, пользователи, подписанный релизный поток, multipart-загрузка, ServerBridge, диагностика и резервное копирование через единый /api/v1.`}</p></div>
        <span className={`badge ${status === 'online' ? 'ok' : 'warn'}`}>Backend: {status === 'online' ? 'доступен' : 'недоступен'}</span>
      </header>
      <section className="card wide">
        <label className="field"><span>URL Backend</span><input value={backendUrl} onChange={(event) => { setToken(''); setRefreshToken(''); setSessionId(''); setIdentity(null); setBackendUrl(event.target.value); }} /></label>
        {token && identity && <div className="projectContext"><label>Текущий проект<select aria-label="Текущий проект" disabled={availableProjects.length === 0} value={selectedProjectId} onChange={event => chooseProject(event.target.value)}><option value="" disabled>Выберите проект</option>{availableProjects.map(p => <option key={String(p.id)} value={String(p.id)}>{String(p.name ?? p.id)}</option>)}</select></label><span className="muted">{identity.user.displayName || identity.user.email} · {identity.user.roleId} · {selectedProjectId || 'Нет доступных проектов'}</span></div>}
        {token && identity && selectedProjectId && <nav className="ownerNavigation0381" aria-label="Ресурсы выбранного проекта">
          <span className="ownerNavigationTitle0381">Проект: <strong>{availableProjects.find(p => p.id === selectedProjectId)?.name || selectedProjectId}</strong></span>
          <label>Профиль<select aria-label="Контекстный профиль" value={selectedProfileId} onChange={e => navigate(active, {profileId:e.target.value,serverId:''})}>
            <option value="">Все профили</option>{(dashboard?.profiles ?? []).filter(p => p.projectId === selectedProjectId).map(p => <option key={p.id} value={p.id}>{p.name || p.id}</option>)}
          </select></label>
          <label>Сервер<select aria-label="Контекстный сервер ServerBridge" disabled={!bridgeInventoryFresh} value={selectedServerId} onChange={e => chooseServer(e.target.value)}>
            <option value="">{bridgeInventory?.error ? 'Недоступно — проверьте Backend' : !bridgeInventoryFresh ? 'Ожидание свежих данных' : 'Выберите сервер'}</option>
            {(projectNodes ?? []).map(n => <option key={n.id} value={n.id}>{n.name || n.id} · {n.profileId || 'без профиля'} · {nodeState0383(n,bridgeInventoryFresh,bridgeClock).status}</option>)}
          </select></label>
          {selectedServerState && <span role="status" className={selectedServerState.status==='available'?'success':'muted'}>ServerBridge: {selectedServerState.label}; telemetry: {selectedServerState.telemetry}</span>}
          <label>Канал<select aria-label="Контекстный канал" value={selectedChannelId} onChange={e => navigate(active, {channelId:e.target.value})}>
            <option value="">Все каналы</option>{(dashboard?.channels ?? []).filter(c => c.projectId === selectedProjectId).map(c => <option key={c.id} value={c.id}>{c.name || c.id}</option>)}
          </select></label>
          <div className="ownerResourceLinks0381">
            {(['projects','profiles','server-bridge','channels','packages','release-workspace','releases','job-monitor'] as const).filter(id => canSeeSection(identity,id,selectedProjectId)).map(id => <a key={id} href={adminHref(id,ownerContext)} aria-current={active === id ? 'page' : undefined}>{sections.find(s => s.id === id)?.title}</a>)}
          </div>
        </nav>}
        <details className="advanced"><summary>API и технические сведения</summary><code>{activeEndpoint}</code></details>
        {!token && <div className="loginRow"><label className="field">Email администратора<input value={email} onChange={(event) => setEmail(event.target.value)} placeholder="почта администратора" type="email" autoComplete="username" /></label><label className="field">Пароль<input value={password} onChange={(event) => setPassword(event.target.value)} placeholder="пароль" type="password" autoComplete="current-password" /></label><label className="field">TOTP (необязательно)<input value={totp} onChange={(event) => setTotp(event.target.value)} placeholder="TOTP (необязательно)" inputMode="numeric" autoComplete="one-time-code" /></label><label className="field">Код восстановления (необязательно)<input value={recoveryCode} onChange={(event) => setRecoveryCode(event.target.value)} placeholder="код восстановления (необязательно)" /></label><button onClick={() => login().catch((err: Error) => setError(err.message))}>{token ? 'Войти заново' : 'Войти'}</button><button onClick={() => passwordlessPasskeyLogin().catch((err: Error) => setError(err.message))}>Войти по passkey</button></div>}
        {token && <details className="advanced"><summary>Безопасность сессии и passkeys</summary><div className="passkeyRow"><button onClick={() => refreshSession().catch((err: Error) => setError(err.message))}>Обновить сессию</button><button onClick={() => logout().catch((err: Error) => setError(err.message))}>Выйти</button><button onClick={() => registerPasskey().catch((err: Error) => setError(err.message))}>Добавить passkey</button><button onClick={() => stepUpPasskey().catch((err: Error) => setError(err.message))}>Подтвердить passkey</button><select aria-label="MFA policy" value={mfaPolicy} onChange={(event) => setMfaPolicy(event.target.value as typeof mfaPolicy)}><option value="optional">MFA optional</option><option value="required">MFA required</option><option value="phishing-resistant">Phishing-resistant</option></select><button onClick={() => saveMfaPolicy().catch((err: Error) => setError(err.message))}>Сохранить MFA policy</button></div></details>}
        {sessionId && <p className="muted">Активная серверная сессия: <code>{sessionId}</code></p>}
        {token && <p className="muted"><a href="#/devices">Управление моими сессиями и доверенными устройствами</a></p>}
        {message && <p className="success" role="status">{message}</p>}
        {error && <p className="error" role="alert">{error}</p>}
      </section>
      {token && <section className="grid"><MetricCard label="Проекты" value={metrics.projects ?? '—'} /><MetricCard label="Профили" value={metrics.profiles ?? '—'} /><MetricCard label="Каналы" value={metrics.channels ?? '—'} /><MetricCard label="Аудит" value={metrics.auditEvents ?? '—'} /><MetricCard label="Состояние" value={dashboard?.status ?? status} /></section>}
      {active === 'dashboard' && token && identity && <AdminExtensions backendUrl={backendUrl} token={token} mode="dashboard" onError={setError} />}
      {active === 'extensions-manager' && token && mayRead ? <section className="card wide"><AdminExtensions backendUrl={backendUrl} token={token} onError={setError} /></section> : null}
      {mayRead && token && active === 'extension-registry' && <RegistryWorkspace backendUrl={backendUrl} token={token} onError={setError} onMessage={setMessage} onResult={setPayload} onChanged={() => loadDashboard().catch(() => undefined)} />}
      {mayRead && crudPanel}
      {mayRead && packagePanel}
      {token && identity && <BackendNoticeInbox0289 backendUrl={backendUrl} token={token} />}
      {token && mayRead && active === 'backend-operations' && <BackendOperations0289 backendUrl={backendUrl} token={token} />}
      {token && mayRead && active === 'operations' && <OperationsWorkspace backendUrl={backendUrl} token={token} userId={identity?.user.id||''} projectId={selectedProjectId} canPublish={canPublish} />}
      {token && mayRead && active === 'release-workspace' && <ReleaseWorkspace key={`${backendUrl}:${identity?.user.id}:${selectedProjectId}`} backendUrl={backendUrl} token={token} userId={identity?.user.id||''} projectId={selectedProjectId} initialProfileId={selectedProfileId} initialChannel={selectedChannelId} canPrepare={canPrepare} canFileWrite={canFileWrite} canPublish={canPublish} />}
      {token && mayRead && active === 'migration-center' && <MigrationCenter0331 backendUrl={backendUrl} token={token} projectId={selectedProjectId} />}
      {token && mayRead && active === 'job-monitor' && <JobMonitor backendUrl={backendUrl} token={token} projectId={selectedProjectId} canPublish={canPublish} />}
      {token && mayRead && active === 'backup-restore' && <BackupWorkspace backendUrl={backendUrl} token={token} canRestore={can(identity, 'settings:manage') && can(identity, 'storage:manage')} />}
      {token && mayRead && active === 'devices' && <SessionsDevicesWorkspace backendUrl={backendUrl} token={token} adminAccess={mayManageUsers} onCurrentRevoked={() => {setToken('');setRefreshToken('');setSessionId('');setDashboard(null);setIdentity(null);}} />}
      {token && mayRead && active === 'audit' && <AuditWorkspace backendUrl={backendUrl} token={token} />}
      {token && mayRead && active === 'config' && <ConfigWorkspace backendUrl={backendUrl} token={token} />}
      {token && mayRead && active === 'official-provider' && <OfficialProviderWorkspace02611 backendUrl={backendUrl} token={token} />}
      {token && mayRead && active === 'auth-provider-wizard' && <AuthProviderWizard02910 backendUrl={backendUrl} token={token} />}
      {token && mayRead && active === 'diagnostics' && <SupportDiagnostics03510 backendUrl={backendUrl} token={token} />}
      {token && mayRead && active === 'branding-studio' && <BrandingStudio0355 projectId={selectedProjectId} canSign={can(identity,'release:publish',selectedProjectId)} />}
      {token && mayRead && active === 'texture-management' && <TextureManagement0259 backendUrl={backendUrl} token={token} projectId={selectedProjectId} />}
      {token && mayRead && active === 'server-bridge' && <ServerBridgeWorkspace backendUrl={backendUrl} token={token} userId={identity?.user.id||''} projectId={selectedProjectId} selectedServerId={selectedServerId} selectedProfileId={selectedProfileId} selectedChannelId={selectedChannelId} onSelectServer={chooseServer} allowedCommands={(Object.keys(gameCommandPermissions) as BridgeCommandType[]).filter(kind => can(identity, gameCommandPermissions[kind], selectedProjectId))} allowEnrollment={can(identity, 'settings:manage')} />}
      {token && !mayRead && <section className="card wide emptyState"><h2>Нет доступа</h2><p>Эта операция недоступна для вашей роли либо проект не выбран. Запросите необходимые полномочия у владельца.</p></section>}
      {token && mayRead && !['extensions-manager','backend-operations','operations','release-workspace','job-monitor','migration-center','server-bridge','texture-management','backup-restore','devices','audit','config','official-provider','auth-provider-wizard','branding-studio','diagnostics'].includes(active) && <section className="card wide"><div className="registryHeading"><h2>{sections.find(section => section.id === active)?.title ?? active}</h2><button onClick={() => loadActive().catch((err: Error) => setError(err.message))}>Обновить данные</button></div>{active === 'dashboard' ? <ResourceGrid section={active} payload={payload} /> : <ResourceGrid section={active} payload={payload} selectedId={active === 'profiles' ? selectedProfileId : active === 'channels' ? selectedChannelId : selectedRecordId} onSelect={selectRecord} />}</section>}

    </section>
  </main>;
}



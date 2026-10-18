import { requestJSON } from './client.ts';

export interface Draft { id: string; projectId: string; ownerId: string; profileId: string; channel: string; version: string; minecraftVersion: string; loader: string; packageId: string; jobId: string; step: string; revision: number; createdAt: string; updatedAt: string }
export type DraftFields = Pick<Draft,'projectId'|'profileId'|'channel'|'version'|'minecraftVersion'|'loader'|'packageId'|'jobId'|'step'>;
export interface PackageInfo { packageId: string; projectId: string; profileId: string; channel: string; version: string; status: string; minecraft?: {version:string;loader:string}; files: Array<{ path: string; size: number; sha256: string }> }
export interface ValidationReport { integrity: null | { result: string; manifestDigest: string; artifactDigest: string; checkedAt: string }; runtime: Array<{ result: string; targetId: string; actualClient: boolean; serverJoin: boolean; finishedAt: string }>; policy: { requiredLevel: string; requireServerJoin: boolean } }
export interface Preview { valid: boolean; permission: string; effect: Record<string,string> }
export interface Operation { id: string; projectId: string; resourceId: string; status: string; kind: string }

export class ReleaseApi {
  private readonly base: string;
  private readonly token: string;
  constructor(base: string, token: string) { this.base = base; this.token = token; }
  private get<T>(path: string) { return requestJSON<T>(this.base, path, this.token); }
  private send<T>(path: string, method: 'POST'|'PUT'|'DELETE', payload?: unknown) { return requestJSON<T>(this.base, path, this.token, { method, body: payload === undefined ? undefined : JSON.stringify(payload) }); }
  drafts(projectId: string) { return this.get<{items: Draft[]}>(`/api/v1/release-drafts?projectId=${encodeURIComponent(projectId)}`); }
  create(fields: DraftFields) { return this.send<Draft>('/api/v1/release-drafts','POST',fields); }
  save(draft: Draft) { return this.send<Draft>(`/api/v1/release-drafts/${encodeURIComponent(draft.id)}`,'PUT',draft); }
  linkedJob(id: string) { return this.get<Operation>(`/api/v1/release-drafts/${encodeURIComponent(id)}/operation`); }
  remove(id: string) { return this.send<{deleted: boolean}>(`/api/v1/release-drafts/${encodeURIComponent(id)}`,'DELETE'); }
  package(id: string) { return this.get<PackageInfo>(`/api/v1/packages/${encodeURIComponent(id)}`); }
  createPackage(fields: DraftFields) { return this.send<PackageInfo>('/api/v1/packages','POST',{projectId:fields.projectId,profileId:fields.profileId,channel:fields.channel,version:fields.version,minecraftVersion:fields.minecraftVersion,loader:fields.loader}); }
  packageAction<T>(id: string,action: 'validate'|'sign'|'stage'|'integrity-check') { return this.send<T>(`/api/v1/packages/${encodeURIComponent(id)}/${action}`,'POST'); }
  validations(id: string) { return this.get<ValidationReport>(`/api/v1/packages/${encodeURIComponent(id)}/validations`); }
  policy(id: string) { return this.get<ValidationReport['policy']>(`/api/v1/projects/${encodeURIComponent(id)}/validation-policy`); }
  evidence(id: string, payload: unknown) { return this.send<Record<string,unknown>>(`/api/v1/packages/${encodeURIComponent(id)}/runtime-validations/evidence`,'POST',payload); }
  validateOperation(req: Record<string,unknown>) { return this.send<Preview>('/api/v1/operations/validate','POST',req); }
  executeOperation(req: Record<string,unknown>) { return this.send<Operation>('/api/v1/operations/execute','POST',req); }
  profiles(id: string) { return this.get<{items: Array<{id:string;name:string;loader:string}>}>(`/api/v1/projects/${encodeURIComponent(id)}/profiles`); }
  releases(id: string) { return this.get<{items: Array<{id:string;version:string;profileId:string;channel:string;status:string}>}>(`/api/v1/projects/${encodeURIComponent(id)}/versions`); }
  async upload(id: string, file: File, path: string) {
    const data = new FormData();data.append('path',path);data.append('file',file);
    return this.sendForm(`/api/v1/packages/${encodeURIComponent(id)}/files`,data);
  }
  private async sendForm(path: string,body: FormData) {
    const res = await fetch(`${this.base.replace(/\/$/,'')}${path}`,{method:'POST',headers:{Authorization:`Bearer ${this.token}`},body,cache:'no-store'});
    const payload: unknown = await res.json().catch(()=>null);
    if (!res.ok) { const error = payload && typeof payload==='object' && 'error' in payload ? (payload as {error?:{message?:string}}).error?.message : undefined; throw new Error(error || `Upload: HTTP ${res.status}`); }
    return payload;
  }
}

import { requestJSON, type Collection } from './client.ts';
import type { AdminIdentity } from '../admin/permissions';

export interface Project {
  id: string; name: string; description: string; homepage: string; repository: string;
  defaultChannel: string; createdAt?: string; updatedAt?: string;
}
export interface Profile {
  id: string; projectId: string; name: string; description: string;
  loader: string; preset: string; isDefault: boolean;
}
export interface Channel { id: string; projectId: string; name: string; description: string; protected: boolean }
export interface Release { id: string; projectId: string; profileId: string; channel: string; version: string; status: string; publishedAt?: string }
export interface AdminUser { id: string; email: string; displayName: string; roleId: string; status: string; projectRoles?: Record<string, string> }
export interface AuditEvent { id: string; actor: string; action: string; target: string; createdAt: string; ip?: string }
export interface AdminOverview {
  status?: string;
  projects: Project[]; profiles: Profile[]; channels: Channel[]; versions: Release[];
  files: Record<string, unknown>[]; users: AdminUser[]; audit: AuditEvent[];
}

export class AdminApi {
  private readonly backendUrl: string;
  private readonly token: string;
  constructor(backendUrl: string, token: string) { this.backendUrl = backendUrl; this.token = token; }
  me() { return requestJSON<AdminIdentity>(this.backendUrl, '/api/v1/admin/me', this.token); }
  overview(projectId?: string) {
    return requestJSON<AdminOverview>(this.backendUrl, `/api/v1/admin/overview${projectId ? `?projectId=${encodeURIComponent(projectId)}` : ''}`, this.token);
  }
  projects() { return this.overview().then(overview => overview.projects); }
  profiles(projectId: string) { return requestJSON<Collection<Profile>>(this.backendUrl, `/api/v1/projects/${encodeURIComponent(projectId)}/profiles`, this.token); }
  channels(projectId: string) { return requestJSON<Collection<Channel>>(this.backendUrl, `/api/v1/projects/${encodeURIComponent(projectId)}/channels`, this.token); }
  releases(projectId: string) { return requestJSON<Collection<Release>>(this.backendUrl, `/api/v1/projects/${encodeURIComponent(projectId)}/versions`, this.token); }
  users() { return requestJSON<Collection<AdminUser>>(this.backendUrl, '/api/v1/admin/users', this.token); }
  audit() { return requestJSON<Collection<AuditEvent>>(this.backendUrl, '/api/v1/admin/audit', this.token); }
}

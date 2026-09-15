#!/usr/bin/env python3
"""Generate the checked-in OpenAPI 3.1 contract for the canonical NeverLauncher API v1."""
from __future__ import annotations
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROUTES = ROOT / "services/api/internal/httpapi"
OUT = ROOT / "schemas/openapi.yaml"
route_re = re.compile(r'"(GET|POST|PUT|PATCH|DELETE) (/api/v1/[^" ]+|/(?:health|ready|metrics))')
files = [ROUTES / "handler.go"] + sorted(p for p in ROUTES.glob("routes_*.go") if "legacy" not in p.name)
routes = []
for file in files:
    for method, path in route_re.findall(file.read_text()):
        path = path.replace("{path...}", "{path}")
        routes.append((method.lower(), path))
routes = sorted(set(routes), key=lambda x:(x[1],x[0]))

public_prefixes = (
    "/health", "/ready", "/metrics", "/api/v1/status", "/api/v1/diagnostics/", "/api/v1/runtime/", "/api/v1/loaders",
    "/api/v1/install/wizard", "/api/v1/install/profiles", "/api/v1/install/readiness", "/api/v1/projects", "/api/v1/files/",
)
public_exact = {"/api/v1/install/bootstrap-admin", "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/admin/login", "/api/v1/textures/{uuid}"}
server_token_paths = {"/api/v1/server-bridge/validate-join", "/api/v1/server-bridge/audit-event"}

def is_public(method, path):
    if path in public_exact: return True
    if method == "get" and any(path.startswith(p) for p in public_prefixes): return True
    return False

def security_for(method, path):
    if path == "/api/v1/install/bootstrap-admin": return [{"BootstrapToken": []}]
    if is_public(method,path): return []
    if path.endswith("/heartbeat") or path in server_token_paths or path == "/api/v1/session/has-joined": return [{"ServerToken": []}]
    return [{"BearerAuth": []}]

def tags_for(path):
    if path in ("/health","/ready","/metrics","/api/v1/status"): return ["operations"]
    for token, tag in [("/auth/","auth"),("/install/","install"),("/server-bridge/","bridge"),("/session/","bridge"),("/textures/","bridge"),("/projects","projects"),("/files/","packages"),("/admin/","admin"),("/runtime/","runtime"),("/loaders","runtime"),("/operations/","operations"),("/telemetry/","operations"),("/crash-reports","operations"),("/diagnostics/","operations")]:
        if token in path: return [tag]
    return ["api"]

def op_id(method,path):
    x = path.strip("/").replace("api/v1/","")
    x = re.sub(r"\{([^}]+)\}", lambda m: "by_"+m.group(1), x)
    x = re.sub(r"[^A-Za-z0-9]+","_",x).strip("_")
    return method + "_" + x

def path_parameters(path):
    out=[]
    for name in re.findall(r"\{([^}]+)\}",path):
        schema={"type":"string","minLength":1}
        out.append({"name":name,"in":"path","required":True,"schema":schema})
    if path.endswith("/manifest"):
        out.append({"name":"channel","in":"query","required":False,"schema":{"type":"string","default":"stable"}})
    if path.endswith("/files") and path.startswith("/api/v1/projects/"):
        out.append({"name":"versionId","in":"query","required":False,"schema":{"type":"string"}})
    if path == "/api/v1/session/has-joined":
        out += [{"name":"username","in":"query","required":False,"schema":{"type":"string"}},{"name":"serverId","in":"query","required":False,"schema":{"type":"string"}}]
    return out

ref=lambda name:{"$ref":f"#/components/schemas/{name}"}

def body_schema(path):
    exact={
      "/api/v1/diagnostics/validate":"DiagnosticsReportRequest",
      "/api/v1/install/bootstrap-admin":"BootstrapAdminRequest", "/api/v1/install/first-project":"FirstProjectRequest",
      "/api/v1/admin/login":"LoginRequest", "/api/v1/auth/login":"LoginRequest", "/api/v1/auth/refresh":"RefreshRequest",
      "/api/v1/auth/sessions/revoke":"RevokeSessionsRequest", "/api/v1/auth/sessions/logout-all":"RevokeSessionsRequest",
      "/api/v1/admin/users":"UserWriteRequest", "/api/v1/admin/projects":"ProjectWriteRequest",
      "/api/v1/admin/projects/import":"FreeFormObject",
      "/api/v1/server-bridge/servers/register":"ServerRegisterRequest", "/api/v1/server-bridge/validate-join":"ValidateJoinRequest",
      "/api/v1/server-bridge/audit-event":"BridgeAuditEventRequest",
      "/api/v1/session/join":"JoinRequest", "/api/v1/session/has-joined":"HasJoinedRequest", "/api/v1/session/invalidate":"InvalidateRequest",
      "/api/v1/telemetry/events":"TelemetryRequest", "/api/v1/crash-reports":"CrashReportRequest",
    }
    if path in exact:return ref(exact[path])
    if path.endswith("/heartbeat"):return ref("HeartbeatRequest")
    if path.endswith("/password"):return ref("PasswordResetRequest")
    if path.endswith("/profiles"):return ref("ProfileWriteRequest")
    if "/profiles/" in path and path.startswith("/api/v1/admin/projects/"):return ref("ProfileWriteRequest")
    if path.endswith("/channels"):return ref("ChannelWriteRequest")
    if "/channels/" in path and path.startswith("/api/v1/admin/projects/"):return ref("ChannelWriteRequest")
    if path.startswith("/api/v1/admin/projects/") and path.count("/")==5 and not path.endswith("/publish"):return ref("ProjectWriteRequest")
    if path.startswith("/api/v1/admin/users/") and path.count("/")==5:return ref("UserWriteRequest")
    if path.endswith("/manifest"):return ref("ManifestRuntimeUpdateRequest")
    if path.endswith("/versions"):return ref("CreateVersionRequest")
    if path.endswith("/publish"):return ref("PublishRequest")
    return ref("FreeFormObject")

def request_body_required(method,path):
    if method not in ("post","put","patch"): return False
    optional={
      "/api/v1/auth/logout", "/api/v1/admin/logout", "/api/v1/auth/sessions/revoke", "/api/v1/auth/sessions/logout-all",
      "/api/v1/session/has-joined", "/api/v1/session/invalidate", "/api/v1/session/invalidate-all",
    }
    if path.endswith("/rotate-token") or path.endswith("/heartbeat") or path.endswith("/disable") or path.endswith("/enable"):
        return False
    if path.endswith("/versions/{versionId}/publish"):
        return False
    return path not in optional

def request_body_allowed(method,path):
    if method not in ("post","put","patch"): return False
    no_body={"/api/v1/auth/logout","/api/v1/admin/logout","/api/v1/session/invalidate-all"}
    if path in no_body or path.endswith("/rotate-token") or path.endswith("/disable") or path.endswith("/enable") or path.endswith("/versions/{versionId}/publish"):
        return False
    return True

def success_status(method,path):
    if path in {"/api/v1/telemetry/events","/api/v1/crash-reports"}: return "202"
    created={
      "/api/v1/install/bootstrap-admin","/api/v1/install/first-project","/api/v1/admin/users","/api/v1/admin/projects",
      "/api/v1/server-bridge/servers/register",
    }
    if path in created or (method=="post" and (path.endswith("/versions") or path.endswith("/files") or path.endswith("/profiles") or path.endswith("/channels") or path.endswith("/admin/projects/{projectId}/publish"))):
        return "201"
    return "200"

def response_schema(path, method):
    if path in ("/health","/api/v1/status"):return ref("ServiceStatus")
    if path == "/ready":return ref("Readiness")
    if path == "/metrics": return {"type":"string"}
    if path.endswith("/manifest") and method=="get":return ref("Manifest")
    if path.startswith("/api/v1/files/"): return {"type":"string","format":"binary"}
    if path.endswith("/versions") and method=="post":return ref("ReleaseVersion")
    if path.endswith("/publish") and method=="post":return ref("ReleaseVersion")
    if path == "/api/v1/admin/login":return ref("AdminSession")
    return {"type":"object","additionalProperties":True}

paths={}
for method,path in routes:
    op={"operationId":op_id(method,path),"tags":tags_for(path),"summary":f"{method.upper()} {path}","responses":{}}
    params=path_parameters(path)
    if params: op["parameters"]=params
    sec=security_for(method,path)
    if sec: op["security"]=sec
    elif sec==[]: op["security"]=[]
    if request_body_allowed(method,path) and not path.endswith("/files"):
        op["requestBody"]={"required":request_body_required(method,path),"content":{"application/json":{"schema":body_schema(path)}}}
    if path.endswith("/files") and method=="post":
        op["requestBody"]={"required":True,"content":{"multipart/form-data":{"schema":{"type":"object","required":["file"],"properties":{"path":{"type":"string"},"file":{"type":"string","format":"binary"}}}}}}
    success=success_status(method,path)
    ctype="text/plain" if path=="/metrics" else ("application/octet-stream" if path.startswith("/api/v1/files/") else "application/json")
    op["responses"][success]={"description":"Success","content":{ctype:{"schema":response_schema(path,method)}}}
    if sec:
        op["responses"]["401"]={"$ref":"#/components/responses/Unauthorized"}
    if method in ("post","put","patch"):
        op["responses"]["400"]={"$ref":"#/components/responses/BadRequest"}
    paths.setdefault(path,{})[method]=op

schemas={
"Error":{"type":"object","required":["error"],"properties":{"error":{"type":"string"}}},
"ServiceStatus":{"type":"object","required":["name","version","status","environment","storage"],"properties":{"name":{"type":"string"},"version":{"type":"string"},"status":{"type":"string"},"environment":{"type":"string"},"message":{"type":"string"},"storage":{"type":"string"}}},
"Readiness":{"type":"object","required":["status"],"properties":{"status":{"type":"string"},"checks":{"type":"array","items":{"type":"object","additionalProperties":True}}},"additionalProperties":True},
"LoginRequest":{"type":"object","required":["email","password"],"properties":{"email":{"type":"string","format":"email"},"password":{"type":"string","minLength":1},"totp":{"type":"string"},"recoveryCode":{"type":"string"},"deviceId":{"type":"string"}}},
"RefreshRequest":{"type":"object","required":["refreshToken"],"properties":{"refreshToken":{"type":"string","minLength":1}}},
"BootstrapAdminRequest":{"type":"object","required":["email","password"],"properties":{"email":{"type":"string","format":"email"},"displayName":{"type":"string"},"password":{"type":"string","minLength":12},"actor":{"type":"string"}}},
"FirstProjectRequest":{"type":"object","properties":{"projectId":{"type":"string"},"profileId":{"type":"string"},"channel":{"type":"string"},"version":{"type":"string"},"actor":{"type":"string"}}},
"Project":{"type":"object","required":["id","name","defaultChannel"],"properties":{"id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"homepage":{"type":"string"},"repository":{"type":"string"},"defaultChannel":{"type":"string"}}},
"Profile":{"type":"object","required":["id","projectId","name","loader"],"properties":{"id":{"type":"string"},"projectId":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"loader":{"type":"string"},"preset":{"type":"string"},"isDefault":{"type":"boolean"}}},
"ReleaseChannel":{"type":"object","required":["id","projectId","name"],"properties":{"id":{"type":"string"},"projectId":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"protected":{"type":"boolean"}}},
"Signature":{"type":"object","required":["algorithm","publicKey","signature","signedAt"],"properties":{"algorithm":{"const":"Ed25519"},"publicKey":{"type":"string","pattern":"^[0-9a-fA-F]{64}$"},"signature":{"type":"string","pattern":"^[0-9a-fA-F]{128}$"},"signedAt":{"type":"string","format":"date-time"}}},
"ManifestFile":{"type":"object","required":["path","size","sha256","url","required","executable"],"properties":{"path":{"type":"string"},"size":{"type":"integer","minimum":0},"sha256":{"type":"string","pattern":"^[0-9a-fA-F]{64}$"},"url":{"type":"string","format":"uri"},"required":{"type":"boolean"},"executable":{"type":"boolean"},"targetOs":{"type":"array","items":{"type":"string"}}}},
"Manifest":{"type":"object","required":["schemaVersion","projectId","profileId","channel","version","createdAt","minecraft","runtime","files","signature"],"properties":{"schemaVersion":{"type":"string"},"projectId":{"type":"string"},"profileId":{"type":"string"},"channel":{"type":"string"},"version":{"type":"string"},"createdAt":{"type":"string"},"minecraft":{"type":"object","additionalProperties":True},"runtime":{"type":"object","additionalProperties":True},"directories":{"type":"object","additionalProperties":True},"files":{"type":"array","items":ref("ManifestFile")},"signature":ref("Signature")}},
"ReleaseVersion":{"type":"object","required":["id","projectId","profileId","channel","version","status","manifest"],"properties":{"id":{"type":"string"},"projectId":{"type":"string"},"profileId":{"type":"string"},"channel":{"type":"string"},"version":{"type":"string"},"status":{"type":"string"},"manifest":ref("Manifest"),"publishedAt":{"type":"string","format":"date-time"}}},
"AdminSession":{"type":"object","required":["token","user","expiresAt"],"properties":{"token":{"type":"string"},"refreshToken":{"type":"string"},"sessionId":{"type":"string"},"user":{"type":"object","additionalProperties":True},"expiresAt":{"type":"string","format":"date-time"},"refreshExpiresAt":{"type":"string","format":"date-time"}}},
"CreateVersionRequest":{"type":"object","required":["version"],"properties":{"profileId":{"type":"string","default":"vanilla"},"channel":{"type":"string","default":"dev"},"version":{"type":"string","minLength":1}}},
"PublishRequest":{"type":"object","properties":{"profileId":{"type":"string"},"channel":{"type":"string"},"version":{"type":"string"}}},
"ManifestRuntimeUpdateRequest":{"type":"object","required":["minecraft","runtime"],"properties":{"minecraft":{"type":"object","additionalProperties":True},"runtime":{"type":"object","additionalProperties":True},"directories":{"type":"object","additionalProperties":True}}},
"ServerRegisterRequest":{"type":"object","required":["id","kind","projectId"],"properties":{"id":{"type":"string"},"name":{"type":"string"},"kind":{"type":"string","enum":["velocity","paper","purpur"]},"projectId":{"type":"string"},"profileId":{"type":"string"},"fingerprint":{"type":"string"}}},
"JoinRequest":{"type":"object","required":["username","serverId","projectId","profileId"],"properties":{"username":{"type":"string","minLength":3,"maxLength":16,"pattern":"^[A-Za-z0-9_]+$"},"serverId":{"type":"string"},"projectId":{"type":"string"},"profileId":{"type":"string"},"channel":{"type":"string","default":"stable"}}},
"InvalidateRequest":{"type":"object","properties":{"serverId":{"type":"string"},"reason":{"type":"string"}}},
"RevokeSessionsRequest":{"type":"object","properties":{"allExceptCurrent":{"type":"boolean"}}},
"PasswordResetRequest":{"type":"object","required":["password"],"properties":{"password":{"type":"string","minLength":12}}},
"ProjectWriteRequest":{"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"homepage":{"type":"string"},"repository":{"type":"string"},"defaultChannel":{"type":"string"}}},
"ProfileWriteRequest":{"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"loader":{"type":"string"},"preset":{"type":"string"},"isDefault":{"type":"boolean"}}},
"ChannelWriteRequest":{"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},"protected":{"type":"boolean"}}},
"UserWriteRequest":{"type":"object","properties":{"email":{"type":"string","format":"email"},"displayName":{"type":"string"},"roleId":{"type":"string"},"password":{"type":"string"},"projectRoles":{"type":"object","additionalProperties":{"type":"string"}}}},
"DiagnosticsReportRequest":{"type":"object","required":["schemaVersion","generatedAt","launcherVersion"],"properties":{"schemaVersion":{"type":"string"},"generatedAt":{"type":"string"},"launcherVersion":{"type":"string"},"os":{"type":"string"},"arch":{"type":"string"},"backendUrl":{"type":"string"},"status":{"type":"string"},"checks":{"type":"object","additionalProperties":{"type":"string"}}}},
"HeartbeatRequest":{"type":"object","properties":{"serverId":{"type":"string"},"serverType":{"type":"string"},"pluginVersion":{"type":"string"}}},
"BridgeAuditEventRequest":{"type":"object","required":["serverId","event"],"properties":{"serverId":{"type":"string"},"event":{"type":"string"},"player":{"type":"string"},"uuid":{"type":"string"},"details":{"type":"object","additionalProperties":True}}},
"HasJoinedRequest":{"type":"object","properties":{"username":{"type":"string"},"serverId":{"type":"string"}}},
"TelemetryRequest":{"type":"object","required":["projectId","event"],"properties":{"projectId":{"type":"string"},"profileId":{"type":"string"},"launcherVersion":{"type":"string"},"profileVersion":{"type":"string"},"event":{"type":"string"},"status":{"type":"string"}}},
"CrashReportRequest":{"type":"object","required":["projectId","message"],"properties":{"projectId":{"type":"string"},"profileId":{"type":"string"},"launcherVersion":{"type":"string"},"profileVersion":{"type":"string"},"message":{"type":"string"},"log":{"type":"string"}}},
"FreeFormObject":{"type":"object","additionalProperties":True},
"ValidateJoinRequest":{"type":"object","required":["serverId","username"],"properties":{"serverId":{"type":"string"},"username":{"type":"string"},"uuid":{"type":"string"},"serverHash":{"type":"string"},"ip":{"type":"string"},"projectId":{"type":"string"},"profileId":{"type":"string"},"channel":{"type":"string"}}}
}

spec={
 "openapi":"3.1.1",
 "info":{"title":"NeverLauncher API","version":"1.0.0","description":"Канонический production API NeverLauncher 0.10.0-P3.2v4. Исторические маршруты /api/v2–/api/v5 удалены и намеренно не входят в контракт."},
 "servers":[{"url":"/","description":"Текущий Backend NeverLauncher"}],
 "tags":[{"name":x} for x in ["auth","install","projects","packages","admin","runtime","bridge","operations"]],
 "paths":paths,
 "components":{"securitySchemes":{"BearerAuth":{"type":"http","scheme":"bearer"},"ServerToken":{"type":"apiKey","in":"header","name":"X-NeverLauncher-Server-Token"},"BootstrapToken":{"type":"apiKey","in":"header","name":"X-NeverLauncher-Bootstrap-Token"}},"schemas":schemas,"responses":{"BadRequest":{"description":"Invalid request","content":{"application/json":{"schema":ref("Error")}}},"Unauthorized":{"description":"Authentication required or invalid","content":{"application/json":{"schema":ref("Error")}}}}}
}
OUT.write_text(json.dumps(spec,ensure_ascii=False,indent=2)+"\n")
print(f"generated {OUT}: {len(routes)} operations")

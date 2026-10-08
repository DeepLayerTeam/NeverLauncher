#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")

def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(message)

version = tuple(int(x) for x in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 5), "VERSION must be >= 0.20.5")

host = read("services/api/internal/extensionhost/host_0205.go")
for token in (
    'exec.Command(entrypoint)', 'net.Listen("tcp"', 'IsLoopback()', 'sanitizedEnvironment',
    'NEVERLAUNCHER_EXTENSION_HOST_TOKEN', 'NEVERLAUNCHER_EXTENSION_HOST_URL',
    'handleHello', 'handleHeartbeat', 'handleCapability', 'project.get', 'storage.read',
    'heartbeat timeout', 'memory limit exceeded', 'process limit exceeded', 'crashloop',
    'captureStream', 'MaxLogBytes', 'StartInstallation', 'Restart(', 'Reconcile(',
):
    require(token in host, f"Extension Host runtime missing {token}")

linux = read("services/api/internal/extensionhost/process_linux_0205.go")
for token in ('Setpgid: true', 'Pdeathsig: syscall.SIGKILL', 'processTreeUsage', 'PR_SET_DUMPABLE=0', 'SYS_PRCTL'):
    require(token in linux, f"Linux host isolation missing {token}")

main = read("services/api/cmd/neverlauncher-api/main.go")
for token in ('extensionhost.HardenBackendProcess()', 'extensionhost.New(', 'host.Start(', 'host.Reconcile(', 'ExtensionHost:'):
    require(token in main, f"Backend Extension Host wiring missing {token}")

lifecycle = read("services/api/internal/httpapi/extension_lifecycle_0204.go")
for token in ('stopExtensionHostForLifecycle0205', 'startEnabledExtensionHost0205', 'restoreExtensionHostAfterLifecycleFailure0205', 'enable was compensated to disabled'):
    require(token in lifecycle, f"lifecycle/host integration missing {token}")
updates = read('services/api/internal/extensionupdates/updates_02011.go') if (ROOT/'services/api/internal/extensionupdates/updates_02011.go').is_file() else ''
require('failed host activation; payload/state rolled back' in lifecycle or ('waitHealthy' in updates and 'm.rollback' in updates), 'lifecycle/host integration missing failed host activation rollback')

routes = read("services/api/internal/httpapi/routes_packages.go")
for suffix in ('', '/{extensionId}', '/{extensionId}/logs', '/{extensionId}/start', '/{extensionId}/stop', '/{extensionId}/restart'):
    require('/api/v1/admin/extension-hosts' + suffix in routes, f"host admin route missing {suffix}")

cli = read("cli/cmd/neverlauncher/extension_host_0205.go")
for token in ('list', 'status', 'logs', 'start', 'stop', 'restart', '/api/v1/admin/extension-hosts'):
    require(token in cli, f"host CLI missing {token}")

admin = read("apps/admin/src/main.tsx")
for token in ('ExtensionHostView', 'loadExtensionHosts', 'Host Start', 'Host Stop', 'Host Restart', 'memoryBytes', 'processCount'):
    require(token in admin, f"Admin Extension Host UI missing {token}")

openapi = read("schemas/openapi.yaml")
for path in ('/api/v1/admin/extension-hosts', '/api/v1/admin/extension-hosts/{extensionId}/logs', '/api/v1/admin/extension-hosts/{extensionId}/restart'):
    require(path in openapi, f"OpenAPI missing {path}")

config = read("services/api/internal/config/config.go")
for token in ('ExtensionHostStartupTimeoutSeconds', 'ExtensionHostHeartbeatTimeoutSeconds', 'ExtensionHostMaxMemoryMB', 'ExtensionHostMaxProcesses', 'ExtensionHostCrashLimit'):
    require(token in config, f"host config missing {token}")

for envfile in ("deploy/production/env.production.example", "cli/cmd/neverlauncher/templates/production/env.production.example"):
    env = read(envfile)
    for key in ('NEVERLAUNCHER_EXTENSION_HOST_ENABLED=', 'NEVERLAUNCHER_EXTENSION_HOST_LISTEN=', 'NEVERLAUNCHER_EXTENSION_HOST_MAX_MEMORY_MB=', 'NEVERLAUNCHER_EXTENSION_HOST_MAX_PROCESSES=', 'NEVERLAUNCHER_EXTENSION_HOST_CRASH_LIMIT='):
        require(key in env, f"{envfile} missing {key}")

print("NeverExtensions Хост расширений 1 0.20.5 рабочий контроль: OK")

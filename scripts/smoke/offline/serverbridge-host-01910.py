#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")

def require(text, needles, label):
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{label}: отсутствующий {needle!r}")

version = read("VERSION").strip()
parts = tuple(int(x) for x in version.split("-", 1)[0].split(".")[:3])
if parts < (0, 19, 10):
    raise SystemExit(f"ServerBridge Хост контроль требует VERSION>=0.19.10, получил {version}")

provision = read("cli/cmd/neverlauncher/serverbridge_provisioning_0199.go")
host = read("cli/cmd/neverlauncher/serverbridge_host_01910.go")
unix = read("cli/cmd/neverlauncher/serverbridge_host_process_unix_01910.go")
windows = read("cli/cmd/neverlauncher/serverbridge_host_process_windows_01910.go")
tests = read("cli/cmd/neverlauncher/serverbridge_host_01910_test.go")
main = read("cli/cmd/neverlauncher/main.go")
preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")

require(provision, ['case "host":', 'handleServerBridgeHost01910(args[1:])'], "ServerBridge host CLI wiring")
require(main, ["Zero-Patch provisioning + host supervisor"], "main help")
require(host, [
    'case "configure":', 'case "start":', 'case "run":', 'case "stop":', 'case "restart":', 'case "status":', 'case "logs":',
    'serverBridgeHostConfig01910', 'serverBridgeHostRuntime01910', 'acquireServerBridgeHostLock01910',
    'resolveServerBridgeHostJava01910', 'javaMajorVersion', 'NEVERLAUNCHER_SERVERBRIDGE_JAVA', 'JAVA_HOME', 'exec.LookPath',
    'java-jar', 'java-args-file', 'detectModernForgeArgsFile01910', '@"+config.JavaArgsFile',
    'hostStreamWriter01910', 'cmd.Stdout =', 'cmd.Stderr =', '"STDOUT"', '"STDERR"',
    'ExitCode', 'CrashCount', 'LastCrashAt', 'RestartPolicy', 'MaxRestarts', 'RestartBackoffMillis',
    'hostTerminateProcess01910', 'hostKillProcess01910', 'updaterProcessAlive0156',
    'stop.request', 'host.lock', 'runtime.json', 'stdout.log', 'stderr.log', 'server.log',
    '--jvm-arg', '--server-arg', '--restart-policy', '--max-restarts', '--stop-timeout-seconds', '--follow',
], "ServerBridge Host implementation")
require(unix, ['Setpgid: true', 'Setsid: true', 'syscall.Kill(-pid, syscall.SIGTERM)', 'syscall.Kill(-pid, syscall.SIGKILL)'], "Unix process supervision")
require(windows, ['CreationFlags', 'hostCreateNewProcessGroup01910', 'hostDetachedProcess01910', 'process.Kill()'], "Windows process supervision")
require(tests, [
    'TestServerBridgeHostConfigureJavaJar01910', 'TestServerBridgeHostCrashRestartAndLogs01910',
    'TestServerBridgeHostStopSupervisedProcess01910', 'TestServerBridgeHostForgeArgsMode01910',
], "ServerBridge Host tests")
for forbidden in ['authlib-injector', 'patchAuthlib', 'rewriteCoreJar', 'server.properties =']:
    if forbidden in host:
        raise SystemExit(f"ServerBridge Хост содержит forbidden authlib/core patch поведение: {forbidden}")
for text, needle, label in [
    (preflight, 'serverbridge-host-01910.py', 'preflight'),
    (ci, 'serverbridge-host-01910.py', 'CI'),
]:
    if needle not in text:
        raise SystemExit(f"{label}: отсутствующий {needle!r}")
print("ServerBridge Хост 0.19.10+ рабочий контроль: OK")

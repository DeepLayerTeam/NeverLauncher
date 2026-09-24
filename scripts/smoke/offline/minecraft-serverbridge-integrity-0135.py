#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]

def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")

def require(text: str, needles: list[str], label: str) -> None:
    missing = [n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{label} missing: {', '.join(missing)}")

def version_tuple(value: str) -> tuple[int, int, int]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not m:
        raise SystemExit(f"invalid VERSION: {value}")
    return tuple(map(int, m.groups()))

version = read("VERSION").strip()
if version_tuple(version) < (0, 13, 5):
    raise SystemExit(f"Minecraft/ServerBridge integrity gate requires >=0.13.5, got {version}")

api_mig = read("services/api/internal/dbmigrate/sql/0019_minecraft_serverbridge_integrity_0135.sql")
cli_mig = read("cli/internal/dbmigrate/sql/0019_minecraft_serverbridge_integrity_0135.sql")
if api_mig != cli_mig:
    raise SystemExit("0.13.5 API/CLI migration 0019 differs")
require(api_mig, ["integrity_verified", "guard_attestation_sha256", "guard_evidence_sha256", "guard_sha256", "launcher_sha256", "launcher_version", "integrity_verified_at"], "Minecraft integrity migration")

model = read("services/api/internal/model/model.go")
require(model, ["IntegrityVerified", "GuardAttestationSHA256", "GuardEvidenceSHA256", "GuardSHA256", "LauncherSHA256", "LauncherVersion", "IntegrityVerifiedAt"], "MinecraftSession persisted integrity snapshot")

minecraft = read("services/api/internal/httpapi/minecraft_serverbridge_integrity_0135.go")
require(minecraft, [
    "guard-launch-integrity-v1", "evaluateMinecraftIntegrity0135", "guardReleasePolicies0134",
    "integrity_release_revoked", "evaluateServerBridgeJoinIntegrity0135", "requireMinecraftIntegrityForBridgeSession0135",
], "live Minecraft integrity enforcement")

auth = read("services/api/internal/httpapi/minecraft_auth_119.go")
require(auth, ["issueMinecraftSessionWithTrustAndIntegrity119", "evaluateMinecraftIntegrity0135", "snapshotFromGuardLaunchTicket0135", "IntegrityVerified"], "Minecraft credential integration")

bridge = read("services/api/internal/httpapi/server_bridge.go")
require(bridge, [
    "MinecraftSessionID", "MinecraftAccessToken", "requireMinecraftIntegrityForBridgeSession0135",
    "evaluateServerBridgeJoinIntegrity0135", "evaluateRegisteredBridgeIntegrity0135",
    "server.PluginSHA256 = \"\"", "server.IntegrityStatus = \"\"",
], "ServerBridge gameplay integrity integration")

plugins = read("services/api/internal/httpapi/bridge_plugins.go")
require(plugins, [
    "PluginSHA256", "validateBridgePluginMeasurement0135", "setIntegrityMeasurement0135",
    "validateBridgeRequestMeasurement0135", "evaluateServerBridgeJoinIntegrity0135",
    "serverbridge-artifact-integrity",
], "ServerBridge backend artifact enforcement")

plugin_policy = read("services/api/internal/httpapi/serverbridge_integrity_0135.go")
require(plugin_policy, [
    "serverbridge-artifact-sha256-v1", "NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON",
    "bridge_integrity_hash_rejected", "bridge_integrity_release_revoked", "bridge_integrity_heartbeat_required",
], "ServerBridge release policy")

java_integrity = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeIntegrity.java")
require(java_integrity, ["artifactSha256", "getProtectionDomain", "Files.isRegularFile", "MessageDigest.getInstance(\"SHA-256\")"], "ServerBridge JAR self-measurement")
java_client = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java")
require(java_client, ["pluginSha256", "requireIntegrity", "bridge_integrity_unavailable", "pluginVersion"], "ServerBridge fail-closed client")
proxy_family_source = read("plugins/proxy-family-common/src/main/java/ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.java")
require(proxy_family_source, ["BridgeIntegrity.artifactSha256", "new NeverLauncherApiClient(config"], "proxy-family runtime self-measurement")
bukkit_family_source = read("plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.java")
require(bukkit_family_source, ["BridgeIntegrity.artifactSha256", "NeverLauncherApiClient(config"], "Bukkit-family runtime self-measurement")
for platform, cls, expected in [("bukkit", "NeverLauncherBukkitBridge", "BUKKIT"), ("spigot", "NeverLauncherSpigotBridge", "SPIGOT"), ("paper", "NeverLauncherPaperBridge", "PAPER"), ("purpur", "NeverLauncherPurpurBridge", "PURPUR"), ("folia", "NeverLauncherFoliaBridge", "FOLIA")]:
    package = "bukkit" if platform == "bukkit" else platform
    source = read(f"plugins/{platform}-bridge/src/main/java/ru/neverlauncher/bridge/{package}/{cls}.java")
    require(source, ["extends BukkitFamilyBridgePlugin", f"BukkitFamilyPlatform.{expected}"], f"{platform} Bukkit-family adapter")

frontend = read("apps/desktop/src/main.tsx")
require(frontend, ["createServerJoinBeforeLaunch(username: string, minecraftAccessToken: string)", "minecraftAccessToken", "minecraftCredentials.accessToken"], "Desktop Minecraft→ServerBridge binding")

config = read("services/api/internal/config/config.go")
require(config, ["BridgeReleaseAllowlistJSON", "NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON", "velocitySha256", "paperSha256", "purpurSha256"], "production ServerBridge release policy")

build = read("scripts/build/bridge-plugins.sh")
require(build, ["BRIDGE_RELEASE_ALLOWLIST.json", "VELOCITY_SHA256", "PAPER_SHA256", "PURPUR_SHA256", '"sha256":"${VELOCITY_SHA256}"'], "release JAR hash generation")
release = read("scripts/release/build-release.sh")
require(release, ["BRIDGE_RELEASE_ALLOWLIST.json", "BRIDGE_PLUGIN_MANIFEST.json"], "release bundle ServerBridge integrity artifacts")

openapi = read("schemas/openapi.yaml")
require(openapi, ["minecraftAccessToken", "pluginSha256", "Current ServerBridge JAR SHA-256"], "OpenAPI integrity contract")

tests = read("services/api/internal/httpapi/minecraft_serverbridge_integrity_0135_test.go")
require(tests, [
    "TestServerBridgeArtifactIntegrity0135RejectsUnmeasuredAndRevokedBoundary",
    "bridge_integrity_request_measurement_mismatch", "bridge_integrity_heartbeat_required",
    "TestMinecraftIntegritySnapshot0135IsReevaluatedAgainstCurrentReleasePolicy", "integrity_release_revoked",
], "0.13.5 enforcement tests")

security = read("SECURITY.md")
require(security, ["Minecraft/ServerBridge integrity enforcement — 0.13.5", "application-level artifact allowlisting", "live revoke"], "0.13.5 security boundary")

ci = read(".github/workflows/ci.yml")
preflight = read("scripts/release/preflight.sh")
if "minecraft-serverbridge-integrity-0135.py" not in ci:
    raise SystemExit("0.13.5 integrity gate is not wired into CI")
if "minecraft-serverbridge-integrity-0135.py" not in preflight:
    raise SystemExit("0.13.5 integrity gate is not wired into preflight")

print(f"[NeverLauncher] Minecraft/ServerBridge integrity enforcement 0.13.5 gate OK: {version}")

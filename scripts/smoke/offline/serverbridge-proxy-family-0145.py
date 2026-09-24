#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 5):
    raise SystemExit("VERSION is older than 0.14.5")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


api_migration = read("services/api/internal/dbmigrate/sql/0025_proxy_family_0145.sql")
cli_migration = read("cli/internal/dbmigrate/sql/0025_proxy_family_0145.sql")
if api_migration != cli_migration:
    raise SystemExit("0.14.5 API/CLI proxy-family migrations differ")
require(api_migration, [
    "server_bridge_nodes_v2_kind_check",
    "'velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia'",
], "0.14.5 PostgreSQL migration")

settings = read("settings.gradle.kts")
require(settings, [
    'maven("https://hub.spigotmc.org/nexus/content/repositories/snapshots/")',
    'include("plugins:proxy-family-common")',
    'include("plugins:bungee-family-common")',
    'include("plugins:velocity-bridge")',
    'include("plugins:bungeecord-bridge")',
    'include("plugins:waterfall-bridge")',
], "Gradle proxy-family modules")

runtime = read("plugins/proxy-family-common/src/main/java/ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.java")
require(runtime, [
    "ScheduledExecutorService",
    "Executors.newSingleThreadScheduledExecutor",
    "NeverLauncherApiClient",
    "NodeIdentity.loadOrCreate",
    "BridgeIntegrity.artifactSha256",
    "nodePublicKey=",
    "validateJoinAsync",
    "triggerHeartbeat",
    "heartbeatExecutor.shutdownNow()",
    "validationExecutor.shutdownNow()",
    "new ArrayBlockingQueue<>(256)",
    "new ThreadPoolExecutor.AbortPolicy()",
], "shared production proxy runtime")

velocity = read("plugins/velocity-bridge/src/main/java/ru/neverlauncher/bridge/velocity/NeverLauncherVelocityBridge.java")
require(velocity, [
    "ProxyBridgeRuntime",
    "EventTask.async",
    "ProxyShutdownEvent",
    '"velocity"',
], "Velocity proxy adapter")

bungee_runtime = read("plugins/bungee-family-common/src/main/java/ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.java")
require(bungee_runtime, [
    "PreLoginEvent",
    "event.registerIntent(this)",
    "event.completeIntent(this)",
    "validateJoinAsync",
    "BungeeFamilyPlatform.detect",
    "actual != expectedPlatform",
    "registerCommand",
    "unregisterCommands",
], "Bungee-family runtime")
platform = read("plugins/bungee-family-common/src/main/java/ru/neverlauncher/bridge/bungee/BungeeFamilyPlatform.java")
require(platform, ['BUNGEECORD("bungeecord"', 'WATERFALL("waterfall"', 'brand.contains("waterfall")', 'brand.contains("bungeecord")'], "Bungee runtime discriminator")

for kind, class_name, expected in (
    ("bungeecord", "ru/neverlauncher/bridge/bungeecord/NeverLauncherBungeeCordBridge.java", "BungeeFamilyPlatform.BUNGEECORD"),
    ("waterfall", "ru/neverlauncher/bridge/waterfall/NeverLauncherWaterfallBridge.java", "BungeeFamilyPlatform.WATERFALL"),
):
    module = f"plugins/{kind}-bridge"
    java = read(f"{module}/src/main/java/{class_name}")
    descriptor = read(f"{module}/src/main/resources/bungee.yml")
    build = read(f"{module}/build.gradle.kts")
    require(java, ["extends BungeeFamilyBridgePlugin", expected], f"{kind} adapter")
    require(descriptor, ["main:", 'version: "${version}"', "NeverLauncher"], f"{kind} descriptor")
    require(build, ['implementation(project(":plugins:bungee-family-common"))', 'net.md-5:bungeecord-api:1.21-R0.5-SNAPSHOT'], f"{kind} Gradle build")

backend = read("services/api/internal/httpapi/server_bridge.go")
integrity = read("services/api/internal/httpapi/serverbridge_integrity_0135.go")
manifest = read("services/api/internal/httpapi/bridge_plugins.go")
require(backend, ['case "velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper", "purpur", "folia"'], "Backend server kind enforcement")
require(integrity, ["BungeeCordSHA256", "WaterfallSHA256", 'case "bungeecord":', 'case "waterfall":'], "Backend proxy artifact integrity policy")
for kind in ("velocity", "bungeecord", "waterfall"):
    require(manifest, [f'{{"id": "{kind}"', f'neverlauncher-{kind}-bridge-', f'"serverType": "{kind}"'], f"{kind} manifest/compatibility")

build = read("scripts/build/bridge-plugins.sh")
for kind in ("velocity", "bungeecord", "waterfall"):
    require(build, [f":plugins:{kind}-bridge:clean", f'neverlauncher-{kind}-bridge-${{VERSION}}.jar'], f"{kind} production build")
require(build, ["bungeeCordSha256", "waterfallSha256", "ProxyBridgeRuntime.class", "BungeeFamilyBridgePlugin.class", "bungee.yml"], "proxy release build/integrity")

config = read("services/api/internal/config/config.go")
require(config, ["bridgeReleaseRequiresProxyFamily0145", "BungeeCordSHA256", "WaterfallSHA256", "для 0.14.5+"], "production configuration validation")

openapi_gen = read("scripts/contracts/generate_openapi.py")
require(openapi_gen, ['enum":["velocity","bungeecord","waterfall","bukkit","spigot","paper","purpur","folia","fabric","forge","neoforge"]'], "OpenAPI proxy-family enum")

tests = read("services/api/internal/httpapi/serverbridge_proxy_family_0145_test.go")
require(tests, [
    "TestServerBridgeProxyFamilyKinds0145",
    "TestServerBridgeProxyFamilyIntegrityAllowlist0145",
    "TestBridgePluginsManifestIncludesProxyFamily0145",
], "proxy-family backend regressions")

runtime_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
compose_e2e = read("e2e/docker-compose.minecraft-e2e.yml")
require(runtime_e2e, [
    "compose up -d velocity bungeecord waterfall spigot paper purpur folia",
    "flow_for_server bungeecord-e2e-p3",
    "flow_for_server waterfall-e2e-p3",
    "neverlauncher-bungeecord-bridge.jar",
    "neverlauncher-waterfall-bridge.jar",
    "proxyFamilyRuntime:true",
], "real proxy runtime E2E")
require(compose_e2e, [
    "TYPE: BUNGEECORD", "TYPE: WATERFALL",
    "./runtime/plugins/bungeecord:/plugins:ro", "./runtime/plugins/waterfall:/plugins:ro",
], "BungeeCord/Waterfall Docker E2E")

migration_e2e = read("e2e/scripts/run-proxy-family-migration-e2e.sh")
require(migration_e2e, [
    "0024_bukkit_family_0144",
    "0025_proxy_family_0145",
    "for kind in velocity bungeecord waterfall",
    "invalid proxy kind bypassed PostgreSQL constraint",
], "0.14.4 -> 0.14.5 migration E2E")

preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
for text, label in ((preflight, "preflight"), (ci, "CI")):
    require(text, ["serverbridge-proxy-family-0145.py", "run-proxy-family-migration-e2e.sh"], f"0.14.5 {label} wiring")

print(f"NeverLauncher 0.14.5 Proxy family gate: OK ({version})")

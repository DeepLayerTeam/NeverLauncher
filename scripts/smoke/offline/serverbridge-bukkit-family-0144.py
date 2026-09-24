#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 4):
    raise SystemExit("VERSION is older than 0.14.4")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


api_migration = read("services/api/internal/dbmigrate/sql/0024_bukkit_family_0144.sql")
cli_migration = read("cli/internal/dbmigrate/sql/0024_bukkit_family_0144.sql")
if api_migration != cli_migration:
    raise SystemExit("0.14.4 API/CLI Bukkit-family migrations differ")
require(api_migration, [
    "server_bridge_nodes_v2_kind_check",
    "'velocity','bukkit','spigot','paper','purpur','folia'",
], "0.14.4 PostgreSQL migration")

settings = read("settings.gradle.kts")
require(settings, [
    'maven("https://hub.spigotmc.org/nexus/content/repositories/snapshots/")',
    'include("plugins:bukkit-family-common")',
    'include("plugins:bukkit-bridge")',
    'include("plugins:spigot-bridge")',
    'include("plugins:paper-bridge")',
    'include("plugins:purpur-bridge")',
    'include("plugins:folia-bridge")',
], "Gradle Bukkit-family modules")

runtime = read("plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.java")
require(runtime, [
    "AsyncPlayerPreLoginEvent",
    "ScheduledExecutorService",
    "Executors.newSingleThreadScheduledExecutor",
    "state.api.validateJoin",
    "state.api.heartbeat",
    "BridgeIntegrity.artifactSha256",
    "NodeIdentity.loadOrCreate",
    "actual != expectedPlatform",
    "disablePlugin(this)",
    "executor.shutdownNow()",
], "shared production Bukkit-family runtime")
for forbidden in ("Bukkit.getScheduler()", "runTask(", "runTaskAsynchronously("):
    if forbidden in runtime:
        raise SystemExit(f"Folia-safe runtime must not use legacy Bukkit scheduler: {forbidden}")

platform = read("plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyPlatform.java")
require(platform, [
    'BUKKIT("bukkit"', 'SPIGOT("spigot"', 'PAPER("paper"', 'PURPUR("purpur"', 'FOLIA("folia"',
    "RegionizedServer", "PurpurConfig", "ServerBuildInfo", "SpigotConfig",
], "runtime platform discriminator")

wrappers = {
    "bukkit": ("ru/neverlauncher/bridge/bukkit/NeverLauncherBukkitBridge.java", "BukkitFamilyPlatform.BUKKIT"),
    "spigot": ("ru/neverlauncher/bridge/spigot/NeverLauncherSpigotBridge.java", "BukkitFamilyPlatform.SPIGOT"),
    "paper": ("ru/neverlauncher/bridge/paper/NeverLauncherPaperBridge.java", "BukkitFamilyPlatform.PAPER"),
    "purpur": ("ru/neverlauncher/bridge/purpur/NeverLauncherPurpurBridge.java", "BukkitFamilyPlatform.PURPUR"),
    "folia": ("ru/neverlauncher/bridge/folia/NeverLauncherFoliaBridge.java", "BukkitFamilyPlatform.FOLIA"),
}
for kind, (java_rel, expected) in wrappers.items():
    module = f"plugins/{kind}-bridge"
    java = read(f"{module}/src/main/java/{java_rel}")
    descriptor = read(f"{module}/src/main/resources/plugin.yml")
    build = read(f"{module}/build.gradle.kts")
    require(java, ["extends BukkitFamilyBridgePlugin", expected], f"{kind} adapter")
    require(descriptor, ["main:", "version: ${version}", "api-version: '1.21'", "nlbridge:"], f"{kind} plugin descriptor")
    require(build, ['implementation(project(":plugins:bukkit-family-common"))', 'org.spigotmc:spigot-api:1.21.1-R0.1-SNAPSHOT'], f"{kind} Gradle build")
if "folia-supported: true" not in read("plugins/folia-bridge/src/main/resources/plugin.yml"):
    raise SystemExit("Folia plugin.yml must explicitly declare folia-supported: true")

backend = read("services/api/internal/httpapi/server_bridge.go")
integrity = read("services/api/internal/httpapi/serverbridge_integrity_0135.go")
manifest = read("services/api/internal/httpapi/bridge_plugins.go")
require(backend, ['case "velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper", "purpur", "folia"'], "Backend server kind enforcement")
require(integrity, ["BukkitSHA256", "SpigotSHA256", "FoliaSHA256", 'case "bukkit":', 'case "spigot":', 'case "folia":'], "Backend artifact integrity policy")
for kind in ("bukkit", "spigot", "paper", "purpur", "folia"):
    require(manifest, [f'{{"id": "{kind}"', f'neverlauncher-{kind}-bridge-', f'"serverType": "{kind}"'], f"{kind} manifest/compatibility")

release_commands = read("cli/cmd/neverlauncher/release_commands.go")
require(release_commands, ["BRIDGE_RELEASE_ALLOWLIST.json", "BRIDGE_PLUGIN_MANIFEST.json"], "release verification requires bridge policy artifacts")

build = read("scripts/build/bridge-plugins.sh")
for kind in ("bukkit", "spigot", "paper", "purpur", "folia"):
    require(build, [f":plugins:{kind}-bridge:clean", f'neverlauncher-{kind}-bridge-${{VERSION}}.jar'], f"{kind} production build")
require(build, ["bukkitSha256", "spigotSha256", "paperSha256", "purpurSha256", "foliaSha256", "folia-supported: true"], "release integrity allowlist")

config = read("services/api/internal/config/config.go")
require(config, ["bridgeReleaseRequiresBukkitFamily0144", "BukkitSHA256", "SpigotSHA256", "FoliaSHA256", "для 0.14.4+"], "production configuration validation")

openapi_gen = read("scripts/contracts/generate_openapi.py")
require(openapi_gen, ['enum":["velocity","bungeecord","waterfall","bukkit","spigot","paper","purpur","folia"]'], "OpenAPI Bukkit-family enum")

tests = read("services/api/internal/httpapi/serverbridge_bukkit_family_0144_test.go")
require(tests, [
    "TestServerBridgeBukkitFamilyKinds0144",
    "TestServerBridgeBukkitFamilyIntegrityAllowlist0144",
    "TestBridgePluginsManifestIncludesEntireBukkitFamily0144",
], "Bukkit-family backend regressions")

runtime_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
compose_e2e = read("e2e/docker-compose.minecraft-e2e.yml")
require(runtime_e2e, [
    "compose up -d velocity bungeecord waterfall spigot paper purpur folia",
    "flow_for_server spigot-e2e-p3",
    "flow_for_server folia-e2e-p3",
    "neverlauncher-spigot-bridge.jar",
    "neverlauncher-folia-bridge.jar",
    "bukkitFamilyRuntime:true",
], "real Spigot/Folia runtime E2E")
require(compose_e2e, [
    "TYPE: SPIGOT", "TYPE: FOLIA",
    "./runtime/plugins/spigot:/plugins:ro", "./runtime/plugins/folia:/plugins:ro",
], "Spigot/Folia Docker E2E")

migration_e2e = read("e2e/scripts/run-bukkit-family-migration-e2e.sh")
require(migration_e2e, [
    "0023_one_time_join_tickets_0143",
    "0024_bukkit_family_0144",
    "for kind in bukkit spigot paper purpur folia",
    "invalid ServerBridge kind bypassed PostgreSQL constraint",
], "0.14.3 -> 0.14.4 migration E2E")

preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
for text, label in ((preflight, "preflight"), (ci, "CI")):
    require(text, ["serverbridge-bukkit-family-0144.py", "run-bukkit-family-migration-e2e.sh"], f"0.14.4 {label} wiring")

print(f"NeverLauncher 0.14.4 Bukkit family gate: OK ({version})")

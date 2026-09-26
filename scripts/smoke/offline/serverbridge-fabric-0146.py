#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 6):
    raise SystemExit("VERSION is older than 0.14.6")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")

api_migration = read("services/api/internal/dbmigrate/sql/0026_fabric_server_bridge_0146.sql")
cli_migration = read("cli/internal/dbmigrate/sql/0026_fabric_server_bridge_0146.sql")
if api_migration != cli_migration:
    raise SystemExit("0.14.6 API/CLI Fabric migrations differ")
require(api_migration, [
    "server_bridge_nodes_v2_kind_check",
    "'fabric'",
    "'velocity'",
    "'folia'",
], "0.14.6 PostgreSQL migration")

settings = read("settings.gradle.kts")
require(settings, [
    'maven("https://maven.fabricmc.net/")',
    'include("plugins:fabric-bridge")',
], "Gradle Fabric module/repository")

build_gradle = read("plugins/fabric-bridge/build.gradle.kts")
require(build_gradle, [
    'id("net.fabricmc.fabric-loom-remap") version "1.17.21"',
    'minecraft("com.mojang:minecraft:1.21.1")',
    'mappings("net.fabricmc:yarn:1.21.1+build.3:v2")',
    'modImplementation("net.fabricmc:fabric-loader:0.16.14")',
    'modImplementation("net.fabricmc.fabric-api:fabric-api:0.116.17+1.21.1")',
    'include(project(":plugins:bridge-common"))',
], "Fabric Loom production build")

fabric_mod = read("plugins/fabric-bridge/src/main/resources/fabric.mod.json")
require(fabric_mod, [
    '"environment": "server"',
    '"ru.neverlauncher.bridge.fabric.NeverLauncherFabricBridge"',
    '"serverType": "fabric"',
    '"clientModRequired": false',
    '"fabric-api": ">=0.116.0+1.21.1"',
], "Fabric server-only metadata")

mixins = read("plugins/fabric-bridge/src/main/resources/neverlauncher.fabric.mixins.json")
accessor = read("plugins/fabric-bridge/src/main/java/ru/neverlauncher/bridge/fabric/mixin/ServerLoginNetworkHandlerAccessor.java")
require(mixins, ["ServerLoginNetworkHandlerAccessor", '"required": true', '"JAVA_21"'], "Fabric login accessor mixin")
require(accessor, ['@Mixin(ServerLoginNetworkHandler.class)', '@Accessor("profile")', '@Accessor("profileName")', '@Accessor("connection")'], "Fabric login accessor")

runtime = read("plugins/fabric-bridge/src/main/java/ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.java")
require(runtime, [
    "ServerLoginConnectionEvents.QUERY_START.register",
    "LoginSynchronizer synchronizer",
    "synchronizer.waitFor(gate)",
    "CompletableFuture.supplyAsync",
    "new ArrayBlockingQueue<>(256)",
    "new ThreadPoolExecutor.AbortPolicy()",
    "BridgeIntegrity.artifactSha256(getClass())",
    "NodeIdentity.loadOrCreate",
    'new NeverLauncherApiClient(config, identity, PLATFORM, BridgeDefaults.VERSION, pluginSha256)',
    'private static final String PLATFORM = "fabric"',
    "current.api.validateJoin",
    "current.api.heartbeat",
    "clientModRequired=false",
    "validationExecutor.shutdownNow()",
    "heartbeatExecutor.shutdownNow()",
], "Fabric production runtime")

backend = read("services/api/internal/httpapi/server_bridge.go")
integrity = read("services/api/internal/httpapi/serverbridge_integrity_0135.go")
manifest = read("services/api/internal/httpapi/bridge_plugins.go")
config = read("services/api/internal/config/config.go")
require(backend, ['"folia", "fabric"'], "Backend Fabric kind enforcement")
require(integrity, ["FabricSHA256", 'case "fabric":', "policy.FabricSHA256"], "Backend Fabric integrity policy")
require(config, ["bridgeReleaseRequiresFabric0146", "FabricSHA256", "для 0.14.6+ должна содержать fabricSha256"], "production Fabric release policy")
require(manifest, [
    '{"id": "fabric"',
    'neverlauncher-fabric-bridge-',
    '"serverType": "fabric"',
    '"descriptor": "fabric.mod.json"',
    '"clientModRequired": false',
], "Fabric manifest/compatibility")

build = read("scripts/build/bridge-plugins.sh")
require(build, [
    ":plugins:fabric-bridge:clean :plugins:fabric-bridge:remapJar",
    "neverlauncher-fabric-bridge-${VERSION}.jar",
    "fabricSha256",
    "FABRIC_SHA256",
    "fabric.mod.json",
    "META-INF/jars/bridge-common-",
    '"clientModRequired":false',
], "Fabric release build/integrity")

release = read("scripts/release/build-release.sh")
release_cli = read("cli/cmd/neverlauncher/release_commands.go")
require(release, ["paper purpur folia fabric"], "release bundle Fabric artifact")
require(release_cli, ['"neverlauncher-fabric-bridge-" + ver + ".jar"'], "release verification Fabric artifact")

openapi_gen = read("scripts/contracts/generate_openapi.py")
require(openapi_gen, ['"folia","fabric"'], "OpenAPI Fabric kind")

tests = read("services/api/internal/httpapi/serverbridge_fabric_0146_test.go")
require(tests, [
    "TestServerBridgeFabricKind0146",
    "TestServerBridgeFabricIntegrityAllowlist0146",
    "TestBridgePluginsManifestIncludesFabric0146",
], "Fabric backend regressions")

runtime_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
compose_e2e = read("e2e/docker-compose.minecraft-e2e.yml")
require(runtime_e2e, [
    "compose up -d velocity bungeecord waterfall spigot paper purpur folia fabric",
    "flow_for_server fabric-e2e-p3",
    "neverlauncher-fabric-bridge.jar",
    "fabricServerBridge:true",
    "health-fabric.json",
], "real Fabric runtime E2E")
require(compose_e2e, [
    "TYPE: FABRIC",
    'VERSION: "1.21.1"',
    'FABRIC_LOADER_VERSION: "0.16.14"',
    "MODRINTH_PROJECTS: fabric-api",
    "./runtime/plugins/fabric:/mods:ro",
], "Fabric Docker E2E")

migration_e2e = read("e2e/scripts/run-fabric-server-bridge-migration-e2e.sh")
require(migration_e2e, [
    "0025_proxy_family_0145",
    "0026_fabric_server_bridge_0146",
    "'fabric-0146','Fabric 0146','fabric'",
    "invalid Fabric kind bypassed PostgreSQL constraint",
], "0.14.5 -> 0.14.6 migration E2E")

preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
for text, label in ((preflight, "preflight"), (ci, "CI")):
    require(text, ["serverbridge-fabric-0146.py", "run-fabric-server-bridge-migration-e2e.sh"], f"0.14.6 {label} wiring")

print(f"NeverLauncher 0.14.6 Fabric Server Bridge gate: OK ({version})")

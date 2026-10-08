#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 4):
    raise SystemExit("VERSION является старый чем 0.14.4")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствующий {missing}")


api_migration = read("services/api/internal/dbmigrate/sql/0024_bukkit_family_0144.sql")
cli_migration = read("cli/internal/dbmigrate/sql/0024_bukkit_family_0144.sql")
if api_migration != cli_migration:
    raise SystemExit("0.14.4 API/CLI Bukkit-семейство миграция differ")
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
        raise SystemExit(f"Folia-безопасный среда выполнения должен не использовать устаревший Bukkit планировщик: {forbidden}")

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
    require(build, ['implementation(project(":plugins:bukkit-family-common"))', 'org.spigotmc:spigot-api:1.21.1-R0.1-SNAPSHOT', 'attributes["paperweight-mappings-namespace"] = "mojang"'], f"{kind} Gradle build")
if "folia-supported: true" not in read("plugins/folia-bridge/src/main/resources/plugin.yml"):
    raise SystemExit("Folia плагин.yml должен явно объявлять Folia-поддерживаемый: true")

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
require(openapi_gen, ['enum":["velocity","bungeecord","waterfall","bukkit","spigot","paper","purpur","folia","fabric","quilt","forge","neoforge","sponge","vanilla"]'], "OpenAPI Bukkit-family enum")

tests = read("services/api/internal/httpapi/serverbridge_bukkit_family_0144_test.go")
require(tests, [
    "TestServerBridgeBukkitFamilyKinds0144",
    "TestServerBridgeBukkitFamilyIntegrityAllowlist0144",
    "TestBridgePluginsManifestIncludesEntireBukkitFamily0144",
], "Bukkit-family backend regressions")

runtime_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
compose_e2e = read("e2e/docker-compose.minecraft-e2e.yml")
require(runtime_e2e, [
    "compose up -d velocity paper",
    "certify_aux_bridge spigot-e2e-p3",
    "certify_aux_bridge folia-e2e-p3",
    'wait_bridge_heartbeat "$service"',
    'capture_health_evidence "$service"',
    'spigot|paper|purpur|folia)',
    'NEVERLAUNCHER_E2E_BUKKIT_RECONNECT_COOLDOWN_SECONDS:-5',
    'wait_log "$service" "neverlauncher.join.denied username=$PLAYER_USERNAME"',
    "neverlauncher-spigot-bridge.jar",
    "neverlauncher-folia-bridge.jar",
    'FOLIA_SOURCE_COMMIT="2e7bc0721af95196c85500c7bb136aeea0bc12ce"',
    'FOLIA_MINECRAFT_VERSION="1.21.1"',
    'SPARK_SOURCE_REPOSITORY="https://github.com/lucko/spark.git"',
    'SPARK_SOURCE_COMMIT="f06de5761a5dee3c809ab9c6ebae6f052c55f7eb"',
    'SPARK_SOURCE_TAG="v1.10"',
    'SPARK_PATCH_VERSION="105"',
    'SPARK_MAVEN_VERSION="1.10.105-SNAPSHOT"',
    'BYTESOCKS_SOURCE_REPOSITORY="https://github.com/lucko/bytesocks-java-client.git"',
    'BYTESOCKS_SOURCE_COMMIT="b6147dcc8a9f1265ccf1491147d427fcfa7d2e27"',
    'BYTESOCKS_MAVEN_VERSION="1.0-20230828.145440-5"',
    'BYTESOCKS_BASE_VERSION="1.0-SNAPSHOT"',
    'materialize_pinned_bytesocks_dependency()',
    'BytesocksClient.create API',
    'channelId API',
    '<artifactId>Java-WebSocket</artifactId>',
    'NEVERLAUNCHER_SPARK_BUILD_MAVEN_REPO',
    'includeModule("me.lucko", "bytesocks-java-client")',
    'bytesocks-build.json',
    'bytesocksPinnedBuildDependency:true',
    'materialize_pinned_spark_paper_dependency()',
    ':spark-paper:shadowJar',
    'NEVERLAUNCHER_FOLIA_BUILD_MAVEN_REPO',
    'includeModule("me.lucko", "spark-paper")',
    'spark-paper-build.json',
    'foliaPinnedBuildDependency:true',
    'GIT_AUTHOR_NAME="NeverLauncher E2E"',
    'GIT_AUTHOR_EMAIL="neverlauncher-e2e@invalid.local"',
    'GIT_COMMITTER_NAME="NeverLauncher E2E"',
    'GIT_COMMITTER_EMAIL="neverlauncher-e2e@invalid.local"',
    "createMojmapPaperclipJar",
    "folia-runtime.json",
    "foliaPinnedRuntime:true",
    "bukkitFamilyRuntime:true",
], "real Spigot/Folia runtime E2E")
folia_materialize_start = runtime_e2e.index("materialize_pinned_folia_runtime() {")
folia_apply = runtime_e2e.index("./gradlew --no-daemon --stacktrace --init-script \"$init_script\" applyPatches", folia_materialize_start)
for marker in (
    'export GIT_AUTHOR_NAME="NeverLauncher E2E"',
    'export GIT_AUTHOR_EMAIL="neverlauncher-e2e@invalid.local"',
    'export GIT_COMMITTER_NAME="NeverLauncher E2E"',
    'export GIT_COMMITTER_EMAIL="neverlauncher-e2e@invalid.local"',
):
    position = runtime_e2e.index(marker, folia_materialize_start)
    if position >= folia_apply:
        raise SystemExit("Закреплённый Folia Git идентичность является не inherited через paperweight patch subprocesses")

bytesocks_helper = runtime_e2e.index("materialize_pinned_bytesocks_dependency() {")
bytesocks_commit_check = runtime_e2e.index('[[ "$resolved_commit" == "$BYTESOCKS_SOURCE_COMMIT" ]]', bytesocks_helper)
bytesocks_api_check = runtime_e2e.index("BytesocksClient.create API", bytesocks_helper)
bytesocks_build = runtime_e2e.index("mvn --batch-mode --no-transfer-progress -Dmaven.test.skip=true package", bytesocks_helper)
bytesocks_evidence = runtime_e2e.index('> "$RUNTIME_DIR/bytesocks-build.json"', bytesocks_helper)
if not (bytesocks_commit_check < bytesocks_api_check < bytesocks_build < bytesocks_evidence):
    raise SystemExit("Закреплённый bytesocks исходник/API проверка должен precede Maven сборка и свидетельство")

spark_helper = runtime_e2e.index("materialize_pinned_spark_paper_dependency() {")
spark_commit_check = runtime_e2e.index('[[ "$resolved_commit" == "$SPARK_SOURCE_COMMIT" ]]', spark_helper)
spark_patch_check = runtime_e2e.index('[[ "$patch_count" == "$SPARK_PATCH_VERSION" ]]', spark_helper)
spark_build = runtime_e2e.index('./gradlew --no-daemon --stacktrace --init-script "$init_script" :spark-paper:shadowJar', spark_helper)
folia_spark_call = runtime_e2e.index("materialize_pinned_spark_paper_dependency", folia_materialize_start)
folia_paperclip = runtime_e2e.index("createMojmapPaperclipJar", folia_materialize_start)
folia_paperclip_lookup = runtime_e2e.index("find \"$source_dir/build/libs\" -maxdepth 1 -type f -name '*paperclip*.jar'", folia_materialize_start)
if 'find "$source_dir/Folia-Server/build/libs"' in runtime_e2e[folia_materialize_start:]:
    raise SystemExit("Закреплённый Folia среда выполнения по-прежнему searches устаревший Folia-Server/build/libs paperclip путь")
if folia_paperclip_lookup <= folia_paperclip:
    raise SystemExit("Закреплённый Folia paperclip артефакт обнаружение должен запуск после createMojmapPaperclipJar")
spark_bytesocks_call = runtime_e2e.index("materialize_pinned_bytesocks_dependency", spark_helper)
if not (spark_bytesocks_call < spark_commit_check < spark_patch_check < spark_build):
    raise SystemExit("Закреплённый spark-Paper source/version проверка должен precede его сборка")
if folia_spark_call >= folia_paperclip:
    raise SystemExit("Закреплённый spark-Paper зависимость должен быть материализовать до Folia paperclip сборка")

require(compose_e2e, [
    "TYPE: SPIGOT", "TYPE: FOLIA",
    "PAPER_CUSTOM_JAR: /folia-runtime/folia-1.21.1-2e7bc0721af9-paperclip.jar",
    "./runtime/plugins/spigot:/plugins:ro", "./runtime/plugins/folia:/plugins:ro",
    "./runtime/folia-runtime:/folia-runtime:ro",
], "Spigot/Folia Docker E2E")


allow_marker = 'wait_log "$service" "neverlauncher.join.allowed username=$PLAYER_USERNAME"'
deny_marker = 'wait_log "$service" "neverlauncher.join.denied username=$PLAYER_USERNAME"'
cooldown_marker = 'NEVERLAUNCHER_E2E_BUKKIT_RECONNECT_COOLDOWN_SECONDS:-5'
if not (runtime_e2e.index(allow_marker) < runtime_e2e.index(cooldown_marker) < runtime_e2e.index(deny_marker)):
    raise SystemExit("Bukkit-семейство E2E переподключение cooldown является не между разрешать и запрещать сеть утверждение")

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
require(ci, ["foliaPinnedBuildDependency", "bytesocksPinnedBuildDependency", "spark-paper-build.json", "bytesocks-build.json", "f06de5761a5dee3c809ab9c6ebae6f052c55f7eb", "b6147dcc8a9f1265ccf1491147d427fcfa7d2e27", "1.10.105-SNAPSHOT", "1.0-20230828.145440-5"], "pinned Folia build dependency CI evidence")

print(f"NeverLauncher 0.14.4 Bukkit семейство контроль: OK ({version})")

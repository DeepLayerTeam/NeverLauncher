#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path
import re

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 7):
    raise SystemExit("VERSION ниже 0.14.7")


def read(path):
    return (root / path).read_text(encoding="utf-8")


def require(text, needles, label):
    missing = [n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


api_migration = read(
    "services/api/internal/dbmigrate/sql/0027_forge_neoforge_server_bridge.sql"
)
cli_migration = resource_read_text(root, "cli/internal/dbmigrate/sql/0027_forge_neoforge_server_bridge.sql")
if api_migration != cli_migration:
    raise SystemExit("Миграции Forge/NeoForge API/CLI 0.14.7 отличаются")
require(
    api_migration,
    ["server_bridge_nodes_v2_kind_check", "'forge'", "'neoforge'", "'fabric'"],
    "Миграция PostgreSQL 0.14.7",
)
settings = read("settings.gradle.kts")
require(
    settings,
    [
        'maven("https://maven.minecraftforge.net/")',
        'maven("https://maven.neoforged.net/releases/")',
        'include("plugins:modloader-family-common")',
        'include("plugins:forge-bridge")',
        'include("plugins:neoforge-bridge")',
    ],
    "Модули Gradle семейства Forge",
)
runtime = read(
    "plugins/modloader-family-common/src/main/java/ru/launcher/bridge/modloader/ModLoaderBridgeRuntime.java"
)
require(
    runtime,
    [
        "new ArrayBlockingQueue<>(256)",
        "new ThreadPoolExecutor.AbortPolicy()",
        "Supplier<Path> artifactPathSupplier",
        "resolveArtifactPath()",
        "BridgeIntegrity.artifactSha256(artifactPath)",
        "BridgeIntegrity.artifactSha256(artifactAnchor)",
        "NodeIdentity.loadOrCreate",
        "validateJoinAsync",
        "current.api.validateJoin",
        "current.api.heartbeat",
        "validationExecutor.shutdownNow()",
        "heartbeatExecutor.shutdownNow()",
    ],
    "Общий промышленный Runtime семейства загрузчиков модов",
)
forge = read(
    "plugins/forge-bridge/src/main/java/ru/launcher/bridge/forge/LauncherForgeBridge.java"
)
neo = read(
    "plugins/neoforge-bridge/src/main/java/ru/launcher/bridge/neoforge/LauncherNeoForgeBridge.java"
)
require(
    forge,
    [
        "GatherLoginConfigurationTasksEvent",
        "ConfigurationTaskContext",
        'new ConfigurationTask.Type("launcher:join_validation")',
        "event.addTask(new JoinValidationTask",
        "runtime.validateJoinAsync",
        "ServerLifecycleHooks.getCurrentServer()",
        "server.execute(() ->",
        "ctx.finish(JOIN_VALIDATION_TASK)",
        "connection.disconnect",
        "ModList.get()",
        "getModFileById(MOD_ID)",
        "getFile().getFilePath()",
        "LauncherForgeBridge::loadedArtifactPath",
        '"forge"',
    ],
    "Проверка входа Forge до загрузки игрового мира",
)
require(
    neo,
    [
        "RegisterConfigurationTasksEvent",
        "modEventBus.addListener(this::onRegisterConfigurationTasks)",
        "event.register(new JoinValidationTask",
        'new ConfigurationTask.Type(ResourceLocation.fromNamespaceAndPath(MOD_ID, "join_validation"))',
        "runtime.validateJoinAsync",
        "ServerLifecycleHooks.getCurrentServer()",
        "server.execute(() ->",
        "listener.finishCurrentTask(JOIN_VALIDATION_TASK)",
        "listener.disconnect",
        "ModList.get()",
        "getModFileById(MOD_ID)",
        "getFile().getFilePath()",
        "LauncherNeoForgeBridge::loadedArtifactPath",
        '"neoforge"',
    ],
    "Проверка входа NeoForge до загрузки игрового мира",
)
forge_build = read("plugins/forge-bridge/build.gradle.kts")
neo_build = read("plugins/neoforge-bridge/build.gradle.kts")
require(
    forge_build,
    [
        "net.minecraftforge.gradle",
        "1.21.1-52.1.16",
        "minecraft.mavenizer(this)",
        "maven(fg.forgeMaven)",
        "maven(fg.minecraftLibsMaven)",
        'configurations.create("bridgeRuntime")',
        'implementation(minecraft.dependency("net.minecraftforge:forge:1.21.1-52.1.16"))',
        'add(bridgeRuntime.name, project(":plugins:modloader-family-common"))',
    ],
    "Промышленная сборка Forge",
)
require(
    neo_build,
    [
        "net.neoforged.moddev",
        "21.1.251",
        'configurations.create("bridgeRuntime")',
        'add(bridgeRuntime.name, project(":plugins:modloader-family-common"))',
    ],
    "Промышленная сборка NeoForge",
)
require(
    read("plugins/forge-bridge/src/main/resources/META-INF/mods.toml"),
    [
        'displayTest="IGNORE_SERVER_VERSION"',
        'side="SERVER"',
        'versionRange="[1.21.1,1.21.2)"',
    ],
    "Метаданные Forge только для сервера",
)
require(
    read("plugins/neoforge-bridge/src/main/resources/META-INF/neoforge.mods.toml"),
    [
        'displayTest="IGNORE_SERVER_VERSION"',
        'side="SERVER"',
        'versionRange="[1.21.1,1.21.2)"',
    ],
    "Метаданные NeoForge только для сервера",
)
backend = read("services/api/internal/httpapi/server_bridge.go")
integrity = read("services/api/internal/httpapi/serverbridge_integrity.go")
config = read("services/api/internal/config/config.go")
manifest = read("services/api/internal/httpapi/bridge_plugins.go")
require(
    backend,
    ['"fabric"', '"forge"', '"neoforge"'],
    "Проверка типов Forge и NeoForge на Backend",
)
require(
    integrity,
    ["ForgeSHA256", "NeoForgeSHA256", 'case "forge":', 'case "neoforge":'],
    "Пространства имён целостности Forge/NeoForge",
)
require(
    config,
    [
        "bridgeReleaseRequiresForgeFamily0147",
        "ForgeSHA256",
        "NeoForgeSHA256",
        "для 0.14.7+",
    ],
    "Политика промышленного релиза 0.14.7",
)
for kind, descriptor in (
    ("forge", "META-INF/mods.toml"),
    ("neoforge", "META-INF/neoforge.mods.toml"),
):
    require(
        manifest,
        [
            f'{{"id": "{kind}"',
            f"launcher-{kind}-bridge-",
            f'"descriptor": "{descriptor}"',
        ],
        f"{kind} manifest",
    )
build = read("scripts/build/bridge-plugins.sh")
require(
    build,
    [
        ":plugins:forge-bridge:clean",
        ":plugins:neoforge-bridge:clean",
        "forgeSha256",
        "neoforgeSha256",
        "ModLoaderBridgeRuntime.class",
        "META-INF/mods.toml",
        "META-INF/neoforge.mods.toml",
    ],
    "Сборка релиза Forge/NeoForge",
)
release_builder = read("scripts/release/build-release.sh")
bridge_loop = re.search(r"for bridge in ([A-Za-z0-9_ ]+); do", release_builder)
if not bridge_loop or not {"fabric", "forge", "neoforge"}.issubset(set(bridge_loop.group(1).split())):
    raise SystemExit("Артефакты Forge/NeoForge отсутствуют в фактическом цикле сборки релиза")
require(
    read("cli/cmd/launcher/release_commands.go"),
    [
        '"launcher-forge-bridge-" + ver + ".jar"',
        '"launcher-neoforge-bridge-" + ver + ".jar"',
    ],
    "Проверка артефактов релиза Forge/NeoForge",
)
require(
    read("scripts/contracts/generate_openapi.py"),
    ['"fabric"', '"forge"', '"neoforge"'],
    "Типы Forge и NeoForge в OpenAPI",
)
tests = read("services/api/internal/httpapi/serverbridge_forge_neoforge_test.go")
require(
    tests,
    [
        "TestForgeNeoForgeKinds0147",
        "TestForgeNeoForgeIntegrityNamespaces0147",
        "TestForgeNeoForgeManifest0147",
    ],
    "Регрессионные проверки Forge/NeoForge",
)
e2e = read("e2e/scripts/run-minecraft-e2e.sh")
compose = read("e2e/docker-compose.minecraft-e2e.yml")
probe = read("e2e/scripts/minecraft-login-probe.py")
require(
    e2e,
    [
        "compose up -d velocity paper",
        "certify_aux_bridge forge-e2e-p3",
        "certify_aux_bridge neoforge-e2e-p3",
        'wait_bridge_heartbeat "$service"',
        'capture_health_evidence "$service"',
        'forgeNeoForgeServerBridge:($mode == "full")',
        "health-forge.json",
        "health-neoforge.json",
        "forge)",
        "neoforge)",
        "allow_probe_mode",
        "deny_probe_mode",
        "--enter-configuration",
        "--drive-neoforge-configuration",
        "--allow-pre-configuration-disconnect",
        "LAUNCHER_E2E_MODLOADER_PROBE_HOLD_SECONDS",
        "${allow_probe_mode[@]}",
        "${deny_probe_mode[@]}",
    ],
    "Сквозные проверки Runtime Forge/NeoForge",
)
flow = e2e[
    e2e.index("flow_for_server() {") : e2e.index("flow_for_server velocity-e2e-p3")
]
if flow.index("neoforge)") < flow.index("forge)"):
    raise SystemExit("режим проверки NeoForge: требуется «явное указание после режима Forge»")
require(
    probe,
    [
        "--enter-configuration",
        "--drive-neoforge-configuration",
        "--allow-pre-configuration-disconnect",
        "LOGIN_SET_COMPRESSION = 0x03",
        "SERVERBOUND_LOGIN_ACKNOWLEDGED = 0x03",
        "CONFIG_CLIENTBOUND_PING = 0x05",
        "CONFIG_CLIENTBOUND_SELECT_KNOWN_PACKS = 0x0E",
        "CONFIG_SERVERBOUND_PONG = 0x05",
        "CONFIG_SERVERBOUND_SELECT_KNOWN_PACKS = 0x07",
        "zlib.decompress",
        "framed_packet",
        "enter_configuration",
        "drive_neoforge_configuration",
        "login-eof",
        "login-reset",
        "login-disconnect",
        "send_protocol_packet(sock, acknowledgement, compression_threshold)",
        "knownPacksResponses={known_packs_responses}",
        "mode=configuration",
        "loginAcknowledged={str(login_acknowledged).lower()}",
    ],
    "Проверка входа Minecraft 1.21.1 Forge/NeoForge с сохранением состояния",
)
require(
    compose,
    [
        "TYPE: FORGE",
        "TYPE: NEOFORGE",
        'FORGE_VERSION: "52.1.16"',
        'NEOFORGE_VERSION: "21.1.251"',
        "./runtime/plugins/forge:/mods:ro",
        "./runtime/plugins/neoforge:/mods:ro",
    ],
    "Сквозная проверка Forge/NeoForge в Docker",
)
migration = read("e2e/scripts/run-forge-neoforge-server-bridge-migration-e2e.sh")
require(
    migration,
    [
        "0026_fabric_server_bridge_0146",
        "0027_forge_neoforge_server_bridge_0147",
        "kind IN ('forge','neoforge')",
        "non-canonical kind bypassed constraint",
    ],
    "Сквозная проверка миграции с 0.14.6 на 0.14.7",
)
for text, label in (
    (read("scripts/release/preflight.sh"), "preflight"),
    (read(".github/workflows/ci.yml"), "CI"),
):
    require(
        text,
        [
            "serverbridge-forge-neoforge.py",
            "run-forge-neoforge-server-bridge-migration-e2e.sh",
        ],
        f"0.14.7 {label} wiring",
    )
print(f"Launcher 0.14.7: проверка ServerBridge для Forge и NeoForge: OK ({version})")

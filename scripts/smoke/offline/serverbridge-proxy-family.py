#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 5):
    raise SystemExit("VERSION ниже 0.14.5")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


api_migration = read("services/api/internal/dbmigrate/sql/0025_proxy_family.sql")
cli_migration = resource_read_text(root, "cli/internal/dbmigrate/sql/0025_proxy_family.sql")
if api_migration != cli_migration:
    raise SystemExit("Миграции семейства прокси API/CLI 0.14.5 различаются")
require(
    api_migration,
    [
        "server_bridge_nodes_v2_kind_check",
        "'velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia'",
    ],
    "Миграция PostgreSQL 0.14.5",
)

settings = read("settings.gradle.kts")
require(
    settings,
    [
        'maven("https://hub.spigotmc.org/nexus/content/repositories/snapshots/")',
        'include("plugins:proxy-family-common")',
        'include("plugins:bungee-family-common")',
        'include("plugins:velocity-bridge")',
        'include("plugins:bungeecord-bridge")',
        'include("plugins:waterfall-bridge")',
    ],
    "Модули Gradle семейства прокси",
)

runtime = read(
    "plugins/proxy-family-common/src/main/java/ru/launcher/bridge/proxy/ProxyBridgeRuntime.java"
)
require(
    runtime,
    [
        "ScheduledExecutorService",
        "Executors.newSingleThreadScheduledExecutor",
        "LauncherApiClient",
        "NodeIdentity.loadOrCreate",
        "BridgeIntegrity.artifactSha256",
        "nodePublicKey=",
        "validateJoinAsync",
        "triggerHeartbeat",
        "heartbeatExecutor.shutdownNow()",
        "validationExecutor.shutdownNow()",
        "new ArrayBlockingQueue<>(256)",
        "new ThreadPoolExecutor.AbortPolicy()",
    ],
    "Общий промышленный Runtime семейства прокси",
)

velocity = read(
    "plugins/velocity-bridge/src/main/java/ru/launcher/bridge/velocity/LauncherVelocityBridge.java"
)
require(
    velocity,
    [
        "ProxyBridgeRuntime",
        "EventTask.async",
        "ProxyShutdownEvent",
        '"velocity"',
    ],
    "Прокси-адаптер Velocity",
)

bungee_runtime = read(
    "plugins/bungee-family-common/src/main/java/ru/launcher/bridge/bungee/BungeeFamilyBridgePlugin.java"
)
require(
    bungee_runtime,
    [
        "PreLoginEvent",
        "event.registerIntent(this)",
        "event.completeIntent(this)",
        "validateJoinAsync",
        "BungeeFamilyPlatform.detect",
        "actual != expectedPlatform",
        "registerCommand",
        "unregisterCommands",
    ],
    "Runtime семейства Bungee",
)
platform = read(
    "plugins/bungee-family-common/src/main/java/ru/launcher/bridge/bungee/BungeeFamilyPlatform.java"
)
require(
    platform,
    [
        'BUNGEECORD("bungeecord"',
        'WATERFALL("waterfall"',
        'brand.contains("waterfall")',
        'brand.contains("bungeecord")',
    ],
    "Определение варианта Bungee в Runtime",
)

for kind, class_name, expected in (
    (
        "bungeecord",
        "ru/launcher/bridge/bungeecord/LauncherBungeeCordBridge.java",
        "BungeeFamilyPlatform.BUNGEECORD",
    ),
    (
        "waterfall",
        "ru/launcher/bridge/waterfall/LauncherWaterfallBridge.java",
        "BungeeFamilyPlatform.WATERFALL",
    ),
):
    module = f"plugins/{kind}-bridge"
    java = read(f"{module}/src/main/java/{class_name}")
    descriptor = read(f"{module}/src/main/resources/bungee.yml")
    build = read(f"{module}/build.gradle.kts")
    require(java, ["extends BungeeFamilyBridgePlugin", expected], f"{kind} adapter")
    require(
        descriptor, ["main:", 'version: "${version}"', "Launcher"], f"{kind} descriptor"
    )
    require(
        build,
        [
            'implementation(project(":plugins:bungee-family-common"))',
            "net.md-5:bungeecord-api:1.21-R0.5-SNAPSHOT",
        ],
        f"{kind} сборка Gradle",
    )

backend = read("services/api/internal/httpapi/server_bridge.go")
integrity = read("services/api/internal/httpapi/serverbridge_integrity.go")
manifest = read("services/api/internal/httpapi/bridge_plugins.go")
require(
    backend,
    [
        'case "velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper", "purpur", "folia"'
    ],
    "Проверка типа сервера в Backend",
)
require(
    integrity,
    ["BungeeCordSHA256", "WaterfallSHA256", 'case "bungeecord":', 'case "waterfall":'],
    "Политика целостности артефактов прокси Backend",
)
for kind in ("velocity", "bungeecord", "waterfall"):
    require(
        manifest,
        [
            f'{{"id": "{kind}"',
            f"launcher-{kind}-bridge-",
            f'"serverType": "{kind}"',
        ],
        f"{kind} manifest/compatibility",
    )

build = read("scripts/build/bridge-plugins.sh")
for kind in ("velocity", "bungeecord", "waterfall"):
    require(
        build,
        [
            f":plugins:{kind}-bridge:clean",
            f"launcher-{kind}-bridge-${{VERSION}}.jar",
        ],
        f"{kind} промышленная сборка",
    )
require(
    build,
    [
        "bungeeCordSha256",
        "waterfallSha256",
        "ProxyBridgeRuntime.class",
        "BungeeFamilyBridgePlugin.class",
        "bungee.yml",
    ],
    "Сборка релиза прокси и проверка целостности",
)

config = read("services/api/internal/config/config.go")
require(
    config,
    [
        "bridgeReleaseRequiresProxyFamily0145",
        "BungeeCordSHA256",
        "WaterfallSHA256",
        "для 0.14.5+",
    ],
    "Проверка производственной конфигурации",
)

openapi_gen = read("scripts/contracts/generate_openapi.py")
require(
    openapi_gen,
    [
        'enum":["velocity","bungeecord","waterfall","bukkit","spigot","paper","purpur","folia","fabric","quilt","forge","neoforge","sponge","vanilla"]'
    ],
    "Перечень семейств прокси в OpenAPI",
)

tests = read("services/api/internal/httpapi/serverbridge_proxy_family_test.go")
require(
    tests,
    [
        "TestServerBridgeProxyFamilyKinds0145",
        "TestServerBridgeProxyFamilyIntegrityAllowlist0145",
        "TestBridgePluginsManifestIncludesProxyFamily0145",
    ],
    "Регрессионные проверки Backend для семейства прокси",
)

runtime_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
compose_e2e = read("e2e/docker-compose.minecraft-e2e.yml")
require(
    runtime_e2e,
    [
        "compose up -d velocity paper",
        "flow_for_server velocity-e2e-p3",
        "certify_aux_bridge bungeecord-e2e-p3",
        "certify_aux_bridge waterfall-e2e-p3",
        'wait_bridge_heartbeat "$service"',
        'capture_health_evidence "$service"',
        "velocity|bungeecord|waterfall)",
        "LAUNCHER_E2E_PROXY_RECONNECT_COOLDOWN_SECONDS:-5",
        'wait_log "$service" "launcher.join.denied username=$PLAYER_USERNAME"',
        "launcher-bungeecord-bridge.jar",
        "launcher-waterfall-bridge.jar",
        "proxyFamilyRuntime:true",
    ],
    "Сквозная проверка настоящего Runtime прокси",
)
require(
    compose_e2e,
    [
        "TYPE: BUNGEECORD",
        "TYPE: WATERFALL",
        '- "25570:25577"',
        "./runtime/plugins/bungeecord:/plugins:ro",
        "./runtime/plugins/waterfall:/plugins:ro",
    ],
    "Сквозные проверки Velocity/BungeeCord/Waterfall в Docker",
)
if '- "25570:25565"' in compose_e2e:
    raise SystemExit(
        "Порт E2E-узла Velocity 25570 перенаправлен на 25565, но Runtime Velocity 3.4 использует порт 25577"
    )


allow_marker = 'wait_log "$service" "launcher.join.allowed username=$PLAYER_USERNAME"'
deny_marker = 'wait_log "$service" "launcher.join.denied username=$PLAYER_USERNAME"'
cooldown_marker = "LAUNCHER_E2E_PROXY_RECONNECT_COOLDOWN_SECONDS:-5"
if not (
    runtime_e2e.index(allow_marker)
    < runtime_e2e.index(cooldown_marker)
    < runtime_e2e.index(deny_marker)
):
    raise SystemExit(
        "Интервал повторного подключения proxy E2E не расположен между проверками разрешения и отказа в сети"
    )

migration_e2e = read("e2e/scripts/run-proxy-family-migration-e2e.sh")
require(
    migration_e2e,
    [
        "0024_bukkit_family_0144",
        "0025_proxy_family_0145",
        "for kind in velocity bungeecord waterfall",
        "invalid proxy kind bypassed PostgreSQL constraint",
    ],
    "Сквозная проверка миграции с 0.14.4 на 0.14.5",
)

preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
for text, label in ((preflight, "preflight"), (ci, "CI")):
    require(
        text,
        ["serverbridge-proxy-family.py", "run-proxy-family-migration-e2e.sh"],
        f"0.14.5 {label} wiring",
    )

print(f"Launcher 0.14.5: проверка семейства прокси: OK ({version})")

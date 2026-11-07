#!/usr/bin/env python3
from pathlib import Path
import json, re

ROOT = Path(__file__).resolve().parents[3]


def read(p):
    return (ROOT / p).read_text(encoding="utf-8")


def require(text, needles, label):
    for n in needles:
        if n not in text:
            raise SystemExit(f"{label}: отсутствует {n!r}")


version = read("VERSION").strip()
parts = tuple(int(x) for x in version.split("-", 1)[0].split(".")[:3])
if parts < (0, 19, 8):
    raise SystemExit(f"Ожидалась VERSION >= 0.19.8, получено {version}")
targets = json.loads(read("serverbridge/targets.json"))
expected = [
    "velocity",
    "bungeecord",
    "waterfall",
    "bukkit",
    "spigot",
    "paper",
    "purpur",
    "folia",
    "fabric",
    "quilt",
    "forge",
    "neoforge",
    "sponge",
    "vanilla",
]
if [x["id"] for x in targets["targets"]] != expected:
    raise SystemExit("Несовпадение: «универсальная группа из 14 целевых платформ»")
profiles = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/BridgeAdapterProfiles.java"
)
require(
    profiles,
    [
        'Map.entry("quilt"',
        'Map.entry("sponge"',
        'Map.entry("vanilla"',
        "rejectUncertifiedHybrid",
        "mohist",
        "arclight",
        "magma",
        "catserver",
        "banner",
        "cardboard",
    ],
    "Профили возможностей и строгая проверка гибридного режима",
)
require(
    read(
        "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/BridgeRuntimeDescriptor.java"
    ),
    ["BridgeAdapterProfiles.find", "runtimeCapabilities"],
    "Публикация возможностей Runtime",
)
require(
    read(
        "plugins/bukkit-family-common/src/main/java/ru/launcher/bridge/bukkit/BukkitFamilyBridgePlugin.java"
    ),
    [
        "BridgeAdapterCapability.REGION_SAFE_SCHEDULER",
        "BridgeAdapterCapability.TELEMETRY_BOUNDED_WORLD_COUNTERS",
        "BridgeAdapterProfiles.rejectUncertifiedHybrid",
    ],
    "Выполнение возможностей Bukkit",
)
quilt = read(
    "plugins/quilt-bridge/src/main/java/ru/launcher/bridge/quilt/LauncherQuiltBridge.java"
)
require(
    quilt,
    [
        "QuiltLoader.getConfigDir()",
        "ServerLoginConnectionEvents.QUERY_START",
        "validateJoin",
        "recordPlatformTelemetry",
        "startControlChannel",
        '"loader.quilt"',
    ],
    "Промышленный адаптер Quilt",
)
require(
    read("plugins/quilt-bridge/src/main/resources/fabric.mod.json"),
    ['"quilt_loader"', '"environment": "server"', '"clientModRequired": false'],
    "Метаданные Quilt для сервера",
)
sponge = read(
    "plugins/sponge-bridge/src/main/java/ru/launcher/bridge/sponge/LauncherSpongeBridge.java"
)
require(
    sponge,
    [
        '@Plugin("launcher_sponge_bridge")',
        "ServerSideConnectionEvent.Auth",
        "validateJoin",
        "server.scheduler().executor(container)",
        "recordPlatformTelemetry",
        "startControlChannel",
    ],
    "Нативный адаптер Sponge",
)
vanilla = read(
    "plugins/vanilla-bridge/src/main/java/ru/launcher/bridge/vanilla/LauncherVanillaBridge.java"
)
rcon = read(
    "plugins/vanilla-bridge/src/main/java/ru/launcher/bridge/vanilla/VanillaRconClient.java"
)
require(
    vanilla,
    [
        "enable-rcon",
        "VanillaRconClient",
        "logs/latest.log",
        "recordPlatformTelemetry",
        "startControlChannel",
        "server.console",
    ],
    "Вспомогательный процесс Vanilla",
)
require(
    rcon,
    [
        "Minecraft Source-RCON",
        "socket.connect",
        "writeLEInt",
        "RCON authentication failed",
    ],
    "Клиент сетевого протокола RCON для Vanilla",
)
for forbidden in ["ProcessBuilder", "Runtime.getRuntime().exec", "/bin/sh", "cmd.exe"]:
    if forbidden in vanilla or forbidden in rcon:
        raise SystemExit(
            f"Вспомогательный процесс Vanilla содержит запрещённый запуск командной оболочки: {forbidden}"
        )
migration = read(
    "services/api/internal/dbmigrate/sql/0039_universal_server_adapters_0198.sql"
)
require(
    migration,
    ["'quilt'", "'sponge'", "'vanilla'", "separate certification"],
    "Миграция 0.19.8",
)
for hybrid in [
    "'mohist'",
    "'arclight'",
    "'magma'",
    "'catserver'",
    "'banner'",
    "'cardboard'",
]:
    if hybrid in migration:
        raise SystemExit(f"Гибридный тип попал в канонический набор видов БД: {hybrid}")
hybrid = json.loads(read("serverbridge/hybrid-targets.json"))
if any(x.get("status") != "not-certified" for x in hybrid["targets"]):
    raise SystemExit("Гибридная цель неожиданно прошла сертификацию")
cert = read("serverbridge/certify_release.py")
require(
    cert,
    [
        "'quilt':'quiltSha256'",
        "'sponge':'spongeSha256'",
        "'vanilla':'vanillaSha256'",
        "universalServerAdapters",
        "hybridCertificationPolicy",
    ],
    "сертификация выпуска",
)
build = read("scripts/build/bridge-plugins.sh")
require(
    build,
    [
        ":plugins:quilt-bridge:remapJar",
        ":plugins:sponge-bridge:jar",
        ":plugins:vanilla-bridge:jar",
        "QUILT_SHA256",
        "SPONGE_SHA256",
        "VANILLA_SHA256",
    ],
    "Промышленная сборка",
)
openapi = read("scripts/contracts/generate_openapi.py")
require(
    openapi,
    ['"fabric","quilt","forge","neoforge","sponge","vanilla"'],
    "Перечень платформ в OpenAPI",
)
print(
    "Проверка производственного релиза универсальных серверных адаптеров ServerBridge 0.19.8+: OK (14 адаптеров, гибридные конфигурации отклоняются)"
)

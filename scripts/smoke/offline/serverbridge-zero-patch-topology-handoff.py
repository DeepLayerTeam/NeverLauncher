#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text().strip()
if tuple(int(x) for x in version.split(".")[:3]) < (0, 14, 8):
    raise SystemExit("VERSION ниже 0.14.8")


def read(p):
    return (root / p).read_text(encoding="utf-8")


def require(text, needles, label):
    missing = [n for n in needles if n not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


api = read(
    "services/api/internal/dbmigrate/sql/0028_zero_patch_topology_handoff_0148.sql"
)
cli = resource_read_text(root, "cli/internal/dbmigrate/sql/0028_zero_patch_topology_handoff_0148.sql")
if api != cli:
    raise SystemExit("Миграции API/CLI 0.14.8 отличаются")
require(
    api,
    [
        "server_bridge_topology_edges_v2",
        "server_bridge_handoffs_v2",
        "source_identity_epoch",
        "target_identity_epoch",
        "server_bridge_handoffs_active_target_player_uq",
    ],
    "Миграция PostgreSQL 0.14.8",
)
repo = read("services/api/internal/repository/server_bridge_v2.go")
require(
    repo,
    [
        "CreateServerBridgeHandoff",
        "GetActiveServerBridgeHandoff",
        "ConsumeServerBridgeHandoff",
        "ListServerBridgeTopology",
        "pg_advisory_xact_lock(1408",
        "a.status='active'",
        "a.expires_at>$3",
        "a.binding_epoch=server_bridge_join_tickets_v2.binding_epoch",
        "target_identity_epoch=$3",
        "server_bridge_topology_edges_v2",
    ],
    "Хранилище передачи управления в PostgreSQL",
)
http = (
    read("services/api/internal/httpapi/server_bridge_topology_handoff_0148.go")
    + read("services/api/internal/httpapi/bridge_plugins.go")
    + read("services/api/internal/httpapi/routes_bridge.go")
)
require(
    http,
    [
        "serverBridgeCreateHandoff0148",
        "serverBridgeTopology0148",
        "serverBridgeHandoffTTL0148 = 30 * time.Second",
        "activeHandoff0148",
        "consumeHandoff0148",
        "authorization",
        "proxy-handoff",
    ],
    "Runtime топологии и передачи управления по HTTP",
)
config = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/BridgeConfig.java"
)
client = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/LauncherApiClient.java"
)
require(
    config,
    [
        "ensureZeroPatchConfig",
        "No Minecraft/proxy configuration is modified",
        "handoffUrl()",
    ],
    "Начальная настройка конфигурации без патчей",
)
require(
    client,
    ["createHandoff", "config.handoffPath()", 'sendSignedWithFailover("POST"'],
    "Клиент подписанной передачи управления",
)
proxy = read(
    "plugins/proxy-family-common/src/main/java/ru/launcher/bridge/proxy/ProxyBridgeRuntime.java"
)
velocity = read(
    "plugins/velocity-bridge/src/main/java/ru/launcher/bridge/velocity/LauncherVelocityBridge.java"
)
bungee = read(
    "plugins/bungee-family-common/src/main/java/ru/launcher/bridge/bungee/BungeeFamilyBridgePlugin.java"
)
require(
    proxy,
    ["createHandoffAsync", "current.api.createHandoff"],
    "Общий Runtime передачи управления для прокси",
)
require(
    velocity,
    ["ServerPreConnectEvent", "createHandoff", "ServerResult.denied"],
    "Проверка передачи управления Velocity",
)
require(
    bungee,
    [
        "ServerConnectEvent",
        "preparedHandoffs",
        "createHandoffAsync",
        "event.setCancelled(true)",
        "event.getPlayer().connect",
    ],
    "Проверка передачи управления Bungee/Waterfall",
)
openapi = read("scripts/contracts/generate_openapi.py")
require(
    openapi,
    ["/api/v1/server-bridge/handoff", "BridgeHandoffRequest"],
    "Контракт передачи управления в OpenAPI",
)
require(
    read("services/api/internal/httpapi/routes_bridge.go"),
    ["/api/v1/server-bridge/topology"],
    "Маршрут топологии",
)
migration = read("e2e/scripts/run-zero-patch-topology-handoff-migration-e2e.sh")
require(
    migration,
    [
        "0027_forge_neoforge_server_bridge_0147",
        "0028_zero_patch_topology_handoff_0148",
        "server_bridge_topology_edges_v2",
        "server_bridge_handoffs_v2",
    ],
    "Сквозная проверка миграции с 0.14.7 на 0.14.8",
)
print(f"Launcher 0.14.8: проверка топологии без патчей и передачи управления: OK ({version})")

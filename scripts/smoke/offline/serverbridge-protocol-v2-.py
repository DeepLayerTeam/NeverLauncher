#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 1):
    raise SystemExit("VERSION ниже 0.14.1")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


api_migration = read(
    "services/api/internal/dbmigrate/sql/0021_serverbridge_protocol_v2_0141.sql"
)
cli_migration = resource_read_text(root, "cli/internal/dbmigrate/sql/0021_serverbridge_protocol_v2_0141.sql")
if api_migration != cli_migration:
    raise SystemExit("Миграции ServerBridge API/CLI 0.14.1 отличаются")
require(
    api_migration,
    [
        "server_bridge_nodes_v2",
        "server_bridge_join_tickets_v2",
        "server_bridge_textures_v2",
        "protocol_version = 2",
        "server_bridge_nodes_v2_kind_check",
        "server_bridge_join_v2_username_normalized_check",
        "server_bridge_join_v2_binding_epoch_check",
        "uq_server_bridge_join_v2_active_player",
        "credential-rotation-required",
        "launcher_persistence_snapshots_950",
    ],
    "ServerBridge Protocol v2 migration",
)

repo = read("services/api/internal/repository/server_bridge_v2.go")
require(
    repo,
    [
        "type ServerBridgeRepository interface",
        "pg_advisory_xact_lock(1401",
        "pg_advisory_xact_lock(1402",
        "status='consumed'",
        "status='invalidated'",
        '"sourceOfTruth": "postgresql"',
    ],
    "PostgreSQL ServerBridge repository",
)

handler = read("services/api/internal/httpapi/handler.go")
require(handler, ["configureRepositoryV2(s.Repo)"], "ServerBridge repository wiring")
protocol = read("services/api/internal/httpapi/server_bridge_protocol_0191.go")
bridge = (
    read("services/api/internal/httpapi/server_bridge.go")
    + read("services/api/internal/httpapi/server_bridge_persistence_v2.go")
    + protocol
)
require(
    bridge,
    [
        "serverBridgeProtocolV2",
        "serverBridgeProtocolV3",
        "serverBridgeSupportedProtocols0191",
        "ConsumeServerBridgeJoinTicket",
        "validBridgeServerKindV2",
        "one-time atomic join tickets",
        '"sourceOfTruth": "memory-dev-test"',
    ],
    "ServerBridge v2 runtime",
)
plugins = read("services/api/internal/httpapi/bridge_plugins.go")
require(
    plugins + protocol,
    [
        "decodeBridgeHeartbeat0191",
        "decodeBridgeValidateJoin0191",
        "http.StatusUpgradeRequired",
        "serverbridge_protocol_unsupported",
        "serverBridgeProtocolV2",
        "consumeJoinV2(join, redemption)",
    ],
    "Применение ограничений конечных точек ServerBridge v2",
)
java = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/LauncherApiClient.java"
)
defaults = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/BridgeDefaults.java"
)
require(
    java,
    ["protocolVersion", "BridgeDefaults.PROTOCOL_VERSION"],
    "ServerBridge Java client",
)
require(
    defaults,
    ["PROTOCOL_VERSION = 3", "LEGACY_PROTOCOL_VERSION = 2"],
    "Текущие константы Java ServerBridge v3 и константы последовательного обновления v2",
)
contract_tests = read(
    "services/api/internal/httpapi/server_bridge_protocol_0191_test.go"
)
require(
    contract_tests,
    [
        "v2 rolling-upgrade contract rejected",
        "Protocol v2 contract must reject Protocol v3 feature field",
        "v2 rolling heartbeat",
    ],
    "Регрессионные тесты последовательного обновления ServerBridge v2",
)

tests = read("services/api/internal/httpapi/server_bridge_test.go") + read(
    "services/api/internal/httpapi/bridge_plugins_test.go"
)
require(
    tests,
    [
        "replayed has-joined must be denied",
        "legacy bridge protocol accepted",
        "http.StatusUpgradeRequired",
    ],
    "Регрессионные тесты ServerBridge v2",
)

e2e = read("e2e/scripts/run-minecraft-e2e.sh")
require(
    e2e,
    [
        "protocolVersion:2",
        "server_bridge_join_tickets_v2",
        "status='consumed'",
        'sourceOfTruth == "postgresql"',
    ],
    "Сквозная проверка Minecraft, PostgreSQL и ServerBridge",
)

print(
    f"Launcher ServerBridge Protocol v2 rolling-compatibility + PostgreSQL source-of-truth gate: OK ({version})"
)

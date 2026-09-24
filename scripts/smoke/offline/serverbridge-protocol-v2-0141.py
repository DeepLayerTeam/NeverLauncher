#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 1):
    raise SystemExit("VERSION is older than 0.14.1")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")

api_migration = read("services/api/internal/dbmigrate/sql/0021_serverbridge_protocol_v2_0141.sql")
cli_migration = read("cli/internal/dbmigrate/sql/0021_serverbridge_protocol_v2_0141.sql")
if api_migration != cli_migration:
    raise SystemExit("0.14.1 API/CLI ServerBridge migrations differ")
require(api_migration, [
    "server_bridge_nodes_v2",
    "server_bridge_join_tickets_v2",
    "server_bridge_textures_v2",
    "protocol_version = 2",
    "server_bridge_nodes_v2_kind_check",
    "server_bridge_join_v2_username_normalized_check",
    "server_bridge_join_v2_binding_epoch_check",
    "uq_server_bridge_join_v2_active_player",
    "credential-rotation-required",
    "neverlauncher_persistence_snapshots_950",
], "ServerBridge Protocol v2 migration")

repo = read("services/api/internal/repository/server_bridge_v2.go")
require(repo, [
    "type ServerBridgeRepository interface",
    "pg_advisory_xact_lock(1401",
    "pg_advisory_xact_lock(1402",
    "status='consumed'",
    "status='invalidated'",
    '"sourceOfTruth": "postgresql"',
], "PostgreSQL ServerBridge repository")

handler = read("services/api/internal/httpapi/handler.go")
require(handler, ["configureRepositoryV2(s.Repo)"], "ServerBridge repository wiring")
bridge = read("services/api/internal/httpapi/server_bridge.go") + read("services/api/internal/httpapi/server_bridge_persistence_v2.go")
require(bridge, [
    "serverBridgeProtocolV2 = 2",
    "ConsumeServerBridgeJoinTicket",
    "subtle.ConstantTimeCompare",
    "secure ServerBridge token generation failed",
    "validBridgeServerKindV2",
    "one-time atomic join tickets",
    '"sourceOfTruth": "memory-dev-test"',
], "ServerBridge v2 runtime")
plugins = read("services/api/internal/httpapi/bridge_plugins.go")
require(plugins, [
    "ProtocolVersion int",
    "http.StatusUpgradeRequired",
    "serverbridge_protocol_unsupported",
    "валидный pluginSha256 обязательны для Protocol v2",
    "consumeJoinV2(join)",
], "ServerBridge v2 endpoint enforcement")
java = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java")
defaults = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeDefaults.java")
require(java, ["protocolVersion", "BridgeDefaults.PROTOCOL_VERSION"], "ServerBridge Java client")
require(defaults, ["PROTOCOL_VERSION = 2"], "ServerBridge Java protocol constant")

tests = read("services/api/internal/httpapi/server_bridge_test.go") + read("services/api/internal/httpapi/bridge_plugins_test.go")
require(tests, [
    "replayed has-joined must be denied",
    "legacy bridge protocol accepted",
    "http.StatusUpgradeRequired",
], "ServerBridge v2 regression tests")

e2e = read("e2e/scripts/run-minecraft-e2e.sh")
require(e2e, [
    r'\"protocolVersion\":2',
    "server_bridge_join_tickets_v2",
    "status='consumed'",
    'sourceOfTruth == "postgresql"',
], "Minecraft PostgreSQL ServerBridge E2E")

print(f"NeverLauncher 0.14.1 ServerBridge Protocol v2 + PostgreSQL source-of-truth gate: OK ({version})")

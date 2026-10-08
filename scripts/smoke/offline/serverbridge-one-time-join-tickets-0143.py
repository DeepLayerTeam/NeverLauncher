#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 3):
    raise SystemExit("VERSION is older than 0.14.3")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


api_migration = read("services/api/internal/dbmigrate/sql/0023_one_time_join_tickets_0143.sql")
cli_migration = read("cli/internal/dbmigrate/sql/0023_one_time_join_tickets_0143.sql")
if api_migration != cli_migration:
    raise SystemExit("0.14.3 API/CLI one-time join ticket migrations differ")
require(api_migration, [
    "ticket_version INTEGER NOT NULL DEFAULT 1",
    "issued_identity_epoch",
    "issued_key_fingerprint",
    "redeemed_identity_epoch",
    "redeemed_key_fingerprint",
    "redeemed_nonce_hash",
    "uq_server_bridge_join_v2_redemption_nonce_0143",
    "DELETE FROM minecraft_joins",
    "status TEXT NOT NULL DEFAULT 'active'",
    "consumed_at TIMESTAMPTZ",
    "minecraft_joins_0143_terminal_check",
], "0.14.3 migration")

helper = read("services/api/internal/httpapi/server_bridge_join_tickets_0143.go")
require(helper, [
    "serverBridgeJoinTicketVersion0143 = 2",
    "make([]byte, 24)",
    "rand.Read(buf)",
    'return "jt_" + base64.RawURLEncoding.EncodeToString(buf), nil',
    "sha256.Sum256(nonce)",
    "ServerBridgeJoinRedemption",
], "secure join ticket helper")
if "UnixNano" in helper or "time.Now" in helper:
    raise SystemExit("0.14.3 ticket identifier helper contains predictable entropy fallback")

repo = read("services/api/internal/repository/server_bridge_v2.go")
require(repo, [
    "TicketVersion = 2",
    "issued_identity_epoch",
    "issued_key_fingerprint",
    "redeemed_identity_epoch",
    "redeemed_key_fingerprint",
    "redeemed_nonce_hash",
    "redeemed_by_ip",
    "ConsumeServerBridgeJoinTicket",
    "j.ticket_version=2",
    "j.issued_identity_epoch=$3",
    "n.identity_epoch=$3",
], "PostgreSQL ServerBridge one-time redemption")

minecraft_repo = read("services/api/internal/repository/postgres.go")
minecraft_http = read("services/api/internal/httpapi/minecraft_auth_119.go")
require(minecraft_repo, [
    "ConsumeMinecraftJoin",
    "status='consumed'",
    "consumed_at=",
    "status='active'",
], "PostgreSQL Yggdrasil consume-once repository")
require(minecraft_http, [
    "ConsumeMinecraftJoin",
    "only the first concurrent /hasJoined",
], "Yggdrasil one-time /hasJoined")

serverbridge_test = read("services/api/internal/httpapi/server_bridge_join_tickets_0143_test.go")
yggdrasil_test = read("services/api/internal/httpapi/minecraft_auth_119_test.go")
require(serverbridge_test, [
    "TestOneTimeJoinTicket0143CSPRNGIdentifier",
    "TestOneTimeJoinTicket0143BindsIdentityAndConsumesExactlyOnce",
    "expected exactly one ticket redemption",
    "redemption audit proof was not persisted",
], "ServerBridge one-time regression tests")
require(yggdrasil_test, [
    "one-time Yggdrasil join replay",
    "http.StatusNoContent",
], "Yggdrasil replay regression test")

migration_e2e = read("e2e/scripts/run-one-time-join-ticket-migration-e2e.sh")
require(migration_e2e, [
    "0022_serverbridge_crypto_node_identities_0142",
    "0023_one_time_join_tickets_0143",
    "legacy-ticket-0142",
    "legacyServerBridgeTicketInvalidated:true",
    "legacyYggdrasilJoinsDiscarded:true",
    "redemptionProofPersisted:true",
], "0.14.2 -> 0.14.3 migration E2E")

main_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
require(main_e2e, [
    ".data.oneTime == true",
    ".data.ticketVersion == 2",
    "redemption_state=",
    "redeemed_nonce_hash",
    "validate_join paper-e2e-p3",
], "Minecraft one-time ticket E2E")

preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
for text, label in [(preflight, "preflight"), (ci, "CI")]:
    require(text, [
        "serverbridge-one-time-join-tickets-0143.py",
        "run-one-time-join-ticket-migration-e2e.sh",
    ], f"0.14.3 {label} wiring")

openapi = read("schemas/openapi.yaml")
require(openapi, [
    "One-Time Join Tickets",
    "one-time join ticket",
], "OpenAPI one-time join documentation")

print(f"NeverLauncher 0.14.3 One-Time Join Tickets gate: OK ({version})")

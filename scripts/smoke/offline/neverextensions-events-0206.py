#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")

def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(message)

version = tuple(int(x) for x in read("VERSION").strip().split(".")[:3])
require(version >= (0, 20, 6), "VERSION must be >= 0.20.6")

migration = read("services/api/internal/dbmigrate/sql/0045_neverextensions_events_hooks_0206.sql")
for token in (
    "extension_event_log", "extension_event_subscriptions", "extension_event_deliveries", "extension_event_dead_letters",
    "UNIQUE (event_type, idempotency_key)", "REFERENCES extension_event_log(sequence) ON DELETE CASCADE",
    "REFERENCES extension_event_subscriptions(id) ON DELETE CASCADE", "next_attempt_at", "lease_until", "lease_token", "extension_event_delivery_lease_state", "payload_sha256",
):
    require(token in migration, f"event migration missing {token}")
dead = migration[migration.index("CREATE TABLE IF NOT EXISTS extension_event_dead_letters"):]
require("REFERENCES extension_event_subscriptions" not in dead, "DLQ must survive unsubscribe")

bus = read("services/api/internal/eventbus/bus_0206.go")
for token in (
    '"project.before-save"', '"project.saved"', '"release.before-publish"', '"release.published"',
    '"package.before-publish"', '"package.published"', '"storage.before-write"', '"storage.file-written"',
    '"serverbridge.event.received"', '"audit.event.created"', "DispatchSync", "HookTimeout", "LeaseExtensionEventDeliveries",
    "RetryExtensionEventDelivery", "DeadLetterExtensionEventDelivery", "SetSubscriptionsEnabled", "IdempotencyKey", "OrderingKey",
):
    require(token in bus, f"event bus missing {token}")

repo = read("services/api/internal/repository/extension_events_0206.go")
for token in (
    "FOR UPDATE OF d SKIP LOCKED", "pe.ordering_key=e.ordering_key", "ON CONFLICT(event_type,idempotency_key)",
    "SetExtensionEventSubscriptionsEnabled", "sql.LevelSerializable", "newEventLeaseToken0206", "lease_token=$3", "JOIN extension_installs", "current_state='enabled'", "status='processing'", "status='dead'",
):
    require(token in repo, f"event repository missing {token}")

host = read("services/api/internal/extensionhost/host_0205.go")
for token in (
    'GET /v1/events/subscriptions', 'POST /v1/events/subscriptions', 'DELETE /v1/events/subscriptions/{subscriptionId}',
    "NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN", "validateCallbackURL0206", "IsLoopback", "events:subscribe", "events:sync",
    "DeliverExtensionEvent", "DeliverExtensionHook", "CheckRedirect",
):
    require(token in host, f"Extension Host event protocol missing {token}")

for rel in (
    "services/api/internal/httpapi/admin_crud.go",
    "services/api/internal/httpapi/admin_handlers.go",
    "services/api/internal/httpapi/package_product.go",
):
    text = read(rel)
    require("0206" in text, f"{rel} is not wired to event hooks")

bridge = read("services/api/internal/httpapi/server_bridge_events_0194.go")
require("ServerBridgeReceived" in bridge and "appendEvents0194" in bridge, "ServerBridge events are not bridged after verified append")

memory = read("services/api/internal/repository/memory.go")
postgres = read("services/api/internal/repository/postgres.go")
require("SetAuditEventSink" in memory and "SetAuditEventSink" in postgres, "audit event sink missing")

main = read("services/api/cmd/neverlauncher-api/main.go")
for token in ("eventbus.New", "SetAuditEventSink", "SetEventBus", "SetDispatcher", "events.Start"):
    require(token in main, f"Backend Event Bus wiring missing {token}")

routes = read("services/api/internal/httpapi/routes_packages.go")
for path in (
    "/api/v1/admin/extension-events",
    "/api/v1/admin/extension-events/subscriptions",
    "/api/v1/admin/extension-events/dead-letters",
):
    require(path in routes, f"Admin event diagnostics route missing {path}")

schema = read("schemas/neverlauncher-extension-events.schema.json")
require("project.before-save" in schema and "serverbridge.event.received" in schema and "audit.event.created" in schema, "event schema incomplete")

openapi = read("schemas/openapi.yaml")
for path in (
    '"/api/v1/admin/extension-events"',
    '"/api/v1/admin/extension-events/subscriptions"',
    '"/api/v1/admin/extension-events/dead-letters"',
):
    require(path in openapi, f"OpenAPI missing {path}")

prod = read("cli/cmd/neverlauncher/release_commands.go")
for table in ("extension_event_log", "extension_event_subscriptions", "extension_event_deliveries", "extension_event_dead_letters"):
    require(table in prod, f"productionTables missing {table}")

for envfile in ("deploy/production/env.production.example", "cli/cmd/neverlauncher/templates/production/env.production.example"):
    env = read(envfile)
    for key in (
        "NEVERLAUNCHER_EXTENSION_EVENTS_ENABLED=", "NEVERLAUNCHER_EXTENSION_EVENTS_WORKER_INTERVAL_MS=",
        "NEVERLAUNCHER_EXTENSION_EVENTS_LEASE_SECONDS=", "NEVERLAUNCHER_EXTENSION_EVENTS_HOOK_TIMEOUT_MS=",
        "NEVERLAUNCHER_EXTENSION_EVENTS_MAX_ATTEMPTS=", "NEVERLAUNCHER_EXTENSION_EVENTS_BASE_RETRY_MS=",
        "NEVERLAUNCHER_EXTENSION_EVENTS_MAX_RETRY_SECONDS=", "NEVERLAUNCHER_EXTENSION_EVENTS_BATCH_SIZE=",
    ):
        require(key in env, f"{envfile} missing {key}")

print("NeverExtensions Events & Hooks 0.20.6 production gate: OK")

#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text, needles, label):
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{label}: отсутствует {needle!r}")


version = read("VERSION").strip()
base = tuple(int(x) for x in version.split("-", 1)[0].split(".")[:3])
if base < (0, 19, 12):
    raise SystemExit(
        f"Security & Certification: требуется версия не ниже 0.19.12, получено {version}"
    )
security = read("services/api/internal/httpapi/server_bridge_security.go")
identity = read("services/api/internal/httpapi/server_bridge_identity.go")
protocol = read("services/api/internal/httpapi/server_bridge_protocol.go")
events = read("services/api/internal/httpapi/server_bridge_events.go")
control = read("services/api/internal/httpapi/server_bridge_control.go")
client = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/LauncherApiClient.java"
)
trust = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/BridgeControlTrust.java"
)
event_record = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/BridgeEventRecord.java"
)
build = read("scripts/build/bridge-plugins.sh")
cert = read("serverbridge/certify_release.py")
cli = read("cli/cmd/launcher/serverbridge_release.go")
contracts = read("scripts/contracts/generate_openapi.py")
tests = read("services/api/internal/httpapi/server_bridge_security_test.go")
event_tests = read("services/api/internal/httpapi/server_bridge_events_test.go")
harness = read(
    "e2e/java/ru/launcher/bridge/common/ServerBridgeSecurityCertification01912Harness.java"
)
preflight = read("scripts/release/preflight.sh")
ci = read(".github/workflows/ci.yml")
e2e = read("e2e/scripts/run-serverbridge-security-certification-e2e.sh")

require(
    security,
    [
        "Launcher-ServerBridge-Protocol-v3",
        "serverbridge3-security-01912",
        "serverBridgeNodeRequestCanonical01912",
        "serverBridgeEventCanonical01912",
        "serverBridgeControlCanonical01912",
        "ServerBridgeControlPreviousSigningPrivateKey",
    ],
    "Канонический домен v3",
)
require(
    protocol,
    [
        "securityCapabilityDigest",
        "capabilitySignature",
        "previousCapabilitySignature",
        "activeSigningKeyFingerprint",
    ],
    "подписанное согласование возможностей",
)
require(
    identity,
    [
        "X-Launcher-Security-Profile",
        "X-Launcher-Capability-Digest",
        "X-Launcher-Runtime-Id",
        "serverbridge_capability_downgrade_detected",
        "serverbridge_runtime_binding_mismatch",
    ],
    "Привязка узла v3",
)
require(
    events,
    [
        "securityCapabilityDigest",
        "nodeKeyFingerprint",
        "serverBridgeEventCanonical01912",
        "serverbridge_event_security_binding_invalid",
    ],
    "подписи событий",
)
require(
    control,
    [
        "identityEpoch",
        "v3SigningPublicKey",
        "previousV3SigningPublicKey",
        "serverBridgeControlCanonical01912",
        "legacyKey = *previousKey",
    ],
    "подписи команд и ротация ключей",
)
require(
    client,
    [
        "SUPPORTED_PROTOCOLS = List.of(BridgeDefaults.PROTOCOL_VERSION)",
        "Protocol v3 downgrade detected",
        "BridgeProtocolSecurity.REQUIRED_FEATURES",
        "X-Launcher-Runtime-Id",
        "X-Launcher-Capability-Digest",
    ],
    "защита моста от отката версии и угроз Runtime",
)
if (
    "LEGACY_PROTOCOL_VERSION)"
    in client.split("SUPPORTED_PROTOCOLS", 1)[1].split(";", 1)[0]
):
    raise SystemExit("«0.19.12 bridge»: запрещено «предлагать протокол v2»")
require(
    trust,
    [
        "verifyCapabilities",
        "persistPins",
        "previousPublicKey",
        "command endpoint can never bootstrap trust",
    ],
    "доверие при оперативной ротации ключей",
)
require(
    event_record,
    [
        "BridgeProtocolSecurity.eventCanonical",
        "nodeKeyFingerprint",
        "securityCapabilityDigest",
    ],
    "Подписывание событий протокола v3",
)
require(
    build,
    [
        '"schemaVersion":"3.0"',
        '"release":"ServerBridge 3"',
        "serverbridge3-security-01912",
        "088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4",
    ],
    "Разрешённый список релиза ServerBridge 3",
)
require(
    cert,
    [
        "SECURITY_PROFILE",
        "SECURITY_FEATURES",
        "securityCapabilityDigest",
        "BridgeProtocolSecurity.class",
    ],
    "сертификация выпуска",
)
require(
    cli,
    [
        "serverBridgeSecurityCertificationRequired01912",
        "ServerBridge 3 release allowlist security metadata mismatch",
    ],
    "проверка релиза в CLI",
)
require(
    contracts,
    [
        "serverbridge3-security-01912",
        "securityCapabilityDigest",
        "activeSigningKeyFingerprint",
        "previousCapabilitySignature",
        "nodeKeyFingerprint",
    ],
    "контракт безопасности OpenAPI v3",
)
require(
    tests,
    [
        "NodeCanonicalRejectsTamper",
        "EventRejectsTamper",
        "CommandCanonicalRejectsReplayAcrossRuntime",
        "AllowlistRejectsTamperedBridge",
        "SecurityFeatureSetIsExact",
    ],
    "тесты противодействия атакам на Go",
)
require(
    event_tests,
    ["TestServerBridgeEventMemoryAckReplay0194"],
    "проверка повторов событий и идемпотентности",
)
require(
    e2e,
    [
        "TARGETS=(velocity bungeecord waterfall bukkit spigot paper purpur folia fabric quilt forge neoforge sponge vanilla)",
        'for target in "${TARGETS[@]}"',
    ],
    "Выполнение сквозных проверок для каждой целевой платформы",
)
# Docker-бэкенд использует нелокальное имя HTTP-хоста. Для моста v3 нужен
# закреплённый якорь доверия; молчаливое HTTP TOFU было бы снижением защиты.
minecraft_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
compose_e2e = read("e2e/docker-compose.minecraft-e2e.yml")
require(
    minecraft_e2e,
    [
        "CONTROL_PUBLIC_KEY=",
        "LAUNCHER_E2E_CONTROL_PUBLIC_KEY=$CONTROL_PUBLIC_KEY",
        '"openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"',
    ],
    "формирование ключей управления Minecraft E2E",
)
if (
    compose_e2e.count(
        "LAUNCHER_CONTROL_BACKEND_PUBLIC_KEY: ${LAUNCHER_E2E_CONTROL_PUBLIC_KEY:"
    )
    != 10
):
    raise SystemExit(
        "Каждый Docker-адаптер ServerBridge должен закреплять ключ подписи управляющего API"
    )

require(
    harness,
    [
        "overlap key rotation",
        "retired previous key cannot authorize rotation after finalize",
        "capability downgrade rejected",
        "tampered bridge artifact rejected by certified hash",
        "replayed event preserves original signed sequence",
        "tampered/runtime-replayed command rejected",
        "tampered/runtime-replayed event rejected",
        "tampered node runtime rejected",
    ],
    "Среда атакующих тестов Runtime",
)

matrix = json.loads(read("serverbridge/security-e2e-matrix.json"))
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
required = {
    "canonical-v3-domain",
    "capability-downgrade",
    "tampered-bridge-artifact",
    "tampered-node-request",
    "tampered-event",
    "replayed-event",
    "tampered-command",
    "replayed-command",
    "runtime-instance-rebind",
    "online-key-rotation",
}
if (
    matrix.get("targets") != expected
    or set(matrix.get("requiredScenarios", [])) != required
    or matrix.get("coverage") != "all-required-scenarios-on-every-target"
):
    raise SystemExit("Отсутствует: «полная сквозная матрица ServerBridge 3»")
for text, needle, label in [
    (preflight, "serverbridge-security-certification.py", "preflight gate"),
    (
        preflight,
        "run-serverbridge-security-certification-e2e.sh",
        "preflight E2E",
    ),
    (ci, "serverbridge-security-certification.py", "CI gate"),
    (ci, "run-serverbridge-security-certification-e2e.sh", "CI E2E"),
]:
    if needle not in text:
        raise SystemExit(f"{label}: отсутствует {needle}")
print("ServerBridge 0.19.12+: проверка безопасности и сертификации: OK")

#!/usr/bin/env python3
from embedded_resources import resource_read_bytes, resource_read_text, resource_exists, migration_catalog
import base64
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 2):
    raise SystemExit("VERSION ниже 0.14.2")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: отсутствует {missing}")


api_migration = read(
    "services/api/internal/dbmigrate/sql/0022_serverbridge_crypto_node_identities.sql"
)
cli_migration = resource_read_text(root, "cli/internal/dbmigrate/sql/0022_serverbridge_crypto_node_identities.sql")
if api_migration != cli_migration:
    raise SystemExit("Криптографические миграции идентичности узлов API/CLI 0.14.2 различаются")
require(
    api_migration,
    [
        "server_bridge_node_nonces_v2",
        "identity-enrollment-required",
        "key_algorithm",
        "public_key",
        "key_fingerprint",
        "identity_epoch",
        "uq_server_bridge_nodes_v2_key_fingerprint",
        "SET token_hash='', token_prefix=''",
        "token_hash=''",
        "status='invalidated'",
    ],
    "Миграция 0.14.2",
)

identity = read("services/api/internal/httpapi/server_bridge_identity.go")
require(
    identity,
    [
        'serverBridgeNodeSignatureScheme0142 = "Launcher-ServerBridge-Node-v1"',
        "ed25519.Verify",
        "serverBridgeNodeClockSkew0142",
        "serverBridgeNodeNonceTTL0142",
        "X-Launcher-Node-Key-Fingerprint",
        "ConsumeServerBridgeNodeNonce",
        "serverbridge_node_nonce_replayed",
        "subtle.ConstantTimeCompare",
    ],
    "Проверка подписи узла на Backend",
)

repo = read("services/api/internal/repository/server_bridge_v2.go")
registration_repo = repo.split("func (r *SQLRepository) SaveServerBridgeNode", 1)[
    1
].split("func timeArg", 1)[0]
if "ON CONFLICT" in registration_repo:
    raise SystemExit(
        "Регистрация узла ServerBridge должна разрешать только создание; SQL upsert обошёл бы усиленную проверку при смене идентичности"
    )
require(
    repo,
    [
        "RotateServerBridgeNodeIdentity",
        "ConsumeServerBridgeNodeNonce",
        "server_bridge_node_nonces_v2",
        "identity_epoch",
        "pg_advisory_xact_lock(1401",
        "pg_advisory_xact_lock(1403",
        "Регистрация намеренно разрешает только создание",
        '"nodeAuthentication": "ed25519-signed-requests"',
        '"replayProtection": "postgresql-single-use-nonce"',
    ],
    "Хранилище идентификаторов в PostgreSQL",
)

bridge = read("services/api/internal/httpapi/server_bridge.go")
routes = read("services/api/internal/httpapi/routes_bridge.go")
require(
    bridge,
    [
        "validateBridgeNodeIdentity0142",
        "rotateIdentity",
        "identityEpoch",
        "Заголовки запросов, подписанные Ed25519",
    ],
    "Жизненный цикл идентификаторов ServerBridge",
)
require(
    routes,
    ["/rotate-identity", "serverBridgeRotateIdentity"],
    "Маршрут ротации идентификаторов",
)
if "rotate-token" in routes or "serverBridgeRotateToken" in bridge:
    raise SystemExit("Ротация устаревшего bearer-токена по-прежнему доступна")

java_identity = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/NodeIdentity.java"
)
java_client = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/LauncherApiClient.java"
)
java_config = read(
    "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/BridgeConfig.java"
)
require(
    java_identity,
    [
        'KeyPairGenerator.getInstance("Ed25519")',
        'Signature.getInstance("Ed25519")',
        "privateKeyPkcs8",
        'PosixFilePermissions.fromString("rw-------")',
        "Files.isSymbolicLink",
        'decodeRequired(properties, "publicKey")',
        "NodeIdentity-self-test-v1",
    ],
    "Жизненный цикл закрытых ключей ServerBridge",
)
require(
    java_client,
    [
        "Launcher-ServerBridge-Node-v1",
        "X-Launcher-Node-Id",
        "X-Launcher-Node-Key-Fingerprint",
        "X-Launcher-Node-Timestamp",
        "X-Launcher-Node-Nonce",
        "X-Launcher-Node-Signature",
        "identity.sign(canonical)",
    ],
    "Подписание запросов Java ServerBridge",
)
require(
    java_config,
    ["identity.file", "LAUNCHER_NODE_IDENTITY_FILE"],
    "Настройки идентификации ServerBridge",
)
if "X-Launcher-Server-Token" in java_client or "server.token" in java_config:
    raise SystemExit(
        "В Runtime плагина остался устаревший общий секрет ServerBridge Bearer"
    )

regression = read("services/api/internal/httpapi/server_bridge_identity_test.go")
require(
    regression,
    [
        "RejectsSignatureReplayAndStaleTimestamp",
        "RejectsBodyTamperAndRetiredKey",
        "serverbridge_node_nonce_replayed",
        "serverbridge_node_timestamp_out_of_window",
        "serverbridge_node_signature_invalid",
        "serverbridge_node_fingerprint_mismatch",
        "existing node identity was replaceable through registration",
    ],
    "Регрессионные тесты криптографической идентификации",
)

openapi = read("schemas/openapi.yaml")
require(
    openapi,
    [
        '"/api/v1/server-bridge/servers/{serverId}/rotate-identity"',
        '"NodeSignature"',
        '"X-Launcher-Node-Signature"',
        '"RotateNodeIdentityRequest"',
        '"const": "ed25519"',
    ],
    "Контракт OpenAPI для идентификации узла",
)
if '"ServerToken"' in openapi or "X-Launcher-Server-Token" in openapi:
    raise SystemExit(
        "В OpenAPI по-прежнему указана устаревшая Bearer-аутентификация ServerBridge"
    )


migration_e2e = read("e2e/scripts/run-serverbridge-crypto-identity-migration-e2e.sh")
require(
    migration_e2e,
    [
        "0021_serverbridge_protocol_v2_0141",
        "0022_serverbridge_crypto_node_identities_0142",
        "identity-enrollment-required",
        "paper-disabled-0141",
        "disabled node retained legacy bearer material",
        "activeJoinInvalidated:true",
        "server_bridge_node_nonces_v2",
    ],
    "Сквозная проверка миграции с 0.14.1 на 0.14.2",
)
main_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
require(
    main_e2e,
    [
        "serverbridge_node_generate",
        "serverbridge_node_signed_request",
        'keyAlgorithm:"ed25519"',
        "node-identities/paper",
    ],
    "Сквозная проверка подписанного узла Minecraft",
)

crypto_helper = read("e2e/scripts/serverbridge-node-crypto.sh")
require(
    crypto_helper,
    [
        "serverbridge_node_sign",
        '-in "$canonical_file"',
        "invalid Ed25519 signature length",
    ],
    "Подписывание Ed25519 для сквозных проверок ServerBridge",
)

# Регрессионная проверка одноразовой подписи Ed25519 в OpenSSL. stdin на
# некоторых сборках OpenSSL не поддерживает позиционирование и раньше
# выдавал нулевую подпись, а E2E доходил до HTTP 401. Вызовите настоящий
# помощник и проверьте 64-байтную подпись по созданному открытому ключу.
with tempfile.TemporaryDirectory(prefix="launcher-ed25519-") as td:
    td = Path(td)
    key = td / "node.pem"
    public = td / "node.pub.pem"
    payload = td / "canonical.txt"
    signature_file = td / "signature.bin"
    canonical = (
        "Launcher-ServerBridge-Node-v1\n"
        "ci-node\nPOST\n/api/v1/server-bridge/validate-join\n"
        "1770000000\nregression-nonce\n" + "0" * 64
    )
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    def bash_path(path: Path) -> str:
        # Git Bash понимает пути /d/...; для подпроцессов Windows нужны D:\... .
        value = str(path.resolve())
        if (
            sys.platform == "win32"
            and len(value) >= 3
            and value[1] == ":"
            and value[2] in ("\\", "/")
        ):
            return "/" + value[0].lower() + value[2:].replace("\\", "/")
        return value

    if sys.platform == "win32":
        # Git Bash может передать временные файлы /c/... нативному OpenSSL.exe,
        # который молча завершится ошибкой. В Windows проверяйте производственную
        # криптографическую операцию напрямую с нативными путями. В Unix
        # регрессия по-прежнему проверяет сам serverbridge_node_sign.
        payload.write_text(canonical, encoding="utf-8")
        signed_process = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(key),
                "-in",
                str(payload),
                "-out",
                str(signature_file),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if signed_process.returncode != 0:
            raise SystemExit(
                "Ошибка подписи ServerBridge через Ed25519: "
                + (signed_process.stderr or signed_process.stdout)[-1200:]
            )
        raw_signature = signature_file.read_bytes()
    else:
        signed_process = subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; source "$1"; serverbridge_node_sign "$2" "$3"',
                "--",
                bash_path(root / "e2e/scripts/serverbridge-node-crypto.sh"),
                bash_path(key),
                canonical,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if signed_process.returncode != 0:
            raise SystemExit(
                "Ошибка подписи ServerBridge через Ed25519: " + signed_process.stderr[-1200:]
            )
        signed = signed_process.stdout.strip()
        raw_signature = base64.urlsafe_b64decode(
            signed + "=" * ((4 - len(signed) % 4) % 4)
        )
    if len(raw_signature) != 64:
        raise SystemExit(
            f"Вспомогательная программа ServerBridge вернула подпись Ed25519 длиной {len(raw_signature)} байт"
        )
    payload.write_text(canonical, encoding="utf-8")
    signature_file.write_bytes(raw_signature)
    subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    verified = subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public),
            "-in",
            str(payload),
            "-sigfile",
            str(signature_file),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if verified.returncode != 0:
        raise SystemExit(
            f"ServerBridge helper Ed25519 verification: ошибка — {verified.stderr.strip()}"
        )
if "X-Launcher-Server-Token" in main_e2e or ".data.serverToken" in main_e2e:
    raise SystemExit(
        "Minecraft E2E по-прежнему использует устаревшую Bearer-аутентификацию ServerBridge"
    )

print(f"Launcher 0.14.2: проверка криптографических идентификаторов узлов: OK ({version})")
print('Cryptographic Node Identities gate')

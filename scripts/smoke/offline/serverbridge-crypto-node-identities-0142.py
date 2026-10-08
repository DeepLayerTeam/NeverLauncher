#!/usr/bin/env python3
import base64
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[3]
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if tuple(int(p) for p in version.split(".")[:3]) < (0, 14, 2):
    raise SystemExit("VERSION is older than 0.14.2")


def read(path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


api_migration = read("services/api/internal/dbmigrate/sql/0022_serverbridge_crypto_node_identities_0142.sql")
cli_migration = read("cli/internal/dbmigrate/sql/0022_serverbridge_crypto_node_identities_0142.sql")
if api_migration != cli_migration:
    raise SystemExit("0.14.2 API/CLI cryptographic node identity migrations differ")
require(api_migration, [
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
], "0.14.2 migration")

identity = read("services/api/internal/httpapi/server_bridge_identity_0142.go")
require(identity, [
    'serverBridgeNodeSignatureScheme0142 = "NeverLauncher-ServerBridge-Node-v1"',
    "ed25519.Verify",
    "serverBridgeNodeClockSkew0142",
    "serverBridgeNodeNonceTTL0142",
    "X-NeverLauncher-Node-Key-Fingerprint",
    "ConsumeServerBridgeNodeNonce",
    "serverbridge_node_nonce_replayed",
    "subtle.ConstantTimeCompare",
], "Backend node signature verification")

repo = read("services/api/internal/repository/server_bridge_v2.go")
registration_repo = repo.split("func (r *SQLRepository) SaveServerBridgeNode", 1)[1].split("func timeArg", 1)[0]
if "ON CONFLICT" in registration_repo:
    raise SystemExit("ServerBridge node registration must remain create-only; SQL upsert would bypass identity rotation step-up")
require(repo, [
    "RotateServerBridgeNodeIdentity",
    "ConsumeServerBridgeNodeNonce",
    "server_bridge_node_nonces_v2",
    "identity_epoch",
    "pg_advisory_xact_lock(1401",
    "pg_advisory_xact_lock(1403",
    "Registration is intentionally create-only",
    '"nodeAuthentication": "ed25519-signed-requests"',
    '"replayProtection": "postgresql-single-use-nonce"',
], "PostgreSQL identity repository")

bridge = read("services/api/internal/httpapi/server_bridge.go")
routes = read("services/api/internal/httpapi/routes_bridge.go")
require(bridge, [
    "validateBridgeNodeIdentity0142",
    "rotateIdentity",
    "identityEpoch",
    "Ed25519 signed request headers",
], "ServerBridge identity lifecycle")
require(routes, ["/rotate-identity", "serverBridgeRotateIdentity"], "identity rotation route")
if "rotate-token" in routes or "serverBridgeRotateToken" in bridge:
    raise SystemExit("legacy bearer token rotation is still exposed")

java_identity = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NodeIdentity.java")
java_client = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/NeverLauncherApiClient.java")
java_config = read("plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeConfig.java")
require(java_identity, [
    'KeyPairGenerator.getInstance("Ed25519")',
    'Signature.getInstance("Ed25519")',
    "privateKeyPkcs8",
    "PosixFilePermissions.fromString(\"rw-------\")",
    "Files.isSymbolicLink",
    'decodeRequired(properties, "publicKey")',
    "NodeIdentity-self-test-v1",
], "ServerBridge private-key lifecycle")
require(java_client, [
    "NeverLauncher-ServerBridge-Node-v1",
    "X-NeverLauncher-Node-Id",
    "X-NeverLauncher-Node-Key-Fingerprint",
    "X-NeverLauncher-Node-Timestamp",
    "X-NeverLauncher-Node-Nonce",
    "X-NeverLauncher-Node-Signature",
    "identity.sign(canonical)",
], "ServerBridge Java request signing")
require(java_config, ["identity.file", "NEVERLAUNCHER_NODE_IDENTITY_FILE"], "ServerBridge identity configuration")
if "X-NeverLauncher-Server-Token" in java_client or "server.token" in java_config:
    raise SystemExit("legacy shared ServerBridge bearer secret remains in plugin runtime")

regression = read("services/api/internal/httpapi/server_bridge_identity_0142_test.go")
require(regression, [
    "RejectsSignatureReplayAndStaleTimestamp",
    "RejectsBodyTamperAndRetiredKey",
    "serverbridge_node_nonce_replayed",
    "serverbridge_node_timestamp_out_of_window",
    "serverbridge_node_signature_invalid",
    "serverbridge_node_fingerprint_mismatch",
    "existing node identity was replaceable through registration",
], "cryptographic identity regression tests")

openapi = read("schemas/openapi.yaml")
require(openapi, [
    '"/api/v1/server-bridge/servers/{serverId}/rotate-identity"',
    '"NodeSignature"',
    '"X-NeverLauncher-Node-Signature"',
    '"RotateNodeIdentityRequest"',
    '"const": "ed25519"',
], "OpenAPI node identity contract")
if '"ServerToken"' in openapi or "X-NeverLauncher-Server-Token" in openapi:
    raise SystemExit("OpenAPI still advertises legacy ServerBridge bearer authentication")


migration_e2e = read("e2e/scripts/run-serverbridge-crypto-identity-migration-e2e.sh")
require(migration_e2e, [
    "0021_serverbridge_protocol_v2_0141",
    "0022_serverbridge_crypto_node_identities_0142",
    "identity-enrollment-required",
    "paper-disabled-0141",
    "disabled node retained legacy bearer material",
    "activeJoinInvalidated:true",
    "server_bridge_node_nonces_v2",
], "0.14.1 -> 0.14.2 migration E2E")
main_e2e = read("e2e/scripts/run-minecraft-e2e.sh")
require(main_e2e, [
    "serverbridge_node_generate",
    "serverbridge_node_signed_request",
    'keyAlgorithm:"ed25519"',
    "node-identities/paper",
], "Minecraft signed-node E2E")

crypto_helper = read("e2e/scripts/serverbridge-node-crypto.sh")
require(crypto_helper, [
    "serverbridge_node_sign",
    '-in "$canonical_file"',
    "invalid Ed25519 signature length",
], "ServerBridge E2E Ed25519 signer")

# Regression for OpenSSL Ed25519 one-shot signing. stdin is not seekable on
# affected OpenSSL builds and previously produced a zero-byte signature while
# the E2E continued to an HTTP 401. Exercise the actual helper and verify the
# resulting 64-byte signature against the generated public key.
with tempfile.TemporaryDirectory(prefix="neverlauncher-ed25519-") as td:
    td = Path(td)
    key = td / "node.pem"
    public = td / "node.pub.pem"
    payload = td / "canonical.txt"
    signature_file = td / "signature.bin"
    canonical = (
        "NeverLauncher-ServerBridge-Node-v1\n"
        "ci-node\nPOST\n/api/v1/server-bridge/validate-join\n"
        "1770000000\nregression-nonce\n" + "0" * 64
    )
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    signed = subprocess.run(
        [
            "bash", "-c",
            'set -euo pipefail; source "$1"; serverbridge_node_sign "$2" "$3"',
            "--", str(root / "e2e/scripts/serverbridge-node-crypto.sh"), str(key), canonical,
        ],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    raw_signature = base64.urlsafe_b64decode(signed + "=" * ((4 - len(signed) % 4) % 4))
    if len(raw_signature) != 64:
        raise SystemExit(f"ServerBridge helper returned {len(raw_signature)}-byte Ed25519 signature")
    payload.write_text(canonical, encoding="utf-8")
    signature_file.write_bytes(raw_signature)
    subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    verified = subprocess.run(
        [
            "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(public), "-in", str(payload), "-sigfile", str(signature_file),
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if verified.returncode != 0:
        raise SystemExit(f"ServerBridge helper Ed25519 verification failed: {verified.stderr.strip()}")
if "X-NeverLauncher-Server-Token" in main_e2e or ".data.serverToken" in main_e2e:
    raise SystemExit("Minecraft E2E still uses legacy ServerBridge bearer authentication")

print(f"NeverLauncher 0.14.2 Cryptographic Node Identities gate: OK ({version})")

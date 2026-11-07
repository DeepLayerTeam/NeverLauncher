#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
TARGETS = ROOT / "serverbridge/targets.json"
EXPECTED = [
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
SECURITY_PROFILE = "serverbridge3-security-01912"
SECURITY_FEATURES = [
    "security.protocol-v3-signing-domain",
    "security.capability-downgrade-protection",
    "security.command-signatures-v3",
    "security.event-signatures-v3",
    "security.runtime-instance-binding-v3",
    "security.online-key-rotation-v1",
]
SECURITY_CAPABILITY_DIGEST = (
    "088d7922033afa09c4489989fab5d71603e3425a08243a95588036f5c27505c4"
)
PROTOCOL_V3_FEATURE_DIGEST = (
    "098bcd1e6f0f57044404edf994b32482ebc70e77054f4f91ff35e848c9d6fdbc"
)
HASH_FIELDS = {
    "velocity": "velocitySha256",
    "bungeecord": "bungeeCordSha256",
    "waterfall": "waterfallSha256",
    "bukkit": "bukkitSha256",
    "spigot": "spigotSha256",
    "paper": "paperSha256",
    "purpur": "purpurSha256",
    "folia": "foliaSha256",
    "fabric": "fabricSha256",
    "quilt": "quiltSha256",
    "forge": "forgeSha256",
    "neoforge": "neoforgeSha256",
    "sponge": "spongeSha256",
    "vanilla": "vanillaSha256",
}
COMMON_PROTOCOL_ENTRIES = [
    "ru/launcher/bridge/common/LauncherApiClient.class",
    "ru/launcher/bridge/common/BridgeProtocolNegotiation.class",
    "ru/launcher/bridge/common/BridgeProtocolSecurity.class",
    "ru/launcher/bridge/common/BridgeRuntimeDescriptor.class",
    "ru/launcher/bridge/common/BridgeRuntimeIdentity.class",
    "ru/launcher/bridge/common/BridgeRuntimeProbe.class",
    "ru/launcher/bridge/common/BridgeTelemetrySampler.class",
    "ru/launcher/bridge/common/BridgeTelemetrySnapshot.class",
    "ru/launcher/bridge/common/BridgePlatformTelemetry.class",
    "ru/launcher/bridge/common/BridgeTickSampler.class",
    "ru/launcher/bridge/common/BridgeEventRecord.class",
    "ru/launcher/bridge/common/BridgeEventJournal.class",
    "ru/launcher/bridge/common/BridgeControlCommand.class",
    "ru/launcher/bridge/common/BridgeControlExecutor.class",
    "ru/launcher/bridge/common/BridgeControlJournal.class",
    "ru/launcher/bridge/common/BridgeControlTrust.class",
    "ru/launcher/bridge/common/BridgeRoutingSnapshot.class",
    "ru/launcher/bridge/common/BridgePlayerSessionRegistry.class",
    "ru/launcher/bridge/common/BridgeAdapterCapability.class",
    "ru/launcher/bridge/common/BridgeAdapterProfile.class",
    "ru/launcher/bridge/common/BridgeAdapterProfiles.class",
]
REQUIRED_ENTRIES = {
    "velocity": [
        "velocity-plugin.json",
        "ru/launcher/bridge/common/LauncherApiClient.class",
        "ru/launcher/bridge/proxy/ProxyBridgeRuntime.class",
    ],
    "bungeecord": [
        "bungee.yml",
        "ru/launcher/bridge/common/LauncherApiClient.class",
        "ru/launcher/bridge/proxy/ProxyBridgeRuntime.class",
        "ru/launcher/bridge/bungee/BungeeFamilyBridgePlugin.class",
    ],
    "waterfall": [
        "bungee.yml",
        "ru/launcher/bridge/common/LauncherApiClient.class",
        "ru/launcher/bridge/proxy/ProxyBridgeRuntime.class",
        "ru/launcher/bridge/bungee/BungeeFamilyBridgePlugin.class",
    ],
    "bukkit": [
        "plugin.yml",
        "ru/launcher/bridge/common/LauncherApiClient.class",
        "ru/launcher/bridge/bukkit/BukkitFamilyBridgePlugin.class",
    ],
    "spigot": [
        "plugin.yml",
        "ru/launcher/bridge/common/LauncherApiClient.class",
        "ru/launcher/bridge/bukkit/BukkitFamilyBridgePlugin.class",
    ],
    "paper": [
        "plugin.yml",
        "ru/launcher/bridge/common/LauncherApiClient.class",
        "ru/launcher/bridge/bukkit/BukkitFamilyBridgePlugin.class",
    ],
    "purpur": [
        "plugin.yml",
        "ru/launcher/bridge/common/LauncherApiClient.class",
        "ru/launcher/bridge/bukkit/BukkitFamilyBridgePlugin.class",
    ],
    "folia": [
        "plugin.yml",
        "ru/launcher/bridge/common/LauncherApiClient.class",
        "ru/launcher/bridge/bukkit/BukkitFamilyBridgePlugin.class",
    ],
    "fabric": [
        "fabric.mod.json",
        "launcher.fabric.mixins.json",
        "ru/launcher/bridge/fabric/LauncherFabricBridge.class",
    ],
    "forge": [
        "META-INF/mods.toml",
        "ru/launcher/bridge/modloader/ModLoaderBridgeRuntime.class",
    ],
    "neoforge": [
        "META-INF/neoforge.mods.toml",
        "ru/launcher/bridge/modloader/ModLoaderBridgeRuntime.class",
    ],
    "quilt": [
        "fabric.mod.json",
        "quilt.mod.json",
        "launcher.quilt.mixins.json",
        "ru/launcher/bridge/quilt/LauncherQuiltBridge.class",
    ],
    "sponge": ["ru/launcher/bridge/sponge/LauncherSpongeBridge.class"],
    "vanilla": [
        "ru/launcher/bridge/vanilla/LauncherVanillaBridge.class",
        "ru/launcher/bridge/vanilla/VanillaRconClient.class",
    ],
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def die(msg: str) -> None:
    raise SystemExit(f"Ошибка: «сертификация выпуска ServerBridge 3»: {msg}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        die(f"{path}: некорректный JSON: {exc}")
    if not isinstance(data, dict):
        die(f"{path}: корневое значение должно быть объектом")
    return data


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Сертифицировать собранную группу выпуска Launcher ServerBridge 3"
    )
    ap.add_argument("--artifacts", type=Path, default=ROOT / "artifacts/plugins")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    artifacts = args.artifacts.resolve()
    manifest_path = artifacts / "PLUGIN_MANIFEST.json"
    allowlist_path = artifacts / "BRIDGE_RELEASE_ALLOWLIST.json"
    if not manifest_path.is_file() or not allowlist_path.is_file():
        die("Требуются PLUGIN_MANIFEST.json и BRIDGE_RELEASE_ALLOWLIST.json")

    targets = load_json(TARGETS)
    target_rows = targets.get("targets")
    if targets.get("productVersion") != VERSION or targets.get("protocolVersion") != 3:
        die("Версия или протокол в serverbridge/targets.json не соответствует ожидаемым")
    if (
        not isinstance(target_rows, list)
        or [r.get("id") for r in target_rows] != EXPECTED
    ):
        die("Набор или порядок целевых платформ ServerBridge не совпадает")
    hybrid = load_json(ROOT / "serverbridge/hybrid-targets.json")
    hybrid_rows = hybrid.get("targets")
    if (
        hybrid.get("productVersion") != VERSION
        or hybrid.get("policy") != "separate-certification-required"
    ):
        die("Версия или политика матрицы сертификации гибридных платформ не совпадает")
    if not isinstance(hybrid_rows, list) or any(
        r.get("status") != "not-certified" for r in hybrid_rows
    ):
        die("Универсальный релиз не должен автоматически подтверждать сертификацию гибридных ядер")
    hybrid_ids = {r.get("id") for r in hybrid_rows}
    if hybrid_ids & set(EXPECTED):
        die("В набор универсальных артефактов попала цель для гибридной платформы")

    manifest = load_json(manifest_path)
    if manifest.get("toolVersion") != VERSION or manifest.get("schemaVersion") != "1.2":
        die("Версия или схема манифеста плагина не совпадает")
    rows = manifest.get("artifacts")
    if not isinstance(rows, list) or [r.get("id") for r in rows] != EXPECTED:
        die("Набор или порядок артефактов манифеста плагина не совпадает")

    allow = load_json(allowlist_path)
    if (
        allow.get("schemaVersion") != "3.0"
        or allow.get("release") != "ServerBridge 3"
        or allow.get("protocolVersion") != 3
        or allow.get("minimumProtocolVersion") != 3
        or allow.get("ga") is not True
        or allow.get("protocolV3Frozen") is not True
        or str(allow.get("protocolV3FeatureDigest", "")).lower()
        != PROTOCOL_V3_FEATURE_DIGEST
        or allow.get("protocolV2Mode") != "compatibility-deprecated"
        or allow.get("securityProfile") != SECURITY_PROFILE
        or str(allow.get("securityCapabilityDigest", "")).lower()
        != SECURITY_CAPABILITY_DIGEST
        or sorted(allow.get("requiredFeatures") or []) != sorted(SECURITY_FEATURES)
    ):
        die("Метаданные безопасности списка разрешённых релизов ServerBridge 3 не совпадают")
    releases = allow.get("releases")
    if (
        not isinstance(releases, dict)
        or set(releases) != {VERSION}
        or not isinstance(releases[VERSION], dict)
    ):
        die(f"Список разрешённых релизов должен содержать только точный набор релиза {VERSION}")
    policy = releases[VERSION]

    evidence = []
    seen_hashes: dict[str, str] = {}
    for row in rows:
        target = row["id"]
        filename = row.get("file")
        expected_filename = f"launcher-{target}-bridge-{VERSION}.jar"
        if filename != expected_filename:
            die(f"{target}: ожидалось имя файла {expected_filename}, получено {filename!r}")
        jar = artifacts / filename
        if not jar.is_file() or jar.stat().st_size == 0:
            die(f"{target}: отсутствует JAR или он пуст {jar}")
        digest = sha256(jar)
        if not HEX64.fullmatch(digest):
            die(f"{target}: внутренняя проверка SHA-256 не пройдена")
        if row.get("sha256") != digest:
            die(f"{target}: manifest SHA-256: не совпадает с JAR")
        field = HASH_FIELDS[target]
        values = policy.get(field)
        if values != [digest]:
            die(f"{target}: {field} должен содержать только SHA-256 собранного JAR")
        if digest in seen_hashes:
            die(
                f"{target}: содержимое артефакта идентично {seen_hashes[digest]} (необходим выпуск для соответствующей платформы)"
            )
        seen_hashes[digest] = target
        try:
            with zipfile.ZipFile(jar) as zf:
                names = set(zf.namelist())
                for entry in REQUIRED_ENTRIES[target]:
                    if entry not in names:
                        die(f"{target}: JAR: отсутствует {entry}")
                if target in {"fabric", "quilt"}:
                    nested = [
                        name
                        for name in names
                        if name.startswith("META-INF/jars/bridge-common-")
                        and name.endswith(".jar")
                    ]
                    if len(nested) != 1:
                        die(
                            f"{target}: ожидался ровно один встроенный JAR bridge-common"
                        )
                    import io

                    with zipfile.ZipFile(io.BytesIO(zf.read(nested[0]))) as common:
                        common_names = set(common.namelist())
                        for entry in COMMON_PROTOCOL_ENTRIES:
                            if entry not in common_names:
                                die(f"{target}: во встроенном bridge-common отсутствует {entry}")
                else:
                    for entry in COMMON_PROTOCOL_ENTRIES:
                        if entry not in names:
                            die(f"{target}: JAR: отсутствует {entry}")
                if target == "folia":
                    text = zf.read("plugin.yml").decode("utf-8", "replace")
                    if "folia-supported: true" not in text:
                        die("folia: дескриптор не объявляет folia-supported: true")
                elif target == "fabric":
                    data = json.loads(zf.read("fabric.mod.json").decode("utf-8"))
                    custom = data.get("custom")
                    launcher = (
                        custom.get("launcher") if isinstance(custom, dict) else None
                    )
                    if (
                        data.get("environment") != "server"
                        or not isinstance(launcher, dict)
                        or launcher.get("clientModRequired") is not False
                    ):
                        die(
                            "fabric: артефакт должен быть только серверным, с clientModRequired=false"
                        )
                elif target == "quilt":
                    data = json.loads(zf.read("fabric.mod.json").decode("utf-8"))
                    custom = (data.get("custom") or {}).get("launcher") or {}
                    if (
                        data.get("environment") != "server"
                        or "quilt_loader" not in (data.get("depends") or {})
                        or custom.get("clientModRequired") is not False
                    ):
                        die(
                            "quilt: артефакт должен предназначаться только для Quilt и сервера, с clientModRequired=false"
                        )
                elif target == "vanilla":
                    manifest = zf.read("META-INF/MANIFEST.MF").decode(
                        "utf-8", "replace"
                    )
                    if (
                        "Main-Class: ru.launcher.bridge.vanilla.LauncherVanillaBridge"
                        not in manifest
                    ):
                        die("vanilla: у исполняемого вспомогательного модуля отсутствует Main-Class")
        except zipfile.BadZipFile:
            die(f"{target}: некорректный JAR/ZIP")
        coverage = next(r.get("coverage") for r in target_rows if r.get("id") == target)
        evidence.append(
            {
                "id": target,
                "file": filename,
                "sha256": digest,
                "bytes": jar.stat().st_size,
                "requiredCoverage": coverage,
                "runtimeEvidenceVerified": False,
            }
        )

    sums_path = artifacts / "SHA256SUMS"
    if not sums_path.is_file():
        die("Отсутствует SHA256SUMS")
    sums = {}
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            sums[parts[1].lstrip("*")] = parts[0].lower()
    for item in evidence:
        if sums.get(item["file"]) != item["sha256"]:
            die(f"{item['id']}: несовпадение контрольной суммы SHA256SUMS")

    # Перед сертификацией группы артефактов проверьте настоящую Java-политику
    # bridge-common для того же коммита. Это НЕ тест живого сервера Minecraft.
    suite = ROOT / "e2e/scripts/run-serverbridge-adapter-capabilities-0286.sh"
    try:
        result = subprocess.run(
            ["bash", str(suite)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        die(f"Выполнение политики адаптера недоступно: {exc}")
    if (
        result.returncode != 0
        or "CAPABILITY_POLICY_OK total=14 runtime_certified=false" not in result.stdout
    ):
        die(f"Ошибка выполнения политики адаптера — {result.stderr[-2048:]}")

    report = {
        "schemaVersion": "1.1",
        "release": "ServerBridge 3",
        "version": VERSION,
        "certificationScope": "artifact-integrity-and-java-capability-policy",
        "adapterCapabilityPolicyExecuted": True,
        "runtimeE2eVerifiedByThisReport": False,
        "protocolVersion": 3,
        "status": "certified",
        "targetCount": len(evidence),
        "ga": True,
        "protocolV3Frozen": True,
        "protocolV3FeatureDigest": PROTOCOL_V3_FEATURE_DIGEST,
        "protocolV2Mode": "compatibility-deprecated",
        "installerUpgradePath": True,
        "unifiedOperatorAPI": "/api/v1/server-bridge/overview",
        "publicCompatibilityMatrix": True,
        "securityProfile": SECURITY_PROFILE,
        "securityCapabilityDigest": SECURITY_CAPABILITY_DIGEST,
        "requiredSecurityFeatures": SECURITY_FEATURES,
        "capabilityDowngradeProtection": True,
        "canonicalSigningDomain": "Launcher-ServerBridge-Protocol-v3",
        "commandSignatures": True,
        "eventSignatures": True,
        "runtimeInstanceBinding": True,
        "onlineKeyRotation": True,
        "zeroPatch": True,
        "nodeIdentity": "Ed25519",
        "oneTimeJoin": True,
        "nodeDiscovery": True,
        "runtimeIdentity": "Ed25519 node-bound process identity",
        "runtimeReplacementDetection": True,
        "serverTelemetry": True,
        "boundedTelemetrySampling": True,
        "serverEventStream": True,
        "orderedEventAck": True,
        "eventReplayProtection": True,
        "eventReconnectResume": True,
        "controlAPI": True,
        "controlRBAC": True,
        "controlIdempotency": True,
        "controlAudit": True,
        "controlCommandAllowlist": True,
        "controlShellExecution": False,
        "topologyRouting2": True,
        "signedRoutingSnapshots": True,
        "healthCapacityRouting": True,
        "handoffSourceTargetProof": True,
        "staleTopologyCleanup": True,
        "playerSessionIntegration3": True,
        "sessionCloneProtection": True,
        "orderedTransferChain": True,
        "trustGuardTransferRecheck": True,
        "topologyWideSessionInvalidation": True,
        "universalServerAdapters": True,
        "adapterCapabilities": True,
        "quiltAdapter": True,
        "spongeAdapter": True,
        "vanillaSidecarRcon": True,
        "hybridCertificationPolicy": "separate-fail-closed",
        "artifacts": evidence,
    }
    out = args.out or (artifacts / "SERVERBRIDGE3_CERTIFICATION.json")
    out.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Набор артефактов ServerBridge проверен (это не Minecraft Runtime E2E): {VERSION}, {len(evidence)} артефактов платформ -> {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

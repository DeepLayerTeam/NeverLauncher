#!/usr/bin/env python3
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
core = VERSION.split("-", 1)[0].split("+", 1)[0]
parts = tuple(int(x) for x in core.split(".")[:3])
if parts < (0, 15, 1):
    raise SystemExit(f"Delivery Manifest gate requires VERSION>=0.15.1, got {VERSION}")


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def require(text: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label}: missing {missing}")


delivery = read("cli/cmd/neverlauncher/delivery_manifest.go")
require(
    delivery,
    [
        'const deliveryManifestFile0151 = "DELIVERY_MANIFEST.json"',
        "normalizeDeliveryPlatform",
        "normalizeDeliveryArchitecture",
        'case "x64", "amd64", "x86_64", "x86-64"',
        'case "arm64", "aarch64"',
        'case "macos", "darwin", "osx", "mac"',
        "verifyDeliveryManifest0151",
        "resolveDeliveryArtifacts0151",
        "deliveryTargetCompatible",
        "checksum/size mismatch",
    ],
    "delivery implementation",
)
release = read("cli/cmd/neverlauncher/release_commands.go")
require(
    release,
    [
        "writeDeliveryManifest0151(out, ver)",
        "verifyDeliveryManifest0151(out, ver)",
        'checks = append(checks, "delivery-manifest-platform-architecture")',
        "deliveryManifestFile0151",
    ],
    "release integration",
)
main = read("cli/cmd/neverlauncher/main.go")
require(main, ['case "delivery":', "handleDelivery(args[1:])"], "CLI routing")
release_gate = read("scripts/smoke/release-required/release-bundle.sh")
require(release_gate, ["DELIVERY_MANIFEST.json", "release publish-check"], "publish gate")

with tempfile.TemporaryDirectory(prefix="neverlauncher-0151-") as tmp_raw:
    tmp = Path(tmp_raw)
    binary = tmp / "nl"
    bundle = tmp / "bundle"
    bundle.mkdir()
    subprocess.run(
        ["go", "build", "-trimpath", "-ldflags", f"-X main.version={VERSION}", "-o", str(binary), "./cmd/neverlauncher"],
        cwd=ROOT / "cli",
        check=True,
    )
    payloads = {
        "neverlauncher-cli-linux-amd64": b"linux-x64-cli\n",
        f"neverlauncher-desktop-{VERSION}-windows-arm64.exe": b"windows-arm64-desktop\n",
        "neverlauncher-desktop-macos-universal": b"macos-universal-desktop\n",
        f"neverlauncher-paper-bridge-{VERSION}.jar": b"platform-neutral-jar\n",
    }
    for name, payload in payloads.items():
        (bundle / name).write_bytes(payload)

    subprocess.run([str(binary), "delivery", "manifest", "--bundle", str(bundle), "--version", VERSION], check=True)
    subprocess.run([str(binary), "delivery", "verify", "--bundle", str(bundle), "--version", VERSION], check=True)
    resolved = subprocess.check_output(
        [
            str(binary),
            "delivery",
            "resolve",
            "--bundle",
            str(bundle),
            "--platform",
            "win32",
            "--arch",
            "aarch64",
            "--component",
            "desktop-launcher",
        ],
        text=True,
    )
    data = json.loads(resolved)
    if data.get("target") != {"platform": "windows", "architecture": "arm64"}:
        raise SystemExit(f"canonical target mismatch: {data.get('target')}")
    artifacts = data.get("artifacts", [])
    if len(artifacts) != 1 or artifacts[0].get("name") != f"neverlauncher-desktop-{VERSION}-windows-arm64.exe":
        raise SystemExit(f"delivery resolver selected unexpected artifacts: {artifacts}")

    (bundle / "neverlauncher-cli-linux-amd64").write_bytes(b"tampered\n")
    tampered = subprocess.run(
        [str(binary), "delivery", "verify", "--bundle", str(bundle), "--version", VERSION],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if tampered.returncode == 0:
        raise SystemExit("delivery verification accepted a tampered artifact")

print(f"NeverLauncher {VERSION} Delivery Manifest + platform/architecture gate: OK")

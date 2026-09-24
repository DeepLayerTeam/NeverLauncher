#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / 'VERSION').read_text(encoding='utf-8').strip()
TARGETS = ROOT / 'serverbridge/targets.json'
EXPECTED = ['velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','forge','neoforge']
HASH_FIELDS = {
    'velocity':'velocitySha256','bungeecord':'bungeeCordSha256','waterfall':'waterfallSha256',
    'bukkit':'bukkitSha256','spigot':'spigotSha256','paper':'paperSha256','purpur':'purpurSha256',
    'folia':'foliaSha256','fabric':'fabricSha256','forge':'forgeSha256','neoforge':'neoforgeSha256',
}
REQUIRED_ENTRIES = {
    'velocity':['velocity-plugin.json','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.class'],
    'bungeecord':['bungee.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.class','ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.class'],
    'waterfall':['bungee.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/proxy/ProxyBridgeRuntime.class','ru/neverlauncher/bridge/bungee/BungeeFamilyBridgePlugin.class'],
    'bukkit':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'spigot':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'paper':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'purpur':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'folia':['plugin.yml','ru/neverlauncher/bridge/common/NeverLauncherApiClient.class','ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.class'],
    'fabric':['fabric.mod.json','neverlauncher.fabric.mixins.json','ru/neverlauncher/bridge/fabric/NeverLauncherFabricBridge.class'],
    'forge':['META-INF/mods.toml','ru/neverlauncher/bridge/modloader/ModLoaderBridgeRuntime.class'],
    'neoforge':['META-INF/neoforge.mods.toml','ru/neverlauncher/bridge/modloader/ModLoaderBridgeRuntime.class'],
}
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def die(msg: str) -> None:
    raise SystemExit(f'ServerBridge 2 release certification failed: {msg}')


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception as exc:
        die(f'{path}: invalid JSON: {exc}')
    if not isinstance(data, dict):
        die(f'{path}: root must be object')
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description='Certify a built NeverLauncher ServerBridge 2 release cohort')
    ap.add_argument('--artifacts', type=Path, default=ROOT / 'artifacts/plugins')
    ap.add_argument('--out', type=Path)
    args = ap.parse_args()
    artifacts = args.artifacts.resolve()
    manifest_path = artifacts / 'PLUGIN_MANIFEST.json'
    allowlist_path = artifacts / 'BRIDGE_RELEASE_ALLOWLIST.json'
    if not manifest_path.is_file() or not allowlist_path.is_file():
        die('PLUGIN_MANIFEST.json and BRIDGE_RELEASE_ALLOWLIST.json are required')

    targets = load_json(TARGETS)
    target_rows = targets.get('targets')
    if targets.get('productVersion') != VERSION or targets.get('protocolVersion') != 2:
        die('serverbridge/targets.json version/protocol drift')
    if not isinstance(target_rows, list) or [r.get('id') for r in target_rows] != EXPECTED:
        die('serverbridge target set/order mismatch')

    manifest = load_json(manifest_path)
    if manifest.get('toolVersion') != VERSION or manifest.get('schemaVersion') != '1.2':
        die('plugin manifest version/schema mismatch')
    rows = manifest.get('artifacts')
    if not isinstance(rows, list) or [r.get('id') for r in rows] != EXPECTED:
        die('plugin manifest artifact set/order mismatch')

    allow = load_json(allowlist_path)
    if set(allow) != {VERSION} or not isinstance(allow[VERSION], dict):
        die(f'allowlist must contain only the exact release cohort {VERSION}')
    policy = allow[VERSION]

    evidence = []
    seen_hashes: dict[str, str] = {}
    for row in rows:
        target = row['id']
        filename = row.get('file')
        expected_filename = f'neverlauncher-{target}-bridge-{VERSION}.jar'
        if filename != expected_filename:
            die(f'{target}: expected filename {expected_filename}, got {filename!r}')
        jar = artifacts / filename
        if not jar.is_file() or jar.stat().st_size == 0:
            die(f'{target}: missing/non-empty JAR {jar}')
        digest = sha256(jar)
        if not HEX64.fullmatch(digest):
            die(f'{target}: internal SHA-256 failure')
        if row.get('sha256') != digest:
            die(f'{target}: manifest SHA-256 does not match JAR')
        field = HASH_FIELDS[target]
        values = policy.get(field)
        if values != [digest]:
            die(f'{target}: {field} must contain exactly the built JAR SHA-256')
        if digest in seen_hashes:
            die(f'{target}: artifact bytes are identical to {seen_hashes[digest]} (platform-matched release required)')
        seen_hashes[digest] = target
        try:
            with zipfile.ZipFile(jar) as zf:
                names = set(zf.namelist())
                for entry in REQUIRED_ENTRIES[target]:
                    if entry not in names:
                        die(f'{target}: JAR missing {entry}')
                if target == 'folia':
                    text = zf.read('plugin.yml').decode('utf-8', 'replace')
                    if 'folia-supported: true' not in text:
                        die('folia: descriptor does not declare folia-supported: true')
                elif target == 'fabric':
                    data = json.loads(zf.read('fabric.mod.json').decode('utf-8'))
                    if data.get('environment') != 'server' or data.get('clientModRequired') is not False:
                        die('fabric: artifact must be server-only and clientModRequired=false')
        except zipfile.BadZipFile:
            die(f'{target}: invalid JAR/ZIP')
        evidence.append({'id': target, 'file': filename, 'sha256': digest, 'bytes': jar.stat().st_size})

    sums_path = artifacts / 'SHA256SUMS'
    if not sums_path.is_file():
        die('SHA256SUMS is missing')
    sums = {}
    for line in sums_path.read_text(encoding='utf-8').splitlines():
        parts = line.split()
        if len(parts) == 2:
            sums[parts[1].lstrip('*')] = parts[0].lower()
    for item in evidence:
        if sums.get(item['file']) != item['sha256']:
            die(f"{item['id']}: SHA256SUMS mismatch")

    report = {
        'schemaVersion': '1.0', 'release': 'ServerBridge 2', 'version': VERSION,
        'protocolVersion': 2, 'status': 'certified', 'targetCount': len(evidence),
        'zeroPatch': True, 'nodeIdentity': 'Ed25519', 'oneTimeJoin': True,
        'artifacts': evidence,
    }
    out = args.out or (artifacts / 'SERVERBRIDGE2_CERTIFICATION.json')
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(f'ServerBridge 2 release certified: {VERSION}, {len(evidence)} platform artifacts -> {out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

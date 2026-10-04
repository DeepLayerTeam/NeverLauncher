#!/usr/bin/env python3
from pathlib import Path
import json,re
ROOT=Path(__file__).resolve().parents[3]
def read(p): return (ROOT/p).read_text(encoding='utf-8')
def require(text, needles, label):
    for n in needles:
        if n not in text: raise SystemExit(f'{label}: missing {n!r}')
version=read('VERSION').strip()
if version!='0.19.8': raise SystemExit(f'expected VERSION 0.19.8, got {version}')
targets=json.loads(read('serverbridge/targets.json'))
expected=['velocity','bungeecord','waterfall','bukkit','spigot','paper','purpur','folia','fabric','quilt','forge','neoforge','sponge','vanilla']
if [x['id'] for x in targets['targets']] != expected: raise SystemExit('universal 14-target cohort mismatch')
profiles=read('plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeAdapterProfiles.java')
require(profiles,['Map.entry("quilt"','Map.entry("sponge"','Map.entry("vanilla"','rejectUncertifiedHybrid','mohist','arclight','magma','catserver','banner','cardboard'],'capability profiles/hybrid fail-closed')
require(read('plugins/bridge-common/src/main/java/ru/neverlauncher/bridge/common/BridgeRuntimeDescriptor.java'),['BridgeAdapterProfiles.find','runtimeCapabilities'],'runtime capability publication')
require(read('plugins/bukkit-family-common/src/main/java/ru/neverlauncher/bridge/bukkit/BukkitFamilyBridgePlugin.java'),['BridgeAdapterCapability.REGION_SAFE_SCHEDULER','BridgeAdapterCapability.TELEMETRY_BOUNDED_WORLD_COUNTERS','BridgeAdapterProfiles.rejectUncertifiedHybrid'],'Bukkit capability execution')
quilt=read('plugins/quilt-bridge/src/main/java/ru/neverlauncher/bridge/quilt/NeverLauncherQuiltBridge.java')
require(quilt,['QuiltLoader.getConfigDir()','ServerLoginConnectionEvents.QUERY_START','validateJoin','recordPlatformTelemetry','startControlChannel','"loader.quilt"'],'Quilt production adapter')
require(read('plugins/quilt-bridge/src/main/resources/fabric.mod.json'),['"quilt_loader"','"environment": "server"','"clientModRequired": false'],'Quilt server-only metadata')
sponge=read('plugins/sponge-bridge/src/main/java/ru/neverlauncher/bridge/sponge/NeverLauncherSpongeBridge.java')
require(sponge,['@Plugin("neverlauncher_sponge_bridge")','ServerSideConnectionEvent.Auth','validateJoin','server.scheduler().executor(container)','recordPlatformTelemetry','startControlChannel'],'Sponge native adapter')
vanilla=read('plugins/vanilla-bridge/src/main/java/ru/neverlauncher/bridge/vanilla/NeverLauncherVanillaBridge.java')
rcon=read('plugins/vanilla-bridge/src/main/java/ru/neverlauncher/bridge/vanilla/VanillaRconClient.java')
require(vanilla,['enable-rcon','VanillaRconClient','logs/latest.log','recordPlatformTelemetry','startControlChannel','server.console'],'Vanilla sidecar')
require(rcon,['Minecraft Source-RCON','socket.connect','writeLEInt','RCON authentication failed'],'Vanilla RCON wire client')
for forbidden in ['ProcessBuilder','Runtime.getRuntime().exec','/bin/sh','cmd.exe']:
    if forbidden in vanilla or forbidden in rcon: raise SystemExit(f'Vanilla sidecar contains forbidden shell execution: {forbidden}')
migration=read('services/api/internal/dbmigrate/sql/0039_universal_server_adapters_0198.sql')
require(migration,["'quilt'","'sponge'","'vanilla'",'separate certification'],'0.19.8 migration')
for hybrid in ["'mohist'","'arclight'","'magma'","'catserver'","'banner'","'cardboard'"]:
    if hybrid in migration: raise SystemExit(f'hybrid leaked into canonical DB kind set: {hybrid}')
hybrid=json.loads(read('serverbridge/hybrid-targets.json'))
if any(x.get('status')!='not-certified' for x in hybrid['targets']): raise SystemExit('hybrid target unexpectedly certified')
cert=read('serverbridge/certify_release.py')
require(cert,["'quilt':'quiltSha256'","'sponge':'spongeSha256'","'vanilla':'vanillaSha256'",'universalServerAdapters','hybridCertificationPolicy'],'release certification')
build=read('scripts/build/bridge-plugins.sh')
require(build,[':plugins:quilt-bridge:remapJar',':plugins:sponge-bridge:jar',':plugins:vanilla-bridge:jar','QUILT_SHA256','SPONGE_SHA256','VANILLA_SHA256'],'production build')
openapi=read('scripts/contracts/generate_openapi.py')
require(openapi,['"fabric","quilt","forge","neoforge","sponge","vanilla"'],'OpenAPI platform enum')
print('ServerBridge Universal Server Adapters 0.19.8 production gate: OK (14 adapters; hybrid cohort fail-closed)')

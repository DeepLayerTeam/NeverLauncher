# NeverLauncher 0.44.9 — интеграционная приёмка переноса Gravit → Never

This release adds an executable, fail-closed acceptance gate. It **does not** claim that a Minecraft project passed actual launch, login, join, cutover or rollback in the developer's environment. `go test` tests the verifier, not Minecraft gameplay. A production Migration GA approval requires the three separately provisioned, real reference projects below, a protected CI runner, and retained independent evidence.

## Поддерживаемые исходные классы и обязательные проверки

| Reference class (`referenceClass`) | Required real environment | Required class-specific checks |
| --- | --- | --- |
| `fileauth-single` | A source Gravit FileAuth project, imported player UUIDs, real client and Minecraft server | `fileauth-login`, `skins`, `negative-auth` |
| `sql-modded` | A source SQL auth project with both **actual** Forge and NeoForge test profiles, optional mods, and real server(s) | `sql-login`, `forge-launch-join`, `neoforge-launch-join`, `optional-presets`, `skins`, `negative-auth`, `negative-optional` |
| `proxy-network` | Gravit proxy network, source-port replacement for the project's custom module, ServerBridge and authenticated server(s) | `official-login`, `serverwrapper`, `module-source-port`, `negative-unknown-module`, `negative-auth` |

**Every** reference additionally runs `uuid-world-plugin-data`, `admin-permissions`, `desktop-cache-install`, `staged-cutover-canary`, `operational-rollback-drill`, `negative-cutover`, `negative-rollback`. Total: 10 + 14 + 12 = **36 independent executable checks** on **three distinct projects/source archives/migration runs**, all tied to the same Never commit. A reference project missing a required environment is `BLOCKED`, not `SKIPPED` or `PASS`. No check may be filled with placeholder output or a synthetic success fixture.

The negative checks must actually attempt and observe rejection of: invalid/expired or revoked credentials (`negative-auth`), conflicting optional dependencies (`negative-optional`), unknown/unported Gravit JARs (`negative-unknown-module`), activation without current valid source fence or live rehearsal (`negative-cutover`), and rollback with changed/expired snapshot authorization (`negative-rollback`). Valid positive checks must observe real client/Java process and server join, not only a CLI exit code. Preserve raw logs and server observations without access tokens or private keys. The MIG10 live rehearsal remains required in the backend report before any GA check can be signed. `module-source-port` requires execution of the ported extension's actual user behavior (not merely a registered extension).

## Сборка и настройка оператором

Build on the pinned project toolchain and verify the full backend, CLI, Admin and supported Desktop variants. Test PostgreSQL migrations and rollback through a fresh database. Gravit source ZIP must include a recognizable `LaunchServer.jar` manifest, match the independently pinned JAR SHA-256 and be restricted to Gravit `5.7.0`–`5.7.12` for this gate; `5.7.13` is only recognized by inventory, not certified here. Store credentials in the protected runner, never in check arguments or JSON logs.

`tools/migration-ga` provides executable `certify`, `verify`, and `verify-cohort` commands. A plan contains a `referenceClass`, source archive and SHA-256 of the trusted Gravit LaunchServer JAR, target release SHA-256, full commit SHA, run ID, project ID, backend HTTPS origin, absolute signing-key path, and **exactly** the checks for that class. Each check has:

```json
{
  "name": "fileauth-login",
  "command": ["/opt/migration-ga/checks/fileauth-login", "--config", "/srv/isolated/ga/fileauth.json"],
  "executableSha256": "<64-lowercase-hex-SHA256-of-the-executable>",
  "timeoutSeconds": 300
}
```

The path above is illustrative: the operator must install a working executable that really exercises the stated behavior. The checker pins its exact bytes **before and after** execution, rejects symlinks and changed executables, bounds execution time and stdout, strips signing and backend credentials from subprocess environment, and discards untrusted stderr from CI logs. Check output must conform to the existing strict `Probe` JSON shape, include its unique run/report/source/release digests, and refer to a **newly generated** absolute evidence file. The check cannot simply emit `passed:true`; it must produce a real supporting evidence file whose content the independent reviewer can inspect. The checker validates SHA-256 and copies the exact evidence plus the canonical check receipt into an owner-only directory using no-overwrite writes.

```bash
export LAUNCHER_MIGRATION_GA_TOKEN='<short-lived-admin-token>'
go -C tools/migration-ga run . certify \
  --plan /srv/isolated/plans/fileauth-single.json \
  --output /srv/private/ga/fileauth-single-certificate.json \
  --evidence-dir /srv/private/ga/fileauth-single-evidence

go -C tools/migration-ga run . verify \
  --certificate /srv/private/ga/fileauth-single-certificate.json \
  --public-key /srv/private/trusted-ga-pub.pem \
  --evidence-dir /srv/private/ga/fileauth-single-evidence
```

Repeat on independent source projects for `sql-modded` and `proxy-network`. Verify the entire cohort:

```bash
go -C tools/migration-ga run . verify-cohort \
 --public-key /srv/private/trusted-ga-pub.pem \
 --fileauth-single /srv/private/ga/fileauth-single-certificate.json \
 --fileauth-single-evidence /srv/private/ga/fileauth-single-evidence \
 --sql-modded /srv/private/ga/sql-modded-certificate.json \
 --sql-modded-evidence /srv/private/ga/sql-modded-evidence \
 --proxy-network /srv/private/ga/proxy-network-certificate.json \
 --proxy-network-evidence /srv/private/ga/proxy-network-evidence
```

`verify` **requires** raw receipts/evidence, not only a signed certificate. It rejects missing, extra, symlinked or modified evidence, changed receipts, incorrect run/source/target, inconsistent world/UUID/plugin hashes, stale certificates, wrong signing key or a missing required negative check. `verify-cohort` also rejects absent/reused classes, duplicated project IDs, source archives or run IDs and mixed commits. Certificates use `launcher.gravit-ga-execution.v2` and the 0.44.9 domain-separated Ed25519 signature; historic 0.34 receipts cannot be reused.

## Состояние CI, хранилища и выпуска

The protected workflow `.github/workflows/gravit-migration-ga-0340.yml` performs unit/race tests, database integration and full product builds first. Its protected `migration-ga-certification` environment then uses three `MIGRATION_GA_{FILEAUTH,SQL,NETWORK}_PLAN_B64` secrets, admin token, signer/public-key secrets and `MIGRATION_GA_EVIDENCE_ROOT` repository environment variable. The latter must name an existing 0700 private directory on an isolated Linux runner. Signed certificate summaries can be uploaded as CI artifacts; raw evidence is retained **only in that private root**, not uploaded to potentially public artifacts. Configure retention, access control, sanitized logs and secure backup for that root separately. The administrator's approval and all 36 independent checks must be completed anew when the source ZIP, operator review, active release, migration snapshot or commit changes.

A passing GitHub workflow **on its own** cannot prove that the self-hosted runner used genuine Gravit/Minecraft assets or that a malicious trusted operator did not falsify observations. Independent review of actual raw logs, live game/server evidence and rollback drill results remains mandatory. None of the old Gravit authentication secrets, session tokens, signing keys, original worlds or external proxy traffic are switched by the verifier. Failure leaves the release blocked; it never automatically cutovers or rolls back production.

### Критерии выпуска

- Three distinct real Gravit sources and Never migration runs, all class checks passing with preserved evidence.
- PostgreSQL integration, Admin/Desktop/CLI/backend builds, real Minecraft login/join and negative tests completed on the actual supported configurations.
- A real restoration/rollback rehearsal performed without silent loss of player worlds, UUIDs, inventory, economy or plugin data; operator records its limits and the point of no return.
- Independent operator verifies full evidence set and signs off on manual steps and external DNS/proxy/server control.

Absent private test infrastructure is a **blocker** for Migration GA certification; it is not permission to downgrade to a simulated PASS.

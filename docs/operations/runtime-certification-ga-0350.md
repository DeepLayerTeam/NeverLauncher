# NeverLauncher 0.35.0 — Runtime Certification GA operations

## Trust boundary and prerequisites

0.35.0 remains **blocked for GA** until this runbook has been executed on a disposable production-equivalent environment with a genuine staged Minecraft client and the applicable dedicated server. An observational CI run, an HTTP 200, a fake client log, or the bundled test fixture never certifies Minecraft.

Provision: PostgreSQL 17 with migrations through `0107`; deployed API configured with `NEVERLAUNCHER_VALIDATION_REQUIRED_TARGETS_JSON`, trusted attestor Ed25519 public key and exact OCI digest; a separate isolated Podman attestation host with protected signer; immutable staged content; Java runtimes and dedicated Windows/Linux/macOS GUI workers for all **claimed** OS/arch targets; real Minecraft accounts authorized for test use; applicable ServerBridge/plugins and servers; a previous signed release, managed JRE and replacement Java; encrypted backups and rollback runbook. Store credentials and signing keys only in protected environments, not GitHub-hosted test workers.

## Execution steps

1. Deploy `0107_ga_stable_snapshot_0350.sql` **after** migrations through `0106`. Backup PostgreSQL and verify `stable_runtime_release_guard_0341`, `stable_runtime_head_guard_0341`, `stable_files_guard_0350` and `stable_integrity_immutable_0350` triggers are enabled. Use least-privilege app roles; a DB owner/superuser is outside the SQL trigger trust boundary.
2. Build and sign candidate 0.35.0 from one exact source commit. Stage the immutable package, run the real package integrity check and freeze its file metadata. Do not recreate equivalent upstream artifacts in test runners. Every OS, architecture, Java, loader, preset and condition branch claimed in target policy must have a concrete target.
3. On the attestation host, run **each** required target in a new rootless Podman container with an independent workspace and single-use challenge. Fetch the staged package from the configured API; perform transactional materialization; verify manifest/file SHA-256; execute normal NeverRuntime with the specified Java, loader and selected optional components.
4. On a real GUI-capable worker confirm the correct process/window, usable renderer, actual main menu and loader readiness, then connect to the matching server and record login, client/server join, game state, ticks and a player action. Use real provider integration (not mock) for custom join/hasJoined and official Minecraft login. Include authorization revocation, Guard/device policy and anti-replay cases. Missing display/renderer means `blocked`, not a Minecraft incompatibility.
5. Execute V09 against the signed **previous** release: cold install, update, corrupt cache/file and repair, interrupted download and two transaction kill points, Java replacement/recovery and actual previous-release rollback/relaunch. Observe exact bytes and actual state, not only process exit status.
6. The independent attestor rehashes diagnostic artifacts, checks the completed scenario and signs v4 `ValidationEvidence` with its protected key. Check API `/api/v1/packages/{packageId}/validation-report`: every mandatory target must be `signature-and-execution-verified` and every required runtime stage must be `passed`.
7. Run `.github/workflows/runtime-acceptance-0350.yml` using the protected `runtime-validation-ga` environment and exact staged package ID. Its read-only live Backend preflight must pass. Run `production-release-candidate.yml` only from `main`; the release signer also performs a fresh API preflight before signing. **The signed release preflight is only a snapshot of Backend eligibility**, not the certificate. The Backend verifies full evidence again and the PostgreSQL transaction enforces the one-use permit at `channel_heads` commit.
8. Only then request durable promotion to stable with fresh MFA. Verify the resulting `channel_heads` revision and release digest, and retain the immutable audit, evidence hashes, redacted logs, build provenance, attestation-host receipt, exact matrix and policy snapshot.

## Four required end-to-end acceptance cases

- **Integrity-positive, runtime-negative:** modify a staged executable mod or Java bytecode, recalculate the *owner-signed* manifest and its integrity hashes legitimately, then prove `manifest/files` PASS and runtime stage FAILED. Durable stable publish and direct SQL/channel head changes must refuse it.
- **Cross-target evidence substitution:** replay a valid, signed v4 evidence from a different release, Java binary/version or optional preset. The Backend must report missing/target mismatch; publish refused.
- **Positive execution:** start the installed staged client's actual Java process, confirm renderer/menu/loader, real provider, matching server join, world ticks/player action, update/repair/rollback. Only corresponding real, fresh signed evidence yields eligible; subsequently commit via durable publish.
- **Provider outage:** isolate or deliberately disable the external identity provider, without substituting a mock. Required provider target is `inconclusive`/`blocked`, never `passed`; stable head unchanged.

## Operational response

On `blocked`, missing targets, stale keys, new adapter/Java/preset/server settings or integrity mismatch: leave the candidate staged, remediate the root cause and issue **new** trusted runs. Never set a manual `certified` flag. To revoke compromised attestor keys, use the authenticated key-revocation operation and rerun all affected targets; do not reuse old permits. Preserve an immutable copy of validation reports and redacted logs with retention per V12 policy. Do not disable the DB guards during emergency rollback: re-certify the previous release or use a documented emergency maintenance process that does **not** change protected stable head.

## Readiness sign-off

Before declaring GA, attach time-stamped real execution references, the signed target matrix and artifact digests, PostgreSQL integration/adversarial results, production builds, provider status, and approvals by release/security owners to `docs/reports/ga-readiness-0350.md`. Without these, status is **not verified**.

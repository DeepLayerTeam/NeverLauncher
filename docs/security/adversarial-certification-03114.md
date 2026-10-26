# NeverLauncher 0.31.14 — Adversarial Security Certification

**Status: certification pending external test evidence.** This release adds executable regression attacks and a fail-closed results gate; it does **not** certify the kernel, physical TPM, other host applications, or the full launcher without running those tests.

## Scope and guarantees

- TPM Certify: certified registered key, AK trust chain, nonce, device/user/session/epoch/expiration. A passing synthetic cryptographic test does not establish physical TPM provenance or attest JVM memory.
- Quote: independently signed PCR digest, exact PCR selection, operator policy, pinned AK/root. A passing measured-boot quote says nothing about late user-mode injection.
- Extension host: per-instance HTTP rate, concurrent request and output budgets across reconnects; signed grants, scoped filesystem and HTTPS operations; owner confirmation of privilege changes.
- Linux: only live user+mount+PID+network namespace/cgroup v2/seccomp tests prove the configured kernel confinement. Root/service process group separation **is not** a sandbox.
- Windows: only live AppContainer token, Job Object, ACL, IPC and child-process tests prove the boundary. Cross-compilation is not proof.
- macOS: `isolated` is intentionally unavailable until all descendants have an OS-enforced, non-escapable resource boundary. Signed helper alone is insufficient. Do not silently fall back to `trusted`.
- OS-level Guard attach/injection protection cannot be inferred from self-reported user-mode evidence. Document and test normal accessibility/overlays/AV on supported hosts before enabling stricter blocking policy.

## Executable tiers

Run from repository root. Python 3 and matching Go toolchain are required.

```bash
# Deterministic attack regression tests, including -race:
python3 scripts/security/certify_03114.py --tier offline --output /tmp/nl-offline.json

# Guard Runtime Policy, continuous ticket/session and release allowlist tests
# (requires ALL Backend Go dependencies, not merely the nopgx build tag):
python3 scripts/security/certify_03114.py --tier backend-security --output /tmp/nl-backend.json

# On a dedicated UNPRIVILEGED Linux worker with delegated writable cgroup v2,
# enabled unprivileged user namespaces and supported seccomp:
python3 scripts/security/certify_03114.py --tier linux-live --output /tmp/nl-linux-live.json

# On a provisioned native Windows worker that permits AppContainer/Jobs:
python scripts/security/certify_03114.py --tier windows-live --output C:\\Temp\\nl-windows-live.json

# Never infer PASS from missing evidence. A release fails unless ALL tiers pass:
python3 scripts/security/certify_03114.py --tier release --output /tmp/nl-gate.json --evidence /tmp/nl-offline.json /tmp/nl-backend.json /tmp/nl-linux-live.json /tmp/nl-windows-live.json
```

Live Linux test verifies actual namespace setup (not merely `Available()`), no backend secrets, immutable package, `NoNewPrivs`, seccomp mode, dropped effective capabilities, and termination of children in a new process group using cgroup.kill. Live Windows test checks true AppContainer token, inaccessible private backend file, read-only package, denied direct internet, named-pipe broker, and Job process-count containment.

The test executor requires each named test to appear as `PASS` in Go's JSON test events. A `SKIP`, absent test, failing command or insufficient platform yields `BLOCKED`/`FAIL` and exit code 1. CI artifacts include the code fingerprint, host platform, run time, statuses and failure excerpts. **Evidence is not cryptographically signed by the Python tool**; use CI artifact provenance and restricted runner permissions.

## Additional mandatory **manual / hardware** scenarios

These are not marked successful by the offline runner and cannot be replaced with a simulator:

1. **Physical TPM on Windows and Linux:** genuine AK issued under a trusted CA and real device key; reject software/self-asserted hardware, wrong key, expired challenge, replayed challenge, rotated binding epoch, revoked AK/root, root replacement and stale runtime.
2. **Measured boot:** accepted physical TPM2 Quote after valid Certify, then policy changes and PCR changes; demonstrate revocation and distinct assurance from Guard process evidence.
3. **Guard and attach/injection:** attempt user-mode attach, debug agent, injected module and modified JVM binary under each supported policy; verify server-side join rejection when required, and document paths OS/user-mode controls cannot exclude. Never promise absolute anti-cheat.
4. **OS sandbox:** attempts to read backend secrets, modify foreign files, open ungranted addresses, create child process groups, exhaust memory/CPU/PIDs/output/requests, disable own policy, and restart to reset quotas. Check expected denial and cleanup after process exits on each supported OS.
5. **Compatibility:** launch tested ordinary screen overlays, assistive technology, antivirus/EDR and debugger/dev tools according to the operator's supported app policy; document false positives and explicit allowed exceptions without disabling isolation.
6. **macOS:** independently prove sandbox inheritance and the aggregate descendant resource boundary on physical hardware before enabling `isolated`. Until then, an explainable `unsupported` result is expected, not PASS.

## Exit criteria

A real 0.32.0 GA security certification requires offline PASS, Backend Guard tests PASS, live Linux PASS, live Windows PASS, tested macOS policy disposition and PASS on all relevant physical TPM/Guard and compatibility cases, from the **same exact source tree**. Failed or skipped mandatory tests prohibit the claim. Evidence must not contain credentials, AK private keys, raw secrets or proprietary personal logs.

Current 0.31.14 automated release gate is deliberately incapable of passing with only three software reports: physical, compatibility and macOS evidence are mandatory and not synthesized.

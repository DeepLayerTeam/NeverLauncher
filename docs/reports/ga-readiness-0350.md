# NeverLauncher 0.35.0 — GA readiness report

**Status: NOT VERIFIED / STABLE MUST REMAIN FAIL-CLOSED.**

This report records work that is verifiable from the supplied 0.34.12 archive and local tooling. It is not an independently signed Minecraft runtime certificate. A source patch cannot, by itself, fulfil the four real E2E release acceptance criteria.

## Implementation in this patch

- Version metadata synchronized to 0.35.0.
- Source SHA consistency enforced by live Backend stable evaluator; exposed in read-only policy/report to bind release workflow commit.
- PostgreSQL migration `0107` freezes verified stable file metadata, manifest, integrity history, published status/time and prevents deletion of a verified stable release.
- Read-only `runtime_acceptance_0350.py` checks exact staged package, version/source SHA, integrity PASS, full trusted coverage, matrix digest, per-target live evidence, expiry and all nine required execution stages. No manual certification override or mock fallback.
- `runtime-acceptance-0350.yml` runs PostgreSQL security tests and consults deployed protected Backend. Production release workflow requires it; release signer itself repeats the protected Backend check before building 0.35.0 GA artifacts.

## Executed locally (2026-10-28)

- Python acceptance, attestor, authentication, optional components, staged execution, startup, matching/gameplay and V09 regressions: **71 passed, 2 skipped** across 73 cases. These are tests of the tooling and negative decisions, **not** a live Minecraft client/server certification.
- Production CLI: `go build ./cmd/neverlauncher` completed.
- Canonical version metadata: `python3 scripts/version/manage.py check` passed for 0.35.0.
- Release signing shell: `bash -n scripts/release/build-release.sh` passed.
- GitHub Actions workflows: YAML parsing succeeded.
- Read-only GA preflight with no protected token returned exit code 3 and produced no acceptance report (fail-closed negative check).
- Backend Go tests: blocked by local Go 1.23.2 versus required 1.27.3; **no successful PostgreSQL migration run** is asserted.

## Acceptance matrix

| Criterion | Status | Evidence still required |
|---|---|---|
| Correctly rehashed broken release passes integrity but fails true runtime, cannot enter stable | **Not run live** | Real staged bad client/mod and actual blocked durable commit |
| Different release/Java/preset signed evidence rejected | **Not run live** | Trusted attestor evidence and real Backend mismatch attempt |
| Positive target confirmed by actual client menu, world join, gameplay and lifecycle | **Not run live** | Genuine GUI + matching server, provider and independent v4 signature |
| Provider outage yields inconclusive/blocked, never PASS | **Not run live** | External provider fault-injection with real provider integration |
| Backend Go + PostgreSQL full security suite | **Not executed locally** | Go 1.27.3, PostgreSQL 17 and integration tests in protected CI |
| Rust, GUI, native platform targets, production build | **Not executed locally** | Rust toolchain and provisioned machines with display, renderer and accounts |

## Release decision

Do not advertise this repository patch as production-certified GA until CI, staging, provider and gameplay evidence have been attached with exact commit, package ID, matrix digest and attestor fingerprint, and the stable head has been advanced only by the real guarded transaction. The current fail-closed behavior is a **required safety condition**, not a failure that can be overridden by a manual flag.

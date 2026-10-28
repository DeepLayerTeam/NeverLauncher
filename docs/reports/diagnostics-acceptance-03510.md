# 0.35.10 Diagnostics acceptance

| Check | Status | Evidence |
| --- | --- | --- |
| Explicit consent required in player UI | Local Node regression | `apps/desktop/tests/diagnostics_support_03510.test.mjs` |
| Unknown report fields/categories rejected by Backend | Go test added, not locally executable with Go 1.23.2 | `support_reports_03510_test.go` |
| Native report excludes arbitrary logs and secret-bearing URLs/paths | Rust test added, toolchain unavailable locally | `diagnostics_bundle_03510.rs` |
| Exact reviewed payload persisted to app-owned private directory | Rust test added, toolchain unavailable locally | `diagnostics_bundle_03510.rs` |
| Authenticated operator access and support inbox | Backend implementation and Admin interface; platform E2E not run | `support_reports_03510.go`, `SupportDiagnostics03510.tsx` |
| Full React/Tauri build | Not verified locally (missing pinned npm/Rust dependencies) | CI workflow included; result not assumed |

**Release claim:** production-path code supplied, but fully compiled, live end-to-end production certification remains **NOT VERIFIED** until all jobs and staged support/consent scenarios run.

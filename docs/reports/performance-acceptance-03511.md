# 0.35.11 performance acceptance — evidence status

## Completed in the source workspace

- New Python benchmark runner with actual compiled executable launch, real HTTP Range network transfer, verification of signed fixtures and independent output SHA-256.
- 10,000-file verification mode, configurable downloaded file sizes including 1 and 10 GiB, a fresh install and cached update of each signed fixture, per-process CPU/RAM sample collection.
- First-render startup marker in the native Tauri command, emitted by React after two animation frames; records process-first vs subsequent warm launches.
- Actual read-only Backend HTTP probe with p50, p95, p99, bounded concurrency and optional Backend PID CPU/RAM sampling.
- Local test suite: unit, rejection, local actual HTTP byte and local process metrics tests.

## Not certified on this workspace

- Rust toolchain and compiled NeverRuntime/desktop binaries are not present, so native 10k verification, native 1/10 GiB downloads and cold/warm real Tauri launches cannot be measured here.
- No running production-like PostgreSQL Backend/representative Admin endpoint was provided, so real app HTTP latency is not yet measured here.
- No external baseline executable and no comparable measurements on equal hardware exist. Do not claim performance superiority.

The release source version does not elevate unexecuted benchmark scenarios to `passed`.

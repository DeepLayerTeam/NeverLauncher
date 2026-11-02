# Guard 0.50.1 — native inventory and baseline

This feature **executes** installed Java and the existing Guard child-process
boundary. It does **not** start Minecraft or certify in-process protection.
`BLOCKED`/`UNSUPPORTED` are intentional, not successful release gates.

## Native command

Build **both** executables with the same release source/toolchain:

```sh
cargo build --manifest-path runtime/runtime/Cargo.toml --bins
```

Linux/macOS (replace `.exe` suffix on Windows):

```sh
python3 scripts/guard_ci/inventory_0501.py local \
  --runtime runtime/runtime/target/debug/runtime \
  --guard runtime/runtime/target/debug/guard \
  --java /path/to/java \
  --game-root /path/to/minecraft \
  --minecraft-version 1.21.1 \
  --output guard-inventory-linux-x64.json
```

`runtime guard-inventory` can also be called directly. Supported flags:
`--guard-executable`, `--java`, `--game-root`, `--minecraft-version`.
The `--game-root` and `--minecraft-version` pair is mandatory when
inspecting installed Minecraft metadata. A version ID must be a single
safe filename. The scanner reads at most 2 MiB of version JSON and refuses
escaping the resolved Minecraft root.

The local wrapper creates a private 0700 Linux IPC directory and invokes the
native Runtime with a 50-second maximum duration. Runtime starts a **real**
Guard process through the production platform supervisor; requests authenticated
status, enforced process policy, validated image/module integrity and a fresh
remote attestation challenge; then shuts it down. Failed checks stay `BLOCKED`.
No simulator or fake IPC responder is used. In debug builds the release package
manifest is not asserted as verified: `guard.release-package = BLOCKED`.

The Java probe runs `-XshowSettings:properties -version` with an eight-second
limit and without inherited JVM injection options. It does not certify an
individual Minecraft/JDK combination. The loader probe identifies the
`mainClass` of installed version metadata (Vanilla, Fabric, Quilt, Forge,
NeoForge or unknown). No JAR is executed. This does not prove that the loader,
optional mods, native libraries or agents can start successfully.

## Native baseline matrix

CI workflow `.github/workflows/guard-inventory-0501.yml` builds and runs native
reports independently on:

- Linux x86_64 / aarch64;
- Windows x86_64 / aarch64;
- macOS x86_64 / aarch64.

Each report is preserved as a separate downloadable CI artifact. Consolidate:

```sh
python3 scripts/guard_ci/inventory_0501.py matrix \
  --output guard-inventory-matrix-0501.json guard-inventory-*.json
```

The merger enforces the exact 0.50.1 report schema, checks, version, target
uniqueness, `UNSUPPORTED` for non-Windows in-process sensors and `BLOCKED` for
all unexecuted real-game/loader/authorized-agent scenarios. Missing native
OS/CPU reports are `BLOCKED`, never implicit `PASS`. Reports are local,
self-reported observations; they are **not cryptographic endorsements by
independent operators**. `certified=false` is always explicit.

## Baseline and acceptance boundary

| Mechanism | Windows | Linux | macOS |
|---|---|---|---|
| Guard subprocess and authenticated IPC | Actively probed | Actively probed | Actively probed |
| Guard process hardening/policy | Actively probed | Actively probed | Actively probed |
| Guard + launcher binary integrity | Actively probed | Actively probed | Actively probed |
| Fresh Guard attestation challenge | Actively probed | Actively probed | Actively probed |
| Release package identity | Verified only if supervisor verifies production package | Same | Same |
| Windows in-process Sensor | BLOCKED without game | UNSUPPORTED | UNSUPPORTED |
| JVM awareness + continuous Sensor | BLOCKED without game | UNSUPPORTED | UNSUPPORTED |
| Vanilla/Fabric/Quilt/Forge/NeoForge runtime compatibility | BLOCKED until real launch/join | BLOCKED | BLOCKED |
| Trusted Java Agent + Guard | BLOCKED until approved real-agent run (0.50.3) | BLOCKED | BLOCKED |

The existing Windows source rejects `-javaagent` in the sensor startup path.
0.50.1 **does not disable that defense**. Work to reconcile owner-approved
agents with signed Guard policies is explicitly scoped to 0.50.2–0.50.4.

A real production acceptance requires signed final installers; actual
Vanilla and modded Minecraft gameplay with official sessions as applicable;
loader/JDK/OS/arch coverage; runtime sensor, watchdog and ServerBridge evidence;
independent native-runner reports; and verification of corresponding package
hashes and signatures. None is inferred from the existence of this command or
from a successful CI diagnostic job.

## Regression checks

```sh
python3 scripts/guard_ci/test_inventory_0501.py
cargo test --manifest-path runtime/runtime/Cargo.toml --lib guard_inventory_0501
cargo test --manifest-path runtime/runtime/Cargo.toml --test guard_inventory_0501
```

The third command is Linux-only (the Rust integration test is conditionally
compiled). CI runs it on native Linux architectures. An IPC failure remains a
failure of the native integration test; it is not converted into a successful
capability row.

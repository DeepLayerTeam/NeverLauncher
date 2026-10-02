#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(body: str, needles: list[str], label: str) -> None:
    missing = [needle for needle in needles if needle not in body]
    if missing:
        raise SystemExit(f"[NeverLauncher] Windows Protection Core II 0.18.1 gate: {label} missing {missing}")


def main() -> int:
    version = read("VERSION").strip()
    if tuple(int(part) for part in version.split("-")[0].split("+")[0].split(".")[:3]) < (0, 18, 1):
        raise SystemExit(f"[NeverLauncher] Windows Protection Core II 0.18.1 gate: VERSION is {version}")

    protection = read("runtime/neverruntime/src/windows_protection.rs")
    policy = read("runtime/neverruntime/src/windows_policy.rs")
    ipc = read("runtime/neverruntime/src/guard_ipc.rs")
    guard = read("runtime/neverruntime/src/bin/neverguard.rs")
    lib = read("runtime/neverruntime/src/lib.rs")
    integration = read("runtime/neverruntime/tests/neverguard_windows.rs")
    ci = read(".github/workflows/ci.yml")
    preflight = read("scripts/release/preflight.sh")

    require(
        protection,
        [
            "NEVERGUARD_WINDOWS_PROTECTION_CORE_VERSION: u32 = 2",
            "NEVERGUARD_WINDOWS_CAPABILITY_MODEL_VERSION: u32 = 1",
            "NEVERGUARD_WINDOWS_PROTECTION_PROFILE_ENV",
            "pub enum WindowsProtectionProfile",
            "Audit,",
            "Compat,",
            "Aggressive,",
            "pub const fn is_remote_attestation_eligible",
            "pub const fn for_profile",
            "pub struct WindowsMitigationCapability",
            "pub struct WindowsProtectionCapabilities",
            "requirements_satisfied",
        ],
        "profile/capability model",
    )
    require(
        policy,
        [
            "SetProcessMitigationPolicy",
            "GetProcessMitigationPolicy",
            "IsProcessInJob",
            "ensure_guard_process_policy_with_profile",
            "ensure_windows_protection_core_with_profile",
            "apply_policy_if_required",
            "mitigation_capability",
            "current_process_is_job_bound",
            "validate_windows_guard_policy_report",
            "protection_core_rejects_capability_drift",
            "protection_core_rejects_profile_substitution",
        ],
        "runtime enforcement",
    )
    require(
        ipc,
        [
            '.arg("--protection-profile")',
            "with_executable_and_profile",
            'send_command(&mut handle, "process-policy")',
            "validate_windows_guard_policy_report(policy, handle.protection_profile)",
            "remote attestation requires aggressive Windows protection profile",
            "windows_protection_core_version",
            "windows_capability_model_version",
            "validate_status_profile",
        ],
        "authenticated supervisor integration",
    )
    require(
        guard,
        [
            "ensure_windows_protection_core_with_profile",
            "windows_protection_profile(&args)",
            "--protection-profile audit|compat|aggressive",
        ],
        "guard executable profile activation",
    )
    require(
        lib,
        [
            "pub mod windows_protection;",
            "WindowsProtectionProfile",
            "WindowsProtectionCapabilities",
            "ensure_windows_protection_core_with_profile",
        ],
        "public runtime API",
    )
    require(
        integration,
        [
            "neverguard_process_boundary_authenticates_and_shuts_down",
            "neverguard_compat_profile_enforces_its_runtime_capabilities",
            "neverguard_audit_profile_measures_without_claiming_remote_trust",
            "guard_lifetime_job_bound",
            "remote_attestation",
        ],
        "Windows executable integration coverage",
    )
    require(
        ci,
        [
            "windows-protection-core-II-0181.py",
            "cargo test --manifest-path runtime/neverruntime/Cargo.toml --test neverguard_windows -- --nocapture",
            "cargo clippy --manifest-path runtime/neverruntime/Cargo.toml --all-targets -- -D warnings",
        ],
        "Windows CI",
    )
    if "windows-protection-core-II-0181.py" not in preflight:
        raise SystemExit("[NeverLauncher] Windows Protection Core II 0.18.1 gate: preflight wiring missing")

    for path, body in [
        ("runtime/neverruntime/src/windows_protection.rs", protection),
        ("runtime/neverruntime/src/windows_policy.rs", policy),
        ("runtime/neverruntime/src/guard_ipc.rs", ipc),
        ("runtime/neverruntime/src/bin/neverguard.rs", guard),
    ]:
        for forbidden in ("todo!()", "unimplemented!()", "TODO: stub", "foundation placeholder"):
            if forbidden in body:
                raise SystemExit(
                    f"[NeverLauncher] Windows Protection Core II 0.18.1 gate: placeholder {forbidden!r} in {path}"
                )

    print("[NeverLauncher] Windows Protection Core II 0.18.1 gate: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

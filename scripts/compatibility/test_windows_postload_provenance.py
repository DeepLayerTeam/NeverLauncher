#!/usr/bin/env python3
"""Platform-neutral source guardrails for Windows native-memory provenance fixes.

These contract tests complement, but cannot replace, Windows/ARM64 integration.
"""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
HOOKS = ROOT / "runtime/guard-sensor/src/hook_engine.rs"
SENSOR = ROOT / "runtime/guard-sensor/src/lib.rs"
RUNTIME = ROOT / "runtime/runtime/src/lib.rs"


class WindowsPostloadProvenanceTests(unittest.TestCase):
    def test_all_four_load_library_hooks_reconcile_after_loading(self):
        source = HOOKS.read_text(encoding="utf-8")
        region = source.split('unsafe extern "system" fn hook_load_library_a(', 1)[1]
        region = region.split("// Track dynamically resolved entry points", 1)[0]
        self.assertEqual(region.count("reconcile_after_library_load(module);"), 4)
        self.assertEqual(region.count("SetLastError(last_error);"), 4)
        self.assertIn("ENGINE_STATE.try_lock()", source)
        self.assertIn(
            "state.healthy = false;",
            source.split("fn reconcile_after_library_load(", 1)[1].split(
                "fn verify_locked(", 1
            )[0],
        )

    def test_live_iat_pointer_patches_are_atomic(self):
        source = HOOKS.read_text(encoding="utf-8")
        patch = source.split("fn patch_pointer(", 1)[1].split("fn restore_records(", 1)[
            0
        ]
        self.assertIn("AtomicUsize::from_ptr", patch)
        self.assertIn("Ordering::Release", patch)
        self.assertNotIn("write_volatile", patch)

    def test_abort_remains_fail_closed_and_explains_windows_fastfail(self):
        source = SENSOR.read_text(encoding="utf-8")
        func = source.split("fn guard_fail_closed_abort()", 1)[1].split(
            "fn module_worker(", 1
        )[0]
        self.assertIn("std::process::abort()", func)
        self.assertIn("Guard Sensor fail-closed abort", func)
        worker = source.split("fn module_worker(", 1)[1].split(
            'pub extern "system" fn Agent_OnLoad(', 1
        )[0]
        self.assertGreater(worker.count("guard_fail_closed_abort()"), 20)

    def test_windows_fastfail_needs_authenticated_guard_violation(self):
        source = RUNTIME.read_text(encoding="utf-8")
        block = source.split("if exit_code == Some(0xE3) ||", 1)[1].split(
            "let finished_at = now_unix()?", 1
        )[0]
        self.assertIn("guard.last_violation.is_empty()", block)
        self.assertIn("0xC000_0409u32 as i32", source)


class WindowsGuardRaceRegressionTests(unittest.TestCase):
    """Source-level contract checks; native semantics require Windows CI."""

    def test_trusted_system_and_jre_dispatchers_validate_exact_loaded_path(self):
        source = (ROOT / "runtime/guard-sensor/src/jvm_awareness.rs").read_text(
            encoding="utf-8"
        )
        resolver = source.split("fn resolve_system_dispatchers()", 1)[1].split(
            "pub fn capture_transition_provenance()", 1
        )[0]
        self.assertIn("GetSystemDirectoryW", resolver)
        self.assertIn("GetModuleFileNameW", resolver)
        self.assertIn("loaded_path != expected_path", resolver)
        self.assertIn("GetModuleHandleW", resolver)
        self.assertIn("K32GetModuleInformation", resolver)
        self.assertIn("TRUSTED_SYSTEM_DISPATCHERS", source)
        self.assertIn("caller_module_basename(caller)", source)
        self.assertIn("GetModuleHandleExW(flags, address as *const u16", source)
        self.assertIn("TransitionOrigin::ForeignNative =>", source)
        self.assertIn("FOREIGN_EXECUTABLE_TRANSITIONS.fetch_add(1", source)
        self.assertIn("outside jvm.dll provenance", source)
        self.assertNotIn("DISABLE_JVM_GUARD", source)

    def test_opengl_dispatcher_from_certified_jdk_or_system32(self):
        source = (ROOT / "runtime/guard-sensor/src/jvm_awareness.rs").read_text(
            encoding="utf-8"
        )
        resolver = source.split("fn resolve_system_dispatchers()", 1)[1].split(
            "pub fn capture_transition_provenance()", 1
        )[0]
        self.assertIn('"opengl32.dll"', resolver)
        self.assertIn("module_path(jvm_module)?", resolver)
        self.assertIn('runtime_opengl = jvm_bin.join("opengl32.dll")', resolver)
        self.assertIn("std::fs::symlink_metadata(&runtime_opengl)", resolver)
        self.assertIn("metadata.file_type().is_symlink()", resolver)
        self.assertIn(
            "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32", resolver
        )
        self.assertIn(
            "LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32)",
            resolver,
        )
        self.assertIn("loaded_path != expected_path", resolver)
        self.assertIn("K32GetModuleInformation", resolver)
        self.assertIn("TransitionOrigin::ForeignNative =>", source)
        self.assertIn("FOREIGN_EXECUTABLE_TRANSITIONS.fetch_add(1", source)
        self.assertNotIn("DISABLE_JVM_GUARD", source)

    def test_runtime_event_watchdog_remains_bounded_and_fail_closed(self):
        source = (ROOT / "runtime/runtime/src/windows_module_guard.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "MODULE_STREAM_TIMEOUT: Duration = Duration::from_secs(15)", source
        )
        self.assertIn(
            "MODULE_RUNTIME_EVENT_TIMEOUT: Duration = Duration::from_secs(45)", source
        )
        loop = source.split("async fn monitor_loop(", 1)[1].split(
            "fn hook_digest_from_event(", 1
        )[0]
        self.assertIn(
            "timeout(MODULE_RUNTIME_EVENT_TIMEOUT, server.read_exact(&mut packet)).await",
            loop,
        )
        self.assertIn("Module Guard heartbeat timeout", loop)
        self.assertIn("fail_closed(&state, pid, &reason, 0)", loop)
        self.assertIn(
            "parse_event_packet(&packet, secret, pid, expected_sequence)", loop
        )

    def test_unloads_require_signed_notification_and_bounded_grace(self):
        source = (ROOT / "runtime/runtime/src/windows_module_guard.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("UNLOAD_EVENT_GRACE: Duration = Duration::from_secs(4)", source)
        self.assertIn(
            "pending_unload_notifications.remove(&event.base_address)", source
        )
        self.assertIn(
            "pending_unloads.entry(*base).or_insert_with(Instant::now)", source
        )
        self.assertIn("if first_missing.elapsed() >= UNLOAD_EVENT_GRACE", source)
        self.assertIn("module base reused before authenticated unload", source)
        self.assertIn("validate_loaded_module(&module.path)", source)
        self.assertIn("Module Guard module path drift", source)

    def test_ack_still_requires_signed_packet_and_bounded_deadline(self):
        source = (ROOT / "runtime/guard-sensor/src/continuous_guard.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("GUARD_ACK_TIMEOUT: Duration = Duration::from_secs(35)", source)
        self.assertIn("mac.verify_slice", source)
        self.assertIn("Guard-ACK sequence mismatch", source)
        self.assertIn("Guard-ACK event-chain mismatch", source)
        self.assertIn("Guard-ACK heartbeat timeout", source)

    def test_lwjgl_native_is_pinned_to_materialized_platform_directory(self):
        source = (ROOT / "runtime/guard-sensor/src/jvm_awareness.rs").read_text(
            encoding="utf-8"
        )
        hooks = HOOKS.read_text(encoding="utf-8")
        region = source.split("pub fn register_loaded_native_dispatcher(", 1)[1].split(
            "pub fn capture_transition_provenance(", 1
        )[0]
        self.assertIn('launch_root.join("natives").join("windows")', region)
        self.assertIn("join(std::env::consts::ARCH)", region)
        self.assertIn('"x86_64" => "x64"', region)
        self.assertIn('"aarch64" => "arm64"', region)
        self.assertIn('.join("org").join("lwjgl").join("lwjgl.dll")', region)
        self.assertIn("let candidates = [", region)
        self.assertIn("let matched = matched.ok_or_else(||", region)
        self.assertIn("std::fs::symlink_metadata(&loaded)", region)
        self.assertIn("std::fs::canonicalize(expected)", region)
        self.assertIn("expected_path.starts_with(launch_root)", region)
        self.assertIn("rejected reparse/symlink native path", region)
        self.assertIn("LWJGL loaded outside certified natives directory", region)
        self.assertIn(
            "GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN",
            region,
        )
        self.assertIn("Sha256::digest(&bytes)", region)
        self.assertIn("RUNTIME_NATIVE_LOAD_FAILED.store(true", region)
        self.assertIn("register_loaded_native_dispatcher(module)", hooks)
        self.assertIn("VERIFIED_LWJGL_IMAGE.get().is_some_and", source)
        self.assertIn("LWJGL image content changed", source)
        self.assertIn("reconcile_first_runtime_native_transition()?;", source)
        self.assertIn("FOREIGN_EXECUTABLE_TRANSITIONS.compare_exchange(", source)
        self.assertIn("TransitionOrigin::ForeignNative =>", source)

    def test_ack_deadline_remains_shorter_than_guard_stream_watchdog(self):
        sensor = (ROOT / "runtime/guard-sensor/src/continuous_guard.rs").read_text(
            encoding="utf-8"
        )
        guard = (ROOT / "runtime/runtime/src/windows_module_guard.rs").read_text(
            encoding="utf-8"
        )
        import re

        ack = int(
            re.search(
                r"GUARD_ACK_TIMEOUT: Duration = Duration::from_secs\((\d+)\)", sensor
            ).group(1)
        )
        stream = int(
            re.search(
                r"MODULE_RUNTIME_EVENT_TIMEOUT: Duration = Duration::from_secs\((\d+)\)",
                guard,
            ).group(1)
        )
        self.assertLess(ack, stream)
        self.assertGreater(ack, 12)
        self.assertIn("mac.verify_slice", sensor)
        self.assertIn("Guard-ACK event-chain mismatch", sensor)

    def test_abort_diagnostics_include_rejected_reason(self):
        source = (ROOT / "runtime/guard-sensor/src/lib.rs").read_text(encoding="utf-8")
        self.assertIn("Guard JVM-Aware violation:", source)
        self.assertIn("Guard Continuous Guard ACK violation:", source)
        self.assertIn("guard_fail_closed_abort();", source)


class AdversarialProbeRuntimeTests(unittest.TestCase):
    def test_module_lifecycle_probe_allows_two_full_heartbeat_cycles(self):
        source = (ROOT / "runtime/runtime/tests/guard_sensor_windows.rs").read_text(
            encoding="utf-8"
        )
        block = source.split("fn compile_module_probe(", 1)[1].split(
            "fn compile_memory_integrity_probe(", 1
        )[0]
        self.assertIn("Thread.sleep(10000L);", block)
        self.assertIn("report.hook_engine.integrity_check_count >= 2", source)
        self.assertIn("report.memory_integrity.integrity_check_count >= 2", source)


class MaterializedWindowsLWJGLTests(unittest.TestCase):
    def test_windows_classifier_natives_are_published_as_verified_flat_copies(self):
        source = (ROOT / "cli/cmd/launcher/vanilla_runtime.go").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "flattenLWJGLWindowsNatives(stagingDir, extracted, target.Arch)", source
        )
        self.assertIn("extracted = append(extracted, aliases...)", source)
        self.assertIn(
            "publishFiles = append(publishFiles, vanillaDownloadedFile{", source
        )
        self.assertIn('"windows/" + classifierArch + "/org/lwjgl/"', source)
        self.assertIn("secureClientDestination(root, clean)", source)
        self.assertIn("secureClientDestination(root, base)", source)
        self.assertIn("LWJGL Windows native filename collision", source)
        self.assertIn("writeAtomicBytes(to, data, 0o644)", source)

    def test_classpath_lwjgl_extracts_only_into_pinned_client_directory(self):
        runtime = (ROOT / "runtime/runtime/src/compatibility.rs").read_text(
            encoding="utf-8"
        )
        source = (ROOT / "runtime/guard-sensor/src/jvm_awareness.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("LWJGL_EXTRACT_PROPERTY", runtime)
        self.assertIn('"-Dorg.lwjgl.system.SharedLibraryExtractPath="', runtime)
        self.assertIn("pin_windows_lwjgl_extract_path(", runtime)
        self.assertIn(
            "args.retain(|arg| !arg.starts_with(LWJGL_EXTRACT_PROPERTY))", runtime
        )
        self.assertIn('join(".launcher").join("lwjgl-extract")', runtime)
        self.assertIn('join("windows").join(std::env::consts::ARCH)', source)
        self.assertIn('extract_root.join("lwjgl.dll")', source)
        self.assertIn(
            "let versioned_candidate = canonical_path.strip_prefix(&extract_root)",
            source,
        )
        self.assertIn(
            "[Component::Normal(version), Component::Normal(platform), Component::Normal(name)]",
            source,
        )
        self.assertIn("version.len() <= 64", source)
        self.assertIn("version.to_string_lossy().bytes().all(", source)
        self.assertIn(
            "platform.to_string_lossy().eq_ignore_ascii_case(classifier_arch)", source
        )
        self.assertIn("if matched == 2 || matched == 3", source)
        self.assertIn("if matched == 2 || matched == 3", source)
        self.assertIn("Sha256::digest(std::fs::read(&canonical_certified)", source)
        self.assertIn("file_sha256.as_slice() != expected_digest.as_slice()", source)
        self.assertIn("extracted LWJGL differs from certified package image", source)
        self.assertIn("LWJGL_REGISTRATION_LOCK.lock()", source)
        self.assertIn("existing.file_sha256 != file_sha256", source)
        self.assertIn("MAX_ADDITIONAL_LWJGL_IMAGES", source)
        self.assertIn(
            "ADDITIONAL_LWJGL_ENDS[index].store(end, Ordering::Release)", source
        )
        self.assertIn("is_verified_lwjgl_caller(address)", source)
        self.assertIn("check_verified_lwjgl_image(native)?;", source)
        self.assertIn("too many verified LWJGL modules", source)
        self.assertIn("rejected reparse/symlink native path", source)
        self.assertIn("outside pinned client root", source)
        self.assertIn("RUNTIME_NATIVE_LOAD_FAILED.store(true", source)
        launch = (ROOT / "runtime/runtime/src/lib.rs").read_text(encoding="utf-8")
        self.assertIn("compatibility::pin_windows_lwjgl_extract_path(", launch)
        self.assertIn('if strategy == "compatibility" || strategy == "mojang"', launch)

    def test_image_integrity_retries_only_partial_reads_with_same_mapping(self):
        memory = (ROOT / "runtime/guard-sensor/src/memory_integrity.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("const ERROR_PARTIAL_COPY: i32 = 299", memory)
        self.assertIn("const IMAGE_READ_RECHECKS: usize = 4", memory)
        self.assertIn("error.raw_os_error() != Some(ERROR_PARTIAL_COPY)", memory)
        self.assertIn("now.allocation_base as usize != region.allocation_base", memory)
        self.assertIn("now.region_size != region.size", memory)
        self.assertIn("now.protect != region.protect", memory)
        self.assertIn("now.state != MEM_COMMIT", memory)
        self.assertIn("now.kind != MEM_IMAGE", memory)
        self.assertIn("if !copied_all", memory)
        self.assertIn("digest.update(&buffer[..chunk])", memory)
        self.assertIn("Guard Memory Integrity code-page drift", memory)

    def test_java21_tooling_retries_setup_but_never_skips_failure(self):
        workflow = (ROOT / ".github/workflows/compatibility.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(workflow.count("id: java21_tooling"), 2)
        self.assertEqual(workflow.count("steps.java21_tooling.outcome == 'failure'"), 2)
        self.assertEqual(
            workflow.count(
                "name: Retry Java 21 tooling after transient extraction failure"
            ),
            2,
        )
        self.assertEqual(workflow.count("distribution: temurin"), 4)
        self.assertNotIn("actions/setup-java@v4", workflow)
        self.assertEqual(
            workflow.count(
                "continue-on-error: true\n        uses: actions/setup-java@v5"
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main()

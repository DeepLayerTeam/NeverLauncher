#!/usr/bin/env python3
"""Platform-neutral source guardrails for Windows native-memory provenance fixes.

These contract tests complement, but cannot replace, Windows/ARM64 integration.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
HOOKS = ROOT / 'runtime/neverguard-sensor/src/hook_engine.rs'
SENSOR = ROOT / 'runtime/neverguard-sensor/src/lib.rs'
RUNTIME = ROOT / 'runtime/neverruntime/src/lib.rs'


class WindowsPostloadProvenanceTests(unittest.TestCase):
    def test_all_four_load_library_hooks_reconcile_after_loading(self):
        source = HOOKS.read_text(encoding='utf-8')
        region = source.split('unsafe extern "system" fn hook_load_library_a(', 1)[1]
        region = region.split('// Track dynamically resolved entry points', 1)[0]
        self.assertEqual(region.count('reconcile_after_library_load(module);'), 4)
        self.assertEqual(region.count('SetLastError(last_error);'), 4)
        self.assertIn('ENGINE_STATE.try_lock()', source)
        self.assertIn('state.healthy = false;', source.split('fn reconcile_after_library_load(', 1)[1].split('fn verify_locked(', 1)[0])

    def test_live_iat_pointer_patches_are_atomic(self):
        source = HOOKS.read_text(encoding='utf-8')
        patch = source.split('fn patch_pointer(', 1)[1].split('fn restore_records(', 1)[0]
        self.assertIn('AtomicUsize::from_ptr', patch)
        self.assertIn('Ordering::Release', patch)
        self.assertNotIn('write_volatile', patch)

    def test_abort_remains_fail_closed_and_explains_windows_fastfail(self):
        source = SENSOR.read_text(encoding='utf-8')
        func = source.split('fn guard_fail_closed_abort()', 1)[1].split('fn module_worker(', 1)[0]
        self.assertIn('std::process::abort()', func)
        self.assertIn('NeverGuard Sensor fail-closed abort', func)
        worker = source.split('fn module_worker(', 1)[1].split('pub extern "system" fn Agent_OnLoad(', 1)[0]
        self.assertGreater(worker.count('guard_fail_closed_abort()'), 20)

    def test_windows_fastfail_needs_authenticated_guard_violation(self):
        source = RUNTIME.read_text(encoding='utf-8')
        block = source.split('if exit_code == Some(0xE3) ||', 1)[1].split('let finished_at = now_unix()?', 1)[0]
        self.assertIn('guard.last_violation.is_empty()', block)
        self.assertIn('0xC000_0409u32 as i32', source)


class WindowsGuardRaceRegressionTests(unittest.TestCase):
    """Source-level contract checks; native semantics require Windows CI."""

    def test_trusted_system_and_jre_dispatchers_validate_exact_loaded_path(self):
        source = (ROOT / 'runtime/neverguard-sensor/src/jvm_awareness.rs').read_text(encoding='utf-8')
        resolver = source.split('fn resolve_system_dispatchers()', 1)[1].split('pub fn capture_transition_provenance()', 1)[0]
        self.assertIn('GetSystemDirectoryW', resolver)
        self.assertIn('GetModuleFileNameW', resolver)
        self.assertIn('loaded_path != expected_path', resolver)
        self.assertIn('GetModuleHandleW', resolver)
        self.assertIn('K32GetModuleInformation', resolver)
        self.assertIn('TRUSTED_SYSTEM_DISPATCHERS', source)
        self.assertIn('caller_module_basename(caller)', source)
        self.assertIn('GetModuleHandleExW(flags, address as *const u16', source)
        self.assertIn('TransitionOrigin::ForeignNative =>', source)
        self.assertIn('FOREIGN_EXECUTABLE_TRANSITIONS.fetch_add(1', source)
        self.assertIn('outside jvm.dll provenance', source)
        self.assertNotIn('DISABLE_JVM_GUARD', source)

    def test_opengl_dispatcher_from_certified_jdk_or_system32(self):
        source = (ROOT / 'runtime/neverguard-sensor/src/jvm_awareness.rs').read_text(encoding='utf-8')
        resolver = source.split('fn resolve_system_dispatchers()', 1)[1].split('pub fn capture_transition_provenance()', 1)[0]
        self.assertIn('"opengl32.dll"', resolver)
        self.assertIn('module_path(jvm_module)?', resolver)
        self.assertIn('runtime_opengl = jvm_bin.join("opengl32.dll")', resolver)
        self.assertIn('std::fs::symlink_metadata(&runtime_opengl)', resolver)
        self.assertIn('metadata.file_type().is_symlink()', resolver)
        self.assertIn('LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32', resolver)
        self.assertIn('LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32)', resolver)
        self.assertIn('loaded_path != expected_path', resolver)
        self.assertIn('K32GetModuleInformation', resolver)
        self.assertIn('TransitionOrigin::ForeignNative =>', source)
        self.assertIn('FOREIGN_EXECUTABLE_TRANSITIONS.fetch_add(1', source)
        self.assertNotIn('DISABLE_JVM_GUARD', source)

    def test_runtime_event_watchdog_remains_bounded_and_fail_closed(self):
        source = (ROOT / 'runtime/neverruntime/src/windows_module_guard.rs').read_text(encoding='utf-8')
        self.assertIn('MODULE_STREAM_TIMEOUT: Duration = Duration::from_secs(15)', source)
        self.assertIn('MODULE_RUNTIME_EVENT_TIMEOUT: Duration = Duration::from_secs(45)', source)
        loop = source.split('async fn monitor_loop(', 1)[1].split('fn hook_digest_from_event(', 1)[0]
        self.assertIn('timeout(MODULE_RUNTIME_EVENT_TIMEOUT, server.read_exact(&mut packet)).await', loop)
        self.assertIn('Module Guard heartbeat timeout', loop)
        self.assertIn('fail_closed(&state, pid, &reason, 0)', loop)
        self.assertIn('parse_event_packet(&packet, secret, pid, expected_sequence)', loop)

    def test_unloads_require_signed_notification_and_bounded_grace(self):
        source = (ROOT / 'runtime/neverruntime/src/windows_module_guard.rs').read_text(encoding='utf-8')
        self.assertIn('UNLOAD_EVENT_GRACE: Duration = Duration::from_secs(4)', source)
        self.assertIn('pending_unload_notifications.remove(&event.base_address)', source)
        self.assertIn('pending_unloads.entry(*base).or_insert_with(Instant::now)', source)
        self.assertIn('if first_missing.elapsed() >= UNLOAD_EVENT_GRACE', source)
        self.assertIn('module base reused before authenticated unload', source)
        self.assertIn('validate_loaded_module(&module.path)', source)
        self.assertIn('Module Guard module path drift', source)

    def test_ack_still_requires_signed_packet_and_bounded_deadline(self):
        source = (ROOT / 'runtime/neverguard-sensor/src/continuous_guard.rs').read_text(encoding='utf-8')
        self.assertIn('GUARD_ACK_TIMEOUT: Duration = Duration::from_secs(12)', source)
        self.assertIn('mac.verify_slice', source)
        self.assertIn('Guard-ACK sequence mismatch', source)
        self.assertIn('Guard-ACK event-chain mismatch', source)
        self.assertIn('Guard-ACK heartbeat timeout', source)

    def test_abort_diagnostics_include_rejected_reason(self):
        source = (ROOT / 'runtime/neverguard-sensor/src/lib.rs').read_text(encoding='utf-8')
        self.assertIn('NeverGuard JVM-Aware violation:', source)
        self.assertIn('NeverGuard Continuous Guard ACK violation:', source)
        self.assertIn('guard_fail_closed_abort();', source)


if __name__ == '__main__':
    unittest.main()

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


if __name__ == '__main__':
    unittest.main()

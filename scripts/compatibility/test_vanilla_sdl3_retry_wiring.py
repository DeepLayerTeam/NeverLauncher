#!/usr/bin/env python3
"""Verify real Vanilla 26.3 certification uses the fail-closed native SDL retry helper."""
from __future__ import annotations

import subprocess
import unittest
import tempfile
import json
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class VanillaSDL3RetryWiringTests(unittest.TestCase):
    def test_vanilla_uses_shared_certification_runner(self):
        script = (ROOT / "e2e/scripts/run-vanilla-certification-case.sh").read_text()
        self.assertIn('certification_run_client "$TARGET_OS" "$NEVERRUNTIME_BIN" "$RUNTIME_DIR/vanilla-certification.json"', script)
        self.assertIn('source "$ROOT/e2e/scripts/lib/certification-platform.sh"', script)

    def test_retry_is_bound_to_real_native_sdl_abort(self):
        script = (ROOT / "e2e/scripts/lib/certification-platform.sh").read_text()
        self.assertIn('"${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}" == "26.3"', script)
        self.assertIn('"${NEVERLAUNCHER_E2E_LOADER:-}" == "vanilla"', script)
        self.assertIn('"${NEVERLAUNCHER_E2E_LOADER:-}" == "fabric"', script)
        self.assertIn('"${NEVERLAUNCHER_E2E_LOADER:-}" == "forge"', script)
        self.assertIn('python3 "$eligibility" --report "$output" --client-root "$client_root"', script)
        self.assertIn('"$runtime_bin" "$@" > "$output"', script)

    def test_both_attempts_uploaded(self):
        flow = (ROOT / ".github/workflows/compatibility.yml").read_text()
        self.assertIn("e2e/runtime/vanilla-certification.first-attempt.json", flow)
        self.assertIn("e2e/runtime/fabric-certification.first-attempt.json", flow)
        self.assertIn("e2e/runtime/forge-certification.first-attempt.json", flow)

    def test_real_vanilla_retry_requires_successful_second_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            scripts = scratch / "scripts/compatibility"
            scripts.mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/compatibility/retry-macos-sdl3.py", scripts / "retry-macos-sdl3.py")
            runtime = scratch / "e2e/runtime"
            logs = runtime / "materialized-client/logs"
            logs.mkdir(parents=True)
            report_path = runtime / "vanilla-certification.json"
            log_path = logs / "vanilla-run.log"
            count = scratch / "count.txt"
            fake = scratch / "fake-client.py"
            fake.write_text("""#!/usr/bin/env python3
import json, pathlib, os
c = pathlib.Path(os.environ['FAKE_COUNT'])
count = int(c.read_text()) if c.exists() else 0
c.write_text(str(count + 1))
log = pathlib.Path(os.environ['FAKE_LOG'])
log.write_text('SDL revision: SDL-3.4.14\\n--- runtime exit --- code=None signal=Some(6)\\n')
if count == 0:
    print(json.dumps({'status':'failed','success':False,'timedOut':False,'exitCode':None,'detectedJavaMajor':25,'logPath':str(log)}))
    raise SystemExit(1)
passed = os.environ.get('FAKE_PASS_SECOND') == 'true'
print(json.dumps({'status':'passed' if passed else 'failed', 'success':passed, 'timedOut':False,'exitCode':0 if passed else 255,'detectedJavaMajor':25,'logPath':str(log)}))
raise SystemExit(0 if passed else 1)
""")
            fake.chmod(0o755)
            for second_succeeds in (True, False):
                count.unlink(missing_ok=True)
                report_path.unlink(missing_ok=True)
                env = dict(os.environ, NEVERLAUNCHER_E2E_LOADER="vanilla", NEVERLAUNCHER_E2E_MINECRAFT_VERSION="26.3",
                           FAKE_COUNT=str(count), FAKE_LOG=str(log_path), FAKE_PASS_SECOND="true" if second_succeeds else "false")
                helper = ROOT / "e2e/scripts/lib/certification-platform.sh"
                run = subprocess.run(["bash", "-c", 'source "$1"; certification_run_client macos "$2" "$3"', "bash", str(helper), str(fake), str(report_path)],
                                     cwd=scratch, env=env, capture_output=True, text=True)
                # Helper finds retry eligibility relative to the source tree;
                # when invoked from a scratch tree, source it there too.
                if "retry-macos-sdl3.py" in run.stderr and "No such file" in run.stderr:
                    self.fail(run.stderr)
                self.assertEqual(count.read_text(), "2", (run.stderr, run.stdout))
                self.assertEqual(run.returncode, 0 if second_succeeds else 1, run.stderr)
                first = runtime / "vanilla-certification.first-attempt.json"
                self.assertTrue(first.exists())
                self.assertEqual(json.loads(first.read_text())["status"], "failed")
                final = json.loads(report_path.read_text())
                self.assertEqual(final["status"], "passed" if second_succeeds else "failed")
                retry = json.loads((runtime / "certification-retry.json").read_text())
                self.assertEqual(retry["lastSuccess"], second_succeeds)

    def test_bash_syntax(self):
        for path in ("e2e/scripts/lib/certification-platform.sh", "e2e/scripts/run-vanilla-certification-case.sh"):
            result = subprocess.run(["bash", "-n", str(ROOT / path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

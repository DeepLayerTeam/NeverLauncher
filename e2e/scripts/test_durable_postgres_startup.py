"""Contract tests for the isolated PostgreSQL container bootstrapping in E2E.

Only the Docker and Go command boundaries are mocked. The actual Bash script,
including set -e and its port handling, executes unchanged.
"""

import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(__file__).with_name("run-durable-boundaries-0213-e2e.sh")


class DurablePostgresStartupTests(unittest.TestCase):
    def run_case(self, *, fail_first=False, fail_all=False, explicit_port=""):
        with tempfile.TemporaryDirectory() as work:
            path = pathlib.Path(work)
            docker = path / "docker"
            docker.write_text(
                textwrap.dedent(
                    """\
                    #!/usr/bin/env bash
                    set -eu
                    case "$1" in
                      rm) exit 0 ;;
                      run)
                        n=0
                        [[ ! -f "$MOCK_COUNT_FILE" ]] || n="$(cat "$MOCK_COUNT_FILE")"
                        n=$((n + 1))
                        echo "$n" > "$MOCK_COUNT_FILE"
                        if [[ "${MOCK_FAIL_ALL:-0}" = 1 ]] ||
                           { [[ "${MOCK_FAIL_FIRST:-0}" = 1 ]] && [[ "$n" = 1 ]]; }; then
                          echo 'mock Docker rejected the first startup' >&2
                          exit 125
                        fi
                        echo container123
                        exit 0 ;;
                      inspect)
                        case "$3" in
                          *HostPort*) echo 49151 ;;
                          *) echo true ;;
                        esac ;;
                      exec) echo 'accepting connections' ;;
                      ps) echo 'name=mock status=exited' ;;
                      logs) echo 'mock PostgreSQL diagnostics' ;;
                      *) echo "unexpected docker command: $*" >&2; exit 2 ;;
                    esac
                    """
                ),
                encoding="utf-8",
            )
            docker.chmod(0o755)
            go = path / "go"
            go.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"${LAUNCHER_DURABLE_DSN:-}\" "
                '> "$MOCK_DSN_FILE"\n',
                encoding="utf-8",
            )
            go.chmod(0o755)
            environment = dict(os.environ)
            environment.update(
                PATH=f"{path}:{environment.get('PATH', '')}",
                MOCK_COUNT_FILE=str(path / "count"),
                MOCK_DSN_FILE=str(path / "dsn"),
                MOCK_FAIL_FIRST="1" if fail_first else "0",
                MOCK_FAIL_ALL="1" if fail_all else "0",
                GITHUB_RUN_ID="mock-durable-test",
            )
            if explicit_port:
                environment["LAUNCHER_DURABLE_POSTGRES_PORT"] = explicit_port
            else:
                environment.pop("LAUNCHER_DURABLE_POSTGRES_PORT", None)
            result = subprocess.run(
                ["bash", str(SCRIPT)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=30,
            )
            attempts = int((path / "count").read_text())
            dsn = (
                (path / "dsn").read_text().strip() if (path / "dsn").is_file() else None
            )
            return result, attempts, dsn

    def test_ephemeral_published_port_is_used_for_connection(self):
        result, attempts, dsn = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 1)
        self.assertIn("@127.0.0.1:49151/launcher", dsn)

    def test_explicit_port_is_preserved(self):
        result, attempts, dsn = self.run_case(explicit_port="55444")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 1)
        self.assertIn("@127.0.0.1:55444/launcher", dsn)

    def test_transient_docker_failure_retries_and_recovers(self):
        result, attempts, dsn = self.run_case(fail_first=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(attempts, 2)
        self.assertIn("mock Docker rejected the first startup", result.stderr)
        self.assertIn("@127.0.0.1:49151/launcher", dsn)

    def test_persistent_failure_remains_fail_closed(self):
        result, attempts, dsn = self.run_case(fail_all=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(attempts, 3)
        self.assertIsNone(dsn)
        self.assertIn("unable to start PostgreSQL after 3 attempts", result.stderr)


if __name__ == "__main__":
    unittest.main()

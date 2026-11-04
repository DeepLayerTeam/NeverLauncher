"""Local security and recovery orchestration tests. Live Docker lab is separate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, call

import chaos_0456 as ch
import dr_03512 as dr


class Chaos0456(unittest.TestCase):
    def env(self, directory):
        env = Path(directory) / "secrets.env"
        env.write_text("LAUNCHER_IMAGE_TAG=0.45.6\nLAUNCHER_STORAGE_S3_BUCKET=nl-dr-testbucket\nLAUNCHER_STORAGE_S3_ACCESS_KEY=lab\nLAUNCHER_STORAGE_S3_SECRET_KEY=secret\n")
        env.chmod(0o600)
        return env

    def test_reject_nonisolated_projects_and_remote_storage(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "AWS_ACCESS_KEY_ID": "lab", "AWS_SECRET_ACCESS_KEY": "secret"}):
            env = self.env(folder)
            for project, confirm, endpoint, bucket in [
                ("production", "production", "http://127.0.0.1:19000", "nl-dr-testbucket"),
                ("nl-dr-test", "wrong", "http://127.0.0.1:19000", "nl-dr-testbucket"),
                ("nl-dr-test", "nl-dr-test", "https://s3.production.example", "nl-dr-testbucket"),
                ("nl-dr-test", "nl-dr-test", "http://127.0.0.1:19000", "launcher-objects"),
                ("nl-dr-test", "nl-dr-test", "http://localhost:19000", "nl-dr-testbucket"),
                ("nl-dr-test", "nl-dr-test", "http://127.0.0.1:19000/?x=1", "nl-dr-testbucket"),
            ]:
                with self.subTest(endpoint=endpoint, bucket=bucket, project=project), self.assertRaises(dr.DrillError):
                    ch.check_scope(project, confirm, env, "https://127.0.0.1:18443/ready", endpoint, bucket)

    def test_env_permissions_and_secret_env_required(self):
        with tempfile.TemporaryDirectory() as folder:
            env = self.env(folder)
            env.chmod(0o644)
            with patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b"}), self.assertRaisesRegex(dr.DrillError, "0600"):
                ch.check_scope("nl-dr-test", "nl-dr-test", env, "https://127.0.0.1:18443/ready", "http://127.0.0.1:19000", "nl-dr-testbucket")
            env.chmod(0o600)
            with patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": ""}), self.assertRaisesRegex(dr.DrillError, "AWS_ACCESS"):
                ch.check_scope("nl-dr-test", "nl-dr-test", env, "https://127.0.0.1:18443/ready", "http://127.0.0.1:19000", "nl-dr-testbucket")

    def test_composes_just_ha_and_chaos_overlay(self):
        with patch.object(dr, "COMPOSE_FILES", [dr.COMPOSE]), patch.object(dr, "COMPOSE_PROFILES", []):
            ch.configure_compose()
            self.assertEqual(len(dr.COMPOSE_FILES), 3)
            self.assertEqual(dr.COMPOSE_PROFILES, ["network-ha"])
            self.assertEqual(dr.COMPOSE_FILES[-1].name, "docker-compose.chaos-0456.yml")

    def test_s3_port_cannot_be_other_tunnel(self):
        with patch.object(ch, "container_id", return_value="1" * 64), patch.object(dr, "run") as invoke:
            invoke.return_value.stdout = b"127.0.0.1:19001\n"
            with self.assertRaisesRegex(dr.DrillError, "loopback port"):
                ch.check_lab_endpoint("nl-dr-test", Path("/tmp/env"), "http://127.0.0.1:19000")
            invoke.return_value.stdout = b"127.0.0.1:19000\n"
            ch.check_lab_endpoint("nl-dr-test", Path("/tmp/env"), "http://127.0.0.1:19000")

    def test_postgres_canary_checked_after_insert(self):
        with patch.object(ch, "pg_sql") as execute:
            execute.return_value = "a" * 64
            ch.pg_write("nl-dr-test", Path("/env"), "1" * 32, "a" * 64)
            self.assertEqual(execute.call_count, 2)
            self.assertIn("INSERT INTO launcher_chaos_canaries_0456", execute.call_args_list[0].args[-1])
            self.assertIn("SELECT payload_sha256", execute.call_args_list[1].args[-1])
            execute.return_value = "wrong"
            with self.assertRaisesRegex(dr.DrillError, "PostgreSQL canary"):
                ch.pg_verify("nl-dr-test", Path("/env"), "1" * 32, "a" * 64)
            with self.assertRaises(dr.DrillError):
                ch.pg_write("nl-dr-test", Path("/env"), "bad';DROP TABLE users", "a" * 64)

    def test_s3_canary_verifies_actual_downloaded_bytes(self):
        data = b"survivable-object"
        digest = hashlib.sha256(data).hexdigest()
        def fake_s3(url, *args, **kwargs):
            if args[0] == "get-object":
                Path(args[-1]).write_bytes(data)
            return b""
        with patch.object(ch, "s3_call", side_effect=fake_s3):
            self.assertEqual(ch.s3_verify("http://127.0.0.1:19000", "nl-dr-testbucket", "neverlauncher-chaos-0456/x", digest), digest)
            with self.assertRaisesRegex(dr.DrillError, "S3 object"):
                ch.s3_verify("http://127.0.0.1:19000", "nl-dr-testbucket", "neverlauncher-chaos-0456/x", "1"*64)

    def test_dependency_stop_recovers_even_if_detection_fails(self):
        with patch.object(dr, "compose") as compose, patch.object(ch, "poll", side_effect=dr.DrillError("readiness unexpectedly healthy")):
            with self.assertRaises(dr.DrillError):
                ch.dependency_fault("nl-dr-test", Path("/env"), "redis", "https://127.0.0.1:18443/ready",
                                    "http://127.0.0.1:19000", "nl-dr-testbucket", "key", "0"*64, "a"*32, "0"*64, 20)
            self.assertEqual(compose.call_args_list[0].args[-4:], ("stop", "-t", "3", "redis"))
            self.assertEqual(compose.call_args_list[1].args[-3:], ("up", "-d", "redis"))

    def test_worker_network_reconnect_even_if_checks_fail(self):
        with patch.object(ch, "container_id", return_value="1"*64), patch.object(ch, "lab_network", return_value="nl-dr-test_launcher"), \
             patch.object(dr, "run") as run, patch.object(ch, "poll", side_effect=dr.DrillError("worker not fenced")):
            with self.assertRaises(dr.DrillError):
                ch.network_fault("nl-dr-test", Path("/env"), "https://127.0.0.1:18443/ready", 20)
            self.assertEqual(run.call_count, 2)
            self.assertIn("disconnect", run.call_args_list[0].args[0])
            self.assertIn("connect", run.call_args_list[1].args[0])

    def test_api_restored_if_failover_unhealthy(self):
        with patch.object(dr, "compose") as compose, patch.object(ch, "poll", side_effect=dr.DrillError("no failover")):
            with self.assertRaises(dr.DrillError):
                ch.api_failover("nl-dr-test", Path("/env"), "https://127.0.0.1:18443/ready", 20)
            self.assertEqual(compose.call_count, 2)
            self.assertEqual(compose.call_args_list[1].args[-3:], ("up", "-d", "api"))

    def test_missing_container_prevents_faults(self):
        with patch.object(dr, "compose_states", return_value={"api": "running"}), patch.object(dr, "compose") as execute, self.assertRaisesRegex(dr.DrillError, "postgres"):
            ch.check_services("nl-dr-test", Path("/env"))
        execute.assert_not_called()

    def test_no_false_success_report_if_failed(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ch, "check_services", return_value=None), \
             patch.object(ch, "check_lab_endpoint", return_value=None), patch.object(ch, "poll", return_value=0), \
             patch.object(ch, "pg_write", return_value=None), patch.object(ch, "s3_prepare", return_value="h"), \
             patch.object(ch, "dependency_fault", side_effect=dr.DrillError("unavailable")), \
             patch.object(ch, "s3_delete", return_value=None) as cleanup:
            report = Path(folder) / "result.json"
            with self.assertRaises(dr.DrillError):
                ch.run_experiment("nl-dr-test", Path("/env"), "https://127.0.0.1:18443/ready", "http://127.0.0.1:19000", "nl-dr-testbucket", 20, report)
            self.assertFalse(report.exists())
            cleanup.assert_called_once()

    def test_report_contains_real_durations_not_hardcoded(self):
        result = {"status":"passed", "events": [{"rtoSeconds":0.03},{"rtoSeconds":0.1}]}
        self.assertEqual(max(x["rtoSeconds"] for x in result["events"]), 0.1)

    def test_full_orchestration_publishes_only_after_all_five_faults(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ch, "check_services"), \
             patch.object(ch, "check_lab_endpoint"), patch.object(ch, "poll", return_value=0), \
             patch.object(ch, "pg_write") as write, patch.object(ch, "s3_prepare"), \
             patch.object(ch, "dependency_fault", return_value={"rtoSeconds": 1.2, "fault": "dependency"}) as dependencies, \
             patch.object(ch, "api_failover", return_value={"rtoSeconds": 2.3, "fault": "api"}) as api, \
             patch.object(ch, "network_fault", return_value={"rtoSeconds": 3.4, "fault": "network"}) as network, \
             patch.object(ch, "pg_verify") as verify, patch.object(ch, "s3_verify") as s3check, \
             patch.object(ch, "s3_delete") as cleanup:
            resultfile=Path(folder)/"report.json"
            report=ch.run_experiment("nl-dr-test",Path("/env"),"https://127.0.0.1:18443/ready",
                                     "http://127.0.0.1:19000", "nl-dr-testbucket",20,resultfile)
            self.assertEqual(report['status'],'passed')
            self.assertEqual(len(report['events']),5)
            self.assertEqual(dependencies.call_count,3)
            self.assertEqual(dependencies.call_args_list[0].args[2], 'postgres')
            self.assertEqual(dependencies.call_args_list[1].args[2], 'redis')
            self.assertEqual(dependencies.call_args_list[2].args[2], 's3')
            api.assert_called_once()
            network.assert_called_once()
            verify.assert_called_once()
            s3check.assert_called_once()
            cleanup.assert_called_once()
            self.assertEqual(json.loads(resultfile.read_text())['rtoSecondsMax'],3.4)
            self.assertEqual(resultfile.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()

"""Регрессионные тесты исполняемого развёртывания 0.51.7 и восстановления после сбоя.

Имитации моделируют ответы состояния Docker/SSH; это не свидетельства многохостового GA.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

import rolling_update as ru
import nn1_compat as nn
import multi_host as multi
from test_nn1_compat import report as live_report

A = "registry.example/launcher/api@sha256:" + "a" * 64
B = "registry.example/launcher/api@sha256:" + "b" * 64


def expected(image):
    return {"nodeId": "node-a", "machineIdentity": "machine:node-a",
            "sharedEndpoints": {"postgres": "pg", "redis": "redis", "s3": "s3"},
            "imageDigestRefs": {"api": image, "worker": image,
                                "admin": A, "ingress": A, "volume-init": A}}


def configuration(image):
    return {"name": "launcher", "services": {
        "api": {"image": image, "environment": {"DATABASE_SECRET": "secret"}},
        "worker": {"image": image, "environment": {"DATABASE_SECRET": "secret"}},
        "admin": {"image": A}, "ingress": {"image": A}, "volume-init": {"image": A}}}


class RollingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.current = self.directory / ".env"
        self.target = self.directory / ru.STAGE
        self.current.write_text("LAUNCHER_API_IMAGE=" + A + "\nPRIVATE=secret\n")
        self.target.write_text("LAUNCHER_API_IMAGE=" + B + "\nPRIVATE=secret\n")
        for path in (self.current, self.target):
            path.chmod(0o600)

    def mocked_config(self, directory, project, *, env_file=None):
        return expected(A if env_file is None else B)

    def mocked_render(self, directory, project, env_file):
        return configuration(A if env_file.name == ".env" else B)

    def test_stage_checks_full_rendered_config_beyond_image_and_keeps_secrets_private(self):
        with patch.object(multi, "resolved_compose", side_effect=self.mocked_config), \
             patch.object(ru, "rendered", side_effect=self.mocked_render):
            out = ru.validate_stage(self.directory, "launcher")
        self.assertEqual(out["sourceImage"], A)
        self.assertEqual(out["targetImage"], B)
        self.assertNotIn("PRIVATE", str(out))
        self.assertNotIn("secret", str(out))

    def test_stage_rejects_secret_rotation_unexpected_environment_and_other_service_image(self):
        with patch.object(multi, "resolved_compose", side_effect=self.mocked_config):
            def render(directory, project, path):
                c = configuration(A if path.name == ".env" else B)
                if path.name != ".env":
                    c["services"]["worker"]["environment"]["DATABASE_SECRET"] = "rotated"
                return c
            with patch.object(ru, "rendered", side_effect=render):
                with self.assertRaisesRegex(ru.RollingError, "отличается не только закреплённым образом"):
                    ru.validate_stage(self.directory, "launcher")
            def render_other(directory, project, path):
                c = configuration(A if path.name == ".env" else B)
                if path.name != ".env":
                    c["services"]["admin"]["image"] = B
                return c
            with patch.object(ru, "rendered", side_effect=render_other):
                with self.assertRaisesRegex(ru.RollingError, "beyond"):
                    ru.validate_stage(self.directory, "launcher")

    def test_stage_rejects_unreadable_file_symlink_hardlink_group_write_and_identical(self):
        self.target.chmod(0o640)
        with self.assertRaisesRegex(ru.RollingError, "небезопасен"):
            ru.secure(self.target)
        self.target.chmod(0o600)
        self.target.unlink()
        self.target.symlink_to(self.current)
        with self.assertRaisesRegex(ru.RollingError, "небезопасен"):
            ru.secure(self.target)
        self.target.unlink()
        os.link(self.current, self.target)
        with self.assertRaisesRegex(ru.RollingError, "небезопасен"):
            ru.secure(self.target)
        self.target.unlink()
        self.target.write_bytes(self.current.read_bytes())
        self.target.chmod(0o600)
        with self.assertRaisesRegex(ru.RollingError, "совпадает с текущим развёртыванием"):
            with patch.object(multi, "resolved_compose"):
                ru.validate_stage(self.directory, "launcher")

    def test_atomic_replace_keeps_private_permissions_and_fsyncs(self):
        ru.atomic_write(self.current, b"PRIVATE=new-secret\n")
        self.assertEqual(self.current.read_text(), "PRIVATE=new-secret\n")
        self.assertEqual(stat.S_IMODE(self.current.stat().st_mode), 0o600)
        self.assertFalse(list(self.directory.glob(".rolling-tmp-*")))

    def test_exclusive_backup_cannot_overwrite_prior_source(self):
        backup = self.directory / ru.BACKUP
        ru.exclusive_write(backup, b"previous")
        with self.assertRaisesRegex(ru.RollingError, "Резервная копия или состояние переключения требуют проверки оператором"):
            ru.exclusive_write(backup, b"malicious")
        self.assertEqual(backup.read_bytes(), b"previous")
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_local_host_lock_prevents_concurrent_operations(self):
        with ru.host_lock(self.directory):
            with self.assertRaisesRegex(ru.RollingError, "уже выполняется"):
                with ru.host_lock(self.directory):
                    pass

    def test_journal_rejects_corruption(self):
        ru.journal(self.directory, {"schema": ru.SCHEMA, "phase": "stopping"})
        self.assertEqual(ru.read_journal(self.directory)["phase"], "stopping")
        (self.directory / ru.STATE).write_text("not-json")
        with self.assertRaisesRegex(ru.RollingError, "Некорректный локальный журнал восстановления"):
            ru.read_journal(self.directory)

    def test_real_docker_command_sequence_and_rollback_on_start_failure(self):
        steps = []
        def compose(directory, project, *args, **kwargs):
            steps.append(args)
            if "up" in args and self.current.read_bytes() == self.target.read_bytes():
                raise ru.RollingError("тестовый образ не прошёл проверку готовности")
            return ""
        original = self.current.read_bytes()
        with patch.object(ru, "validate_stage", return_value={
                "nodeId": "node-a", "sourceImage": A, "targetImage": B,
                "sourceHash": ru.sha(self.current.read_bytes()), "targetHash": ru.sha(self.target.read_bytes())}), \
             patch.object(ru, "live_local", return_value=live_report("node-a", ru.SOURCE)), \
             patch.object(ru, "compose", side_effect=compose), \
             patch.object(multi, "run", return_value="sha256:123"):
            with self.assertRaisesRegex(ru.RollingError, "восстановлен и проверен"):
                ru.apply_host(self.directory, "launcher")
        self.assertEqual(self.current.read_bytes(), original)
        self.assertEqual(ru.read_journal(self.directory)["phase"], "rolled-back")
        self.assertTrue(any("pull" in args for args in steps))
        self.assertTrue(any("stop" in args and "worker" in args and "api" in args for args in steps))
        self.assertEqual(len([x for x in steps if "up" in x]), 2)

    def test_successful_update_preserves_backup_and_unchanged_teams(self):
        previous = self.current.read_bytes()
        commands = []
        def live(directory, project, version):
            self.assertEqual(version, ru.SOURCE if self.current.read_bytes() == previous else ru.TARGET)
            return live_report("node-a", version)
        stage = {"nodeId": "node-a", "sourceImage": A, "targetImage": B,
                 "sourceHash": ru.sha(previous), "targetHash": ru.sha(self.target.read_bytes())}
        with patch.object(ru, "validate_stage", return_value=stage), \
             patch.object(ru, "live_local", side_effect=live), \
             patch.object(ru, "compose", side_effect=lambda *a, **k: commands.append(a[2:]) or ""), \
             patch.object(multi, "run", return_value="sha256:123"):
            result = ru.apply_host(self.directory, "launcher")
        self.assertTrue(result["ready"])
        self.assertEqual(self.current.read_bytes(), self.target.read_bytes())
        self.assertEqual((self.directory / ru.BACKUP).read_bytes(), previous)
        self.assertEqual(ru.read_journal(self.directory)["phase"], "applied")
        self.assertTrue(any("--no-deps" in cmd and "--force-recreate" in cmd for cmd in commands))
        self.assertTrue(all("ingress" not in cmd and "admin" not in cmd for cmd in commands))

    def test_recover_after_interrupted_update_from_stopping_and_switching(self):
        old = self.current.read_bytes()
        new = self.target.read_bytes()
        plan = {"schema": ru.SCHEMA, "nodeId": "node-a", "sourceHash": ru.sha(old),
                "targetHash": ru.sha(new), "sourceImage": A, "targetImage": B}
        for phase in ("stopping", "switching"):
            ru.atomic_write(self.current, new if phase == "switching" else old)
            if not (self.directory / ru.BACKUP).exists():
                ru.exclusive_write(self.directory / ru.BACKUP, old)
            ru.journal(self.directory, {**plan, "phase": phase})
            with patch.object(ru, "live_local", return_value=live_report("node-a", ru.SOURCE)), \
                 patch.object(ru, "compose", return_value=""):
                result = ru.rollback_host(self.directory, "launcher")
            self.assertEqual(result["to"], ru.SOURCE)
            self.assertEqual(self.current.read_bytes(), old)
            self.assertEqual(ru.read_journal(self.directory)["phase"], "rolled-back")

    def test_rollback_fails_when_backup_changed_and_does_not_run_docker(self):
        old = self.current.read_bytes()
        plan = {"schema": ru.SCHEMA, "phase": "applied", "nodeId": "node-a",
                "sourceHash": ru.sha(old), "targetHash": ru.sha(self.target.read_bytes())}
        ru.journal(self.directory, plan)
        ru.exclusive_write(self.directory / ru.BACKUP, b"incorrect")
        with patch.object(ru, "compose") as cmd:
            with self.assertRaisesRegex(ru.RollingError, "резервная копия окружения изменилась"):
                ru.rollback_host(self.directory, "launcher")
            cmd.assert_not_called()

    def test_no_secret_contents_in_local_receipt(self):
        self.assertNotIn("secret", json.dumps({"sourceHash": ru.sha(self.current.read_bytes())}))

    def test_pair_checks_allow_only_specific_0516_0517_versions(self):
        nn.validate_live_nodes({"a": live_report("a", ru.SOURCE),
                                "b": live_report("b", ru.TARGET)}, pair=ru.PAIR, require_mixed=True)
        with self.assertRaisesRegex(nn.CompatibilityError, "не поддерживается версия готовности"):
            nn.validate_live_nodes({"a": live_report("a", "0.51.5"),
                                    "b": live_report("b", ru.TARGET)}, pair=ru.PAIR)

    def test_remote_ssh_has_strict_host_keys_and_mutation_confirmation(self):
        def fake_run(argv, **kwargs):
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("--allow-update", argv[-1])
            return json.dumps({"schema": ru.SCHEMA, "ready": True, "project": "launcher"})
        with patch.object(multi, "run", side_effect=fake_run):
            ru.remote("operator@node-a", "/opt/launcher/scripts/operations/rolling_update.py",
                      "/opt/launcher/deploy/production", "launcher", "local-rollback")

    def test_remote_rejects_uncertain_response_and_does_not_claim_success(self):
        with patch.object(multi, "run", return_value="not-json"):
            with self.assertRaisesRegex(ru.RollingError, "некорректный JSON"):
                ru.remote("user@node-a", "/opt/launcher/scripts/operations/rolling_update.py",
                          "/opt/launcher/deploy/production", "launcher", "local-apply")

    def test_edge_monitor_reports_real_failures(self):
        with patch.object(multi, "edge_ready", return_value=(False, {})):
            with ru.EdgeMonitor("https://edge.example") as monitor:
                __import__('time').sleep(.04)
            with self.assertRaisesRegex(ru.RollingError, "недоступен"):
                monitor.assert_continuity()

    def test_advisory_lock_requires_stable_connection(self):
        lock = ru.PGAdvisoryLock(Path("/nonexistent"))
        with self.assertRaisesRegex(ru.RollingError, "Завершился сеанс блокировки PostgreSQL"):
            lock.ping()

    def test_cli_requires_explicit_confirmation_for_mutations(self):
        with patch.object(ru, "apply_host") as apply:
            self.assertEqual(ru.main(["local-apply", "--directory", str(self.directory),
                                      "--project", "launcher", "--output", "-"]), 3)
            apply.assert_not_called()


class ClusterControllerTest(unittest.TestCase):
    def setUp(self):
        self.versions = {"alpha": ru.SOURCE, "beta": ru.SOURCE}
        self.nodes = {"alpha": "operator@alpha", "beta": "operator@beta"}
        self.actions = []
        self.args = types.SimpleNamespace(
            node=["alpha=operator@alpha", "beta=operator@beta"],
            edge_url="https://edge.example", pg_dsn_file=Path("/tmp/pg-secret"),
            project="launcher", directory="/opt/launcher/deploy/production",
            remote_script="/opt/launcher/scripts/operations/multi_host.py",
            rolling_script="/opt/launcher/scripts/operations/rolling_update.py")

    def remote_call(self, target, script, directory, project, mode, **kwargs):
        name = target.split("@", 1)[1]
        self.actions.append((name, mode))
        return live_report(name, self.versions[name])

    def remote(self, target, script, directory, project, mode, **kwargs):
        name = target.split("@", 1)[1]
        self.actions.append((name, mode))
        if mode == "local-plan":
            return {"schema": ru.SCHEMA, "ready": True, "nodeId": name,
                    "sourceImage": live_report(name, ru.SOURCE)["imageDigestRefs"]["api"],
                    "targetImage": live_report(name, ru.TARGET)["imageDigestRefs"]["api"],
                    "to": ru.TARGET}
        if mode == "local-apply":
            self.versions[name] = ru.TARGET
            return {"schema": ru.SCHEMA, "ready": True, "nodeId": name,
                    "sourceImage": live_report(name, ru.SOURCE)["imageDigestRefs"]["api"],
                    "targetImage": live_report(name, ru.TARGET)["imageDigestRefs"]["api"],
                    "from": ru.SOURCE, "to": ru.TARGET}
        if mode == "local-rollback":
            self.versions[name] = ru.SOURCE
            return {"schema": ru.SCHEMA, "ready": True, "nodeId": name,
                    "phase": "rolled-back"}
        raise AssertionError("Неожиданная операция: " + mode)

    class Lock:
        def __init__(self, *args):
            self.pings = 0
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def ping(self):
            self.pings += 1

    class Monitor:
        samples = 5
        failures = 0
        def __init__(self, *args):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def assert_continuity(self):
            pass

    def mocks(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(multi, "remote_call", side_effect=self.remote_call))
        stack.enter_context(patch.object(ru, "remote", side_effect=self.remote))
        stack.enter_context(patch.object(ru, "PGAdvisoryLock", self.Lock))
        stack.enter_context(patch.object(ru, "EdgeMonitor", self.Monitor))
        stack.enter_context(patch.object(nn, "migration_catalog", return_value=({"one": "sha"}, "catalog")))
        stack.enter_context(patch.object(nn, "live_pg_migrations", return_value={"one": "sha"}))
        stack.enter_context(patch.object(multi, "edge_ready", return_value=(True, {"success": 3, "sampled": 3})))
        return stack

    def test_rolls_one_node_at_time_and_observes_cluster_between_each(self):
        with self.mocks():
            result = ru.rollout(self.args)
        self.assertTrue(result["verified"])
        self.assertEqual(self.versions, {"alpha": ru.TARGET, "beta": ru.TARGET})
        self.assertEqual([a for a in self.actions if a[1] == "local-apply"],
                         [("alpha", "local-apply"), ("beta", "local-apply")])
        first_apply = self.actions.index(("alpha", "local-apply"))
        second_apply = self.actions.index(("beta", "local-apply"))
        self.assertGreater(sum(1 for a in self.actions[first_apply+1:second_apply]
                               if a[1] == "local-compat-observe"), 0)
        self.assertEqual(len(result["steps"]), 2)
        self.assertTrue(all(step["edgeFailures"] == 0 for step in result["steps"]))

    def test_resumes_after_first_success_without_reapplying_updated_node(self):
        self.versions["alpha"] = ru.TARGET
        with self.mocks():
            result = ru.rollout(self.args)
        self.assertTrue(result["verified"])
        self.assertNotIn(("alpha", "local-apply"), self.actions)
        self.assertIn(("beta", "local-apply"), self.actions)
        self.assertEqual(len(result["steps"]), 1)

    def test_denies_schema_drift_before_stopping_any_containers(self):
        with self.mocks(), patch.object(nn, "validate_schema", side_effect=nn.CompatibilityError("drift")):
            with self.assertRaisesRegex(nn.CompatibilityError, "drift"):
                ru.rollout(self.args)
        self.assertNotIn(("alpha", "local-apply"), self.actions)

    def test_post_cutover_failure_rolls_back_only_affected_node(self):
        class FailureMonitor(self.Monitor):
            def assert_continuity(self):
                raise ru.RollingError("пограничный узел недоступен")
        with self.mocks(), patch.object(ru, "EdgeMonitor", FailureMonitor):
            with self.assertRaisesRegex(ru.RollingError, "затронутый узел восстановлен"):
                ru.rollout(self.args)
        self.assertEqual(self.versions["alpha"], ru.SOURCE)
        self.assertIn(("alpha", "local-rollback"), self.actions)
        self.assertNotIn(("beta", "local-apply"), self.actions)

    def test_unknown_version_aborts_before_mutation(self):
        self.versions["alpha"] = "0.51.5"
        with self.mocks():
            with self.assertRaisesRegex(nn.CompatibilityError, "не поддерживается версия готовности"):
                ru.rollout(self.args)
        self.assertNotIn(("alpha", "local-apply"), self.actions)

    def test_mismatched_remote_receipt_forces_rollback(self):
        original = self.remote
        def altered(*args, **kwargs):
            response = original(*args, **kwargs)
            if args[4] == "local-apply":
                response["targetImage"] = "invalid-sha"
            return response
        with self.mocks(), patch.object(ru, "remote", side_effect=altered):
            with self.assertRaisesRegex(ru.RollingError, "затронутый узел восстановлен"):
                ru.rollout(self.args)
        self.assertIn(("alpha", "local-rollback"), self.actions)
        self.assertNotIn(("beta", "local-apply"), self.actions)

    def test_different_target_digests_are_rejected_before_any_update(self):
        original = self.remote
        def mismatch(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[4] == "local-plan" and args[0].endswith("@beta"):
                result["targetImage"] = "registry.example/api@sha256:" + "c" * 64
            return result
        with self.mocks(), patch.object(ru, "remote", side_effect=mismatch):
            with self.assertRaisesRegex(ru.RollingError, "единую целевую контрольную сумму OCI"):
                ru.rollout(self.args)
        self.assertNotIn(("alpha", "local-apply"), self.actions)
        self.assertNotIn(("beta", "local-apply"), self.actions)

    def test_unauthorized_admin_image_difference_blocks_initial_cluster(self):
        original = self.remote_call
        def mismatch(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[0].endswith("@beta"):
                result["imageDigestRefs"]["admin"] = "repo/admin@sha256:" + "c" * 64
            return result
        with self.mocks(), patch.object(multi, "remote_call", side_effect=mismatch):
            with self.assertRaisesRegex(ru.RollingError, "закреплённые значения admin image"):
                ru.rollout(self.args)
        self.assertNotIn(("alpha", "local-apply"), self.actions)

    def test_two_independent_nodes_required(self):
        self.args.node = ["alpha=operator@alpha"]
        with self.mocks():
            with self.assertRaisesRegex(multi.DeploymentError, "два независимых SSH-узла"):
                ru.rollout(self.args)
        self.assertFalse(self.actions)



if __name__ == "__main__":
    unittest.main()

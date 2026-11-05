"""Регрессионные тесты исполнителя развёртывания 0.51.2. Не выдавать их за подтверждение реального HA."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import multi_host_0512 as mh

DIGEST = "@sha256:" + "a" * 64

def fixture(name="node-a"):
    env = {
        "LAUNCHER_DEPLOYMENT_MODE": "network-ha", "LAUNCHER_REPOSITORY_DRIVER": "postgres",
        "LAUNCHER_SQL_DRIVER": "pgx", "LAUNCHER_PROCESS_ROLE": "api",
        "LAUNCHER_DATABASE_AUTO_MIGRATE": "false", "LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH": "",
        "LAUNCHER_SERVERBRIDGE_HA_REQUIRED": "true", "LAUNCHER_RATE_LIMIT_ENABLED": "true",
        "LAUNCHER_RATE_LIMIT_FAIL_CLOSED": "true", "LAUNCHER_STORAGE_DRIVER": "s3",
        "LAUNCHER_DATABASE_DSN": "postgres://user:secret@pg.internal:5432/launcher?sslmode=verify-full",
        "LAUNCHER_REDIS_URL": "rediss://:secret@redis.internal:6379/0",
        "LAUNCHER_STORAGE_S3_ENDPOINT": "https://s3.internal",
        "LAUNCHER_STORAGE_S3_BUCKET": "launcher", "LAUNCHER_STORAGE_S3_REGION": "eu-west-1",
        "LAUNCHER_PUBLIC_URL": "https://launcher.example", "LAUNCHER_REPLICA_ID": name + "-api",
    }
    worker = {**env, "LAUNCHER_PROCESS_ROLE": "worker", "LAUNCHER_REPLICA_ID": name + "-worker"}
    return {
        "services": {
            "api": {"image": "registry/launcher-api"+DIGEST, "environment": env, "healthcheck": {"test": ["CMD", "wget"]}},
            "worker": {"image": "registry/launcher-api"+DIGEST, "environment": worker, "healthcheck": {"test": ["CMD", "wget"]}},
            "admin": {"image": "registry/launcher-admin"+DIGEST},
            "ingress": {"image": "registry/nginx"+DIGEST,
                        "ports": [{"host_ip": "10.0.0.10", "target": 443, "published": "443", "protocol": "tcp"}],
                        "volumes": [{"target": "/etc/launcher/tls/fullchain.pem", "source": "/tmp/multi-host-test-cert", "type": "bind", "read_only": True},
                                    {"target": "/etc/launcher/tls/privkey.pem", "source": "/tmp/multi-host-test-key", "type": "bind", "read_only": True}]},
            "volume-init": {"image": "registry/alpine"+DIGEST},
        }
    }


def tmp_config():
    d = tempfile.TemporaryDirectory()
    directory = Path(d.name)
    (directory / ".env").write_text("PRIVATE_KEY=never-share\n")
    (directory / ".env").chmod(0o600)
    (directory / "docker-compose.multi-host.yml").write_text("services: {}\n")
    (directory / "nginx.multi-host-0512.conf").write_text("server {}\n")
    return d, directory


def node_report(node_id, machine_id):
    return {"schema": mh.SCHEMA, "version": mh.VERSION, "project": "launcher",
            "nodeId": node_id, "machineIdentity": machine_id, "configurationValidated": True,
            "imageDigestRefs": {name: item["image"] for name, item in fixture()["services"].items()},
            "sharedEndpoints": {"postgres": "pg.internal", "redis": "redis.internal",
                                "s3": "s3.internal", "bucket": "launcher", "public": "launcher.example"},
            "ready": True,
            "live": {"dockerEngineIdentity": "engine:"+machine_id,
                     "containers": [{"service": s, "running": True} for s in mh.SERVICES]}}


class MultiHostExecutorTest(unittest.TestCase):
    def test_production_compose_is_independent_and_uses_distinct_worker_volumes(self):
        # Проверяйте фактическую структуру исходного YAML; дополнительные зависимости
        # промышленной среде не нужны (Compose сам разбирает YAML).
        import yaml
        root = Path(__file__).resolve().parents[2]
        data = yaml.safe_load((root / "deploy/production/docker-compose.multi-host.yml").read_text())
        self.assertEqual(set(data["services"]), set(mh.ALL_SERVICES))
        self.assertNotIn("postgres", data["services"])
        self.assertNotIn("redis", data["services"])
        self.assertEqual(data["services"]["api"]["environment"]["LAUNCHER_PROCESS_ROLE"], "api")
        self.assertEqual(data["services"]["worker"]["environment"]["LAUNCHER_PROCESS_ROLE"], "worker")
        self.assertNotEqual(data["services"]["api"]["volumes"], data["services"]["worker"]["volumes"])
        init_volumes = data["services"]["volume-init"]["volumes"]
        self.assertEqual(len(init_volumes), 10)
        self.assertNotIn("ports", data["services"]["api"])
        self.assertNotIn("ports", data["services"]["worker"])

    def test_baseline_inventory_understands_new_worker_and_ingress_services(self):
        import ha_inventory_0511 as ha
        def item(service, replica):
            return {"service": service, "containerId": service+replica,
                    "environment": {"LAUNCHER_REPLICA_ID": replica},
                    "health": "healthy", "running": True,
                    "readiness": {"success": 3, "sampled": 3, "failures": 0}}
        nodes = {}
        for label in ("a", "b"):
            nodes[label] = {"nodeIdentity": "machine:"+label,
                            "observations": [], "sourceState": {"observed": False},
                            "containers": [item("api", label+"-api"), item("worker", label+"-worker"),
                                           item("ingress", ""), item("admin", "")]}
        result = ha.assess_cluster(nodes)
        checks = {i["component"]: i["status"] for i in result["spof"]}
        self.assertEqual(checks["api"], "OBSERVED")
        self.assertEqual(checks["worker"], "OBSERVED")
        self.assertEqual(checks["ingress"], "OBSERVED")
        self.assertEqual(checks["replica_roles_and_identity"], "OBSERVED")
        self.assertFalse(result["multiHostFailoverCertified"])

    def test_live_configuration_runs_real_compose_config_and_checks_TLS_pin_and_unique_id(self):
        temp, directory = tmp_config()
        self.addCleanup(temp.cleanup)
        raw = fixture()
        with patch.object(mh, "run", return_value=json.dumps(raw)) as execute, \
             patch.object(mh.inventory, "machine_identity", return_value="machine:abc"), \
             patch.object(mh, "check_secure_file", return_value=None):
            observed = mh.resolved_compose(directory, "launcher")
        self.assertEqual(observed["nodeId"], "node-a")
        self.assertEqual(observed["sharedEndpoints"]["postgres"], "pg.internal")
        self.assertEqual(observed["imageDigestRefs"]["api"], raw["services"]["api"]["image"])
        self.assertIn("config", execute.call_args.args[0])
        self.assertNotIn("PRIVATE_KEY", json.dumps(observed))

    def test_reject_single_node_dependencies_and_insecure_transport(self):
        temp, directory = tmp_config()
        self.addCleanup(temp.cleanup)
        changes = (
            ("api", "LAUNCHER_DATABASE_DSN", "postgres://u:p@localhost/db?sslmode=verify-full"),
            ("api", "LAUNCHER_DATABASE_DSN", "postgres://u:p@pg.internal/db?sslmode=disable"),
            ("api", "LAUNCHER_REDIS_URL", "redis://u:p@redis.internal:6379"),
            ("api", "LAUNCHER_STORAGE_S3_ENDPOINT", "http://s3.internal"),
            ("worker", "LAUNCHER_DATABASE_AUTO_MIGRATE", "true"),
            ("worker", "LAUNCHER_REPLICA_ID", "node-a-api"),
        )
        for component, key, value in changes:
            raw = fixture()
            raw["services"][component]["environment"][key] = value
            with self.subTest(key=key, value=value), \
                 patch.object(mh, "run", return_value=json.dumps(raw)), \
                 patch.object(mh.inventory, "machine_identity", return_value="machine:abc"), \
             patch.object(mh, "check_secure_file", return_value=None):
                with self.assertRaises(mh.DeploymentError):
                    mh.resolved_compose(directory, "launcher")

    def test_reject_unpinned_image_and_public_api_port(self):
        temp, directory = tmp_config()
        self.addCleanup(temp.cleanup)
        raw = fixture()
        raw["services"]["api"]["image"] = "launcher-api:latest"
        with patch.object(mh, "run", return_value=json.dumps(raw)), \
             patch.object(mh.inventory, "machine_identity", return_value="machine:abc"), \
             patch.object(mh, "check_secure_file", return_value=None):
            with self.assertRaisesRegex(mh.DeploymentError, "неизменяемую контрольную сумму"):
                mh.resolved_compose(directory, "launcher")
        raw = fixture()
        raw["services"]["api"]["ports"] = [{"target": 8080, "published": "8080"}]
        with patch.object(mh, "run", return_value=json.dumps(raw)), \
             patch.object(mh.inventory, "machine_identity", return_value="machine:abc"), \
             patch.object(mh, "check_secure_file", return_value=None):
            with self.assertRaisesRegex(mh.DeploymentError, "host ports"):
                mh.resolved_compose(directory, "launcher")

    def test_env_permissions_and_symlinks_fail_closed(self):
        temp, directory = tmp_config()
        self.addCleanup(temp.cleanup)
        (directory / ".env").chmod(0o644)
        with self.assertRaisesRegex(mh.DeploymentError, "доступен группе"):
            mh.resolved_compose(directory, "launcher")
        (directory / ".env").chmod(0o600)
        (directory / ".env").unlink()
        (directory / ".env").symlink_to(directory / "nginx.multi-host-0512.conf")
        with self.assertRaisesRegex(mh.DeploymentError, "символической ссылкой"):
            mh.resolved_compose(directory, "launcher")

    def test_no_duplicate_machine_or_node_identity(self):
        a, b = node_report("a", "machine:a"), node_report("b", "machine:b")
        mh.assert_peer_config({"a": a, "b": b})
        with self.assertRaisesRegex(mh.DeploymentError, "Идентификаторы machine ID или node ID"):
            mh.assert_peer_config({"a": a, "b": {**b, "machineIdentity": "machine:a"}})
        with self.assertRaisesRegex(mh.DeploymentError, "Идентификаторы machine ID или node ID"):
            mh.assert_peer_config({"a": a, "b": {**b, "nodeId": "a"}})
        with self.assertRaisesRegex(mh.DeploymentError, "закреплены разные образы"):
            mh.assert_peer_config({"a": a, "b": {**b, "imageDigestRefs": {"api": "wrong"}}})

    def test_production_start_pulls_pinned_images_before_start_then_probes(self):
        temp, directory = tmp_config()
        self.addCleanup(temp.cleanup)
        calls = []
        with patch.object(mh, "resolved_compose", return_value=node_report("a", "machine:a")), \
             patch.object(mh, "run", side_effect=lambda argv, **kw: calls.append(argv) or ""), \
             patch.object(mh, "live_observe", return_value={"ready": True}):
            result = mh.local_up(directory, "launcher")
        self.assertTrue(result["ready"])
        self.assertIn("pull", calls[0])
        self.assertIn("--no-build", calls[1])
        self.assertIn("--wait", calls[1])

    def test_cluster_probe_requires_live_nodes_and_public_edge(self):
        reports = {"a": node_report("a", "machine:a"), "b": node_report("b", "machine:b")}
        with patch.object(mh, "edge_ready", return_value=(True, {"success": 3, "sampled": 3})):
            self.assertTrue(mh.cluster_verify(reports, "https://launcher.example")["multiHostControlPlaneObserved"])
        with patch.object(mh, "edge_ready", return_value=(False, {"success": 0, "sampled": 3})):
            self.assertFalse(mh.cluster_verify(reports, "https://launcher.example")["multiHostControlPlaneObserved"])
        reports["b"]["live"]["dockerEngineIdentity"] = reports["a"]["live"]["dockerEngineIdentity"]
        with patch.object(mh, "edge_ready", return_value=(True, {"success": 3, "sampled": 3})):
            self.assertFalse(mh.cluster_verify(reports, "https://launcher.example")["multiHostControlPlaneObserved"])
        reports["b"]["live"]["dockerEngineIdentity"] = "engine:machine:b"
        reports["b"]["ready"] = False
        with patch.object(mh, "edge_ready", return_value=(True, {"success": 3, "sampled": 3})):
            self.assertFalse(mh.cluster_verify(reports, "https://launcher.example")["multiHostControlPlaneObserved"])

    def test_outage_drill_restores_even_if_public_lb_does_not_fail_over(self):
        reports = {"a": node_report("a", "machine:a"), "b": node_report("b", "machine:b")}
        actions = []
        def action(target, script, directory, project, verb):
            actions.append(verb)
            return {"schema": mh.SCHEMA, "project": "launcher", "executed": True}
        with patch.object(mh, "collect_cluster", return_value=reports), \
             patch.object(mh, "cluster_verify", return_value={"multiHostControlPlaneObserved": True}), \
             patch.object(mh, "remote_stop_start", side_effect=action), \
             patch.object(mh, "edge_ready", return_value=(False, {"success": 0, "sampled": 3})), \
             patch.object(mh.time, "sleep"):
            report = mh.outage_drill({"a": "a.example", "b": "b.example"}, "/opt/tool.py",
                                     "/opt/deploy", "launcher", "https://launcher.example", "a")
        self.assertEqual(actions, ["stop", "start"])
        self.assertFalse(report["testPassed"])
        self.assertEqual(len(report["publicEdgeUnderOutage"]), 15)

    def test_outage_drill_pass_requires_survivor_and_full_restoration(self):
        reports = {"a": node_report("a", "machine:a"), "b": node_report("b", "machine:b")}
        actions = []
        with patch.object(mh, "collect_cluster", return_value=reports), \
             patch.object(mh, "cluster_verify", return_value={"multiHostControlPlaneObserved": True}), \
             patch.object(mh, "remote_stop_start", side_effect=lambda *args: actions.append(args[-1])), \
             patch.object(mh, "edge_ready", return_value=(True, {"success": 3, "sampled": 3})), \
             patch.object(mh, "remote_call", return_value=reports["b"]):
            result = mh.outage_drill({"a": "a.example", "b": "b.example"}, "/opt/tool.py",
                                     "/opt/deploy", "launcher", "https://launcher.example", "a")
        self.assertTrue(result["testPassed"])
        self.assertEqual(actions, ["stop", "start"])

    def test_ssh_target_hardening_and_secret_free_remote_failures(self):
        with self.assertRaises(mh.DeploymentError):
            mh.parse_nodes(["a=user@host;rm -rf /", "b=good-host"])
        with self.assertRaises(mh.DeploymentError):
            mh.parse_nodes(["a=one-host", "b=one-host"])
        raw = json.dumps({"schema": mh.SCHEMA, "project": "launcher"})
        with patch.object(mh, "run", return_value=raw) as call:
            mh.remote_call("user@host", "/opt/launcher/tool.py", "/opt/launcher/deploy", "launcher", "local-check")
        self.assertIn("StrictHostKeyChecking=yes", call.call_args.args[0])
        self.assertIn("BatchMode=yes", call.call_args.args[0])
        with patch.object(mh, "run", side_effect=mh.DeploymentError("command failed: ssh (exit 255)")):
            with self.assertRaises(mh.DeploymentError) as cm:
                mh.remote_call("user@host", "/opt/launcher/tool.py", "/opt/launcher/deploy", "launcher", "local-check")
        self.assertNotIn("secret", str(cm.exception))

    def test_actual_subprocess_local_check_writes_private_report_without_secrets(self):
        temp, directory = tmp_config()
        self.addCleanup(temp.cleanup)
        raw = fixture()
        cert = directory / "fullchain.pem"
        cert.write_text("local cert fixture")
        key = directory / "privkey.pem"
        key.write_text("local key fixture")
        key.chmod(0o600)
        for volume in raw["services"]["ingress"]["volumes"]:
            volume["source"] = str(key if volume["target"].endswith("privkey.pem") else cert)
        data = directory / "config.json"
        data.write_text(json.dumps(raw))
        fakebin = directory / "fakebin"
        fakebin.mkdir()
        docker = fakebin / "docker"
        docker.write_text("#!/bin/sh\ncat '" + str(data) + "'\n")
        docker.chmod(0o700)
        env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ.get("PATH", ""))
        report = directory / "local-result.json"
        process = subprocess.run([sys.executable, str(Path(mh.__file__)), "local-check",
                                  "--directory", str(directory), "--output", str(report)],
                                 capture_output=True, text=True, env=env)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(report.read_text())
        self.assertTrue(result["configurationValidated"])
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertNotIn("secret", json.dumps(result).lower())
        self.assertNotIn("PRIVATE_KEY", json.dumps(result))

    def test_observation_rejects_skip_growth_even_when_health_is_green(self):
        expected = node_report("a", "machine:a")
        state = {"containers": [{"service": s, "running": True, "health": "healthy",
                                 "environment": {"LAUNCHER_REPLICA_ID": "a-"+s},
                                 "readiness": {"success": 3}} for s in mh.SERVICES],
                 "observations": []}
        with patch.object(mh, "resolved_compose", return_value=expected), \
             patch.object(mh.inventory, "node_inventory", return_value=state), \
             patch.object(mh.inventory, "docker_ids", return_value=[]), \
             patch.object(mh.inventory, "docker_inspect", return_value=[]):
            report = mh.live_observe(Path("/opt/launcher/deploy/production"), "launcher", growth=False)
        self.assertFalse(report["ready"])
        self.assertIn("Реальная сквозная проверка PostgreSQL/Redis/S3 была намеренно пропущена", " ".join(report["issues"]))

    def test_cli_refuses_disruption_without_opt_in_and_does_not_contact_ssh(self):
        temp, directory = tmp_config()
        self.addCleanup(temp.cleanup)
        result = subprocess.run([sys.executable, str(Path(mh.__file__)), "cluster-drill", "--node", "a=hosta",
                                 "--node", "b=hostb", "--edge-url", "https://launcher.example",
                                 "--failed-node", "a", "--output", str(directory / "result.json")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((directory / "result.json").exists())
        self.assertIn("allow-disruption", result.stderr)

if __name__ == "__main__":
    unittest.main()

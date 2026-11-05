"""Регрессионные тесты выполнения, безопасности и ложных срабатываний 0.51.1 (Docker не нужен)."""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import ha_inventory_0511 as ha


def fixture(service, label, replica, health="healthy", ready=True, image="sha256:"+"a"*64):
    return {
        "service": service, "containerId": label, "imageId": image,
        "running": True, "health": health,
        "readiness": {"sampled": 3, "success": 3 if ready else 0,
                      "failures": 0 if ready else 3, "p50Ms": 2.5, "p95Ms": 3.1},
        "environment": {"LAUNCHER_REPLICA_ID": replica},
        "writableDataMounts": [], "secretsPresentInDockerEnvironment": []
    }


def node(node_id, names):
    return {"schema": "neverlauncher.ha-inventory.0.51.1", "project": "launcher",
            "nodeIdentity": node_id, "dockerEngineIdentity": "engine-"+node_id,
            "containers": names, "observations": [], "nodeStatus": "OBSERVED"}


class LiveHAInventory(unittest.TestCase):
    def test_env_redaction_includes_only_safe_flags_and_hostnames(self):
        env, sensitive = ha.safe_environment([
            "LAUNCHER_DATABASE_DSN=postgres://admin:password@db.internal:5432/app?sslmode=require&token=secret",
            "LAUNCHER_REDIS_URL=rediss://:password@redis.internal:6379/1",
            "LAUNCHER_STORAGE_S3_ENDPOINT=https://access:secret@s3.internal:9000/private",
            "LAUNCHER_AUTH_TOKEN_SECRET=very-sensitive",
            "LAUNCHER_STORAGE_S3_SECRET_KEY=keep-me-secret",
            "LAUNCHER_PROCESS_ROLE=worker",
        ])
        text = json.dumps(env)
        self.assertNotIn("password", text)
        self.assertNotIn("keep-me-secret", text)
        self.assertNotIn("very-sensitive", text)
        self.assertNotIn("admin", text)
        self.assertEqual(env["LAUNCHER_DATABASE_DSN_HOST"], "db.internal")
        self.assertEqual(env["LAUNCHER_REDIS_URL_HOST"], "redis.internal")
        self.assertEqual(env["LAUNCHER_STORAGE_S3_ENDPOINT_HOST"], "s3.internal")
        self.assertIn("LAUNCHER_AUTH_TOKEN_SECRET", sensitive)

    def test_docker_project_mismatch_rejected_without_exposing_env(self):
        with self.assertRaisesRegex(ha.InventoryError, "Несовпадение"):
            ha.classify_container({"Config": {"Labels": {"com.docker.compose.project": "wrong"},
                                               "Env": ["LAUNCHER_AUTH_TOKEN_SECRET=hidden"]}}, "launcher")

    def test_inspects_live_services_and_never_leaks_docker_secrets(self):
        item = {"Id": "a" * 64, "Image": "sha256:"+"f"*64,
                "Config": {"Labels": {"com.docker.compose.project": "launcher",
                                      "com.docker.compose.service": "worker-a"},
                           "Env": ["LAUNCHER_PROCESS_ROLE=worker", "LAUNCHER_REPLICA_ID=worker-a",
                                   "LAUNCHER_AUTH_TOKEN_SECRET=top-secret"]},
                "State": {"Running": True, "Health": {"Status": "healthy"}},
                "HostConfig": {"NetworkMode": "launcher_default"},
                "Mounts": [{"Destination": "/var/lib/launcher/storage", "Type": "volume",
                            "Name": "launcher_a_storage", "RW": True, "Source": "/very/private"},
                           {"Destination": "/private/keys", "Type": "bind", "Source": "/secrets"}]}
        report = ha.classify_container(item, "launcher")
        self.assertEqual(report["environment"]["LAUNCHER_REPLICA_ID"], "worker-a")
        serialized = json.dumps(report)
        self.assertNotIn("top-secret", serialized)
        self.assertNotIn("/secrets", serialized)
        self.assertNotIn("/very/private", serialized)
        self.assertIn("launcher_a_storage", serialized)

    def test_growth_requires_real_success_no_forged_boolean(self):
        with patch.object(ha, "execute", return_value=json.dumps({"verified": True,
                                      "checks": {"postgresql": True, "redisLease": True, "s3RoundTrip": False}})):
            report = ha.docker_growth("id")
            self.assertTrue(report["verified"])
            self.assertFalse(report["s3RoundTrip"])
        with patch.object(ha, "execute", side_effect=ha.InventoryError("command failed")):
            self.assertFalse(ha.docker_growth("id")["verified"])

    def test_unreachable_ready_is_not_healthy(self):
        with patch.object(ha, "execute", side_effect=ha.InventoryError("unreachable")) as invoke:
            result = ha.docker_ready("id", 3)
        self.assertEqual(result["failures"], 3)
        self.assertEqual(result["success"], 0)
        self.assertIsNone(result["p95Ms"])
        self.assertEqual(invoke.call_count, 3)

    def test_true_two_machine_api_worker_not_mistaken_for_certified_ha(self):
        a = node("a", [fixture("api", "api-a", "api-a"), fixture("worker-a", "worker-a", "worker-a"),
                       fixture("admin", "admin", ""), fixture("nginx", "nginx", "")])
        b = node("b", [fixture("api-b", "api-b", "api-b"), fixture("worker-b", "worker-b", "worker-b"),
                       fixture("admin", "admin-b", ""), fixture("nginx", "nginx-b", "")])
        report = ha.assess_cluster({"a": a, "b": b})
        self.assertFalse(report["multiHostFailoverCertified"])
        checks = {x["component"]: x["status"] for x in report["spof"]}
        self.assertEqual(checks["api"], "OBSERVED")
        self.assertEqual(checks["worker"], "OBSERVED")
        self.assertEqual(checks["postgresql"], "UNVERIFIED")
        self.assertEqual(checks["serverbridge"], "UNVERIFIED")

    def test_single_host_docker_compose_detects_real_spof(self):
        a = node("a", [fixture("api", "a", "a"), fixture("api-b", "b", "b"),
                       fixture("worker-a", "c", "c"), fixture("worker-b", "d", "d"),
                       fixture("postgres", "e", ""), fixture("redis", "f", ""),
                       fixture("nginx", "g", ""), fixture("admin", "h", "")])
        report = ha.assess_cluster({"a": a})
        checks = {x["component"]: x["status"] for x in report["spof"]}
        for critical in ("api", "worker", "ingress", "admin", "postgresql", "redis", "failure_domains"):
            self.assertEqual(checks[critical], "RISK", critical)

    def test_same_machine_id_clone_and_duplicate_replica_id_are_risks(self):
        a = node("same", [fixture("api", "a", "duplicated"), fixture("worker-a", "c", "wa")])
        b = node("same", [fixture("api-b", "b", "duplicated"), fixture("worker-b", "d", "wb")])
        report = ha.assess_cluster({"a": a, "b": b})
        checks = {x["component"]: x["status"] for x in report["spof"]}
        self.assertEqual(checks["replica_roles_and_identity"], "RISK")
        self.assertEqual(checks["failure_domains"], "RISK")

    def test_node_fails_missing_roles_storage_migrations_and_duplicates(self):
        raw = [{"Id": "a"*64, "Image": "sha256:"+"f"*64,
                "Config": {"Labels": {"com.docker.compose.project": "launcher",
                                      "com.docker.compose.service": service},
                           "Env": ["LAUNCHER_PROCESS_ROLE=api", "LAUNCHER_REPLICA_ID=same"]},
                "State": {"Running": True, "Health": {"Status": "healthy"}},
                "HostConfig": {}, "Mounts": []} for service in ("api", "worker-a")]
        with patch.object(ha, "docker_ids", return_value=["a"*12, "b"*12]), \
             patch.object(ha, "docker_inspect", return_value=raw), \
             patch.object(ha, "machine_identity", return_value="different"), \
             patch.object(ha, "execute", return_value="docker-engine"), \
             patch.object(ha, "docker_ready", return_value={"sampled": 2, "success": 2, "p50Ms": 1, "p95Ms": 1, "failures": 0}):
            report = ha.node_inventory("launcher", 2, growth=False)
        self.assertEqual(report["nodeStatus"], "RISK")
        self.assertTrue(any("Повторяющийся" in x for x in report["observations"]))
        self.assertTrue(any("DATABASE_AUTO_MIGRATE" in x for x in report["observations"]))
        self.assertTrue(any("worker-a: выделенная роль worker" in x for x in report["observations"]))

    def test_source_inventory_reports_but_does_not_assert_remote_consistency(self):
        root = Path(__file__).resolve().parents[2]
        report = ha.source_state_inventory(root)
        self.assertTrue(report["observed"])
        self.assertIn("AuthSessions", report["replicaLocalStateToVerify"])
        self.assertTrue(report["snapshotRestoredAtBoot"])
        self.assertTrue(report["realDependencyRoundTripPresent"])

    def test_atomic_private_report_and_no_overwrite_or_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.json"
            ha.write_report(str(path), {"ok": True})
            self.assertEqual(json.loads(path.read_text()), {"ok": True})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(ha.InventoryError, "уже существует"):
                ha.write_report(str(path), {"ok": False})
            link = Path(directory) / "link.json"
            link.symlink_to(path)
            with self.assertRaisesRegex(ha.InventoryError, "уже существует"):
                ha.write_report(str(link), {"ok": False})

    def test_remote_accepts_nonzero_risk_exit_with_json(self):
        a = node("a", [])
        with patch.object(ha, "execute", return_value=json.dumps(a)) as invoke:
            remote = ha.remote_node("operator@server.example", "/opt/launcher/inventory.py", "launcher", 2, False)
        self.assertEqual(remote["nodeIdentity"], "a")
        self.assertIn(3, invoke.call_args.kwargs["allowed_codes"])
        self.assertIn("StrictHostKeyChecking=yes", invoke.call_args.args[0])
        with self.assertRaises(ha.InventoryError):
            ha.remote_node("-o ProxyCommand=evil", "/opt/launcher/inventory.py", "launcher", 2, False)

    def test_empty_project_is_actionable_not_false_pass(self):
        with patch.object(ha, "docker_ids", return_value=[]), \
             patch.object(ha, "docker_inspect", return_value=[]), \
             patch.object(ha, "machine_identity", return_value="host"), \
             patch.object(ha, "execute", return_value="engine"):
            result = ha.node_inventory("launcher", 1, growth=False)
        self.assertEqual(result["nodeStatus"], "RISK")

    def test_real_subprocess_cli_with_docker_protocol_simulator(self):
        # Интеграционный тест запускает настоящий CLI через реальные подпроцессы;
        # имитируется только Docker. Это НЕ сертификат живого HA.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shim = root / "docker"
            services = ("api", "api-b", "worker-a", "worker-b", "postgres", "redis", "nginx", "admin")
            raw = []
            for idx, service in enumerate(services):
                role = "worker" if service.startswith("worker") else "api"
                raw.append({"Id": "%012x" % (idx+1), "Image": "sha256:"+"a"*64,
                            "Config": {"Labels": {"com.docker.compose.project": "launcher",
                                                  "com.docker.compose.service": service},
                                       "Env": ["LAUNCHER_DEPLOYMENT_MODE=network-ha",
                                               "LAUNCHER_PROCESS_ROLE="+role,
                                               "LAUNCHER_REPLICA_ID="+service,
                                               "LAUNCHER_REPOSITORY_DRIVER=postgres",
                                               "LAUNCHER_STORAGE_DRIVER=s3",
                                               "LAUNCHER_DATABASE_AUTO_MIGRATE=false",
                                               "LAUNCHER_SERVERBRIDGE_HA_REQUIRED=true",
                                               "LAUNCHER_RATE_LIMIT_ENABLED=true",
                                               "LAUNCHER_RATE_LIMIT_FAIL_CLOSED=true",
                                               "LAUNCHER_AUTH_TOKEN_SECRET=DO-NOT-EXPORT"]},
                            "State": {"Running": True, "Health": {"Status": "healthy"}},
                            "HostConfig": {"NetworkMode": "launcher"}, "Mounts": []})
            fixture_file = root / "docker-fixture.json"
            fixture_file.write_text(json.dumps(raw))
            shim.write_text(r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
items = json.load(open(os.environ['FAKE_DOCKER_FIXTURE']))
if args[0] == 'ps':
    print('\n'.join(i['Id'] for i in items))
elif args[0] == 'inspect':
    print(json.dumps(items))
elif args[0] == 'info':
    print('fake-engine-0511')
elif args[0] == 'exec':
    if 'growth' in args:
        print(json.dumps({'verified':True, 'checks': {'postgresql':True, 'redisLease':True, 's3RoundTrip':True}}))
    elif 'psql' in args[-1]:
        print(json.dumps({'inRecovery':False, 'synchronousStandbyConfigured':False, 'synchronousCommit':'on', 'replicationPeers':0, 'synchronousPeers':0}))
    elif 'redis-cli' in args[-1]:
        print('role:master\nconnected_slaves:0\n')
    else:
        print('ready')
else:
    sys.exit(22)
""")
            shim.chmod(0o700)
            output = root / "node.json"
            proc = subprocess.run([sys.executable, str(Path(ha.__file__).resolve()), "node",
                                   "--project", "launcher", "--samples", "2", "--output", str(output)],
                                  env={**os.environ, "PATH": str(root)+os.pathsep+os.environ["PATH"],
                                       "FAKE_DOCKER_FIXTURE": str(fixture_file)},
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr.decode())
            result = json.loads(output.read_text())
            self.assertEqual(result["nodeStatus"], "OBSERVED")
            self.assertEqual(len(result["containers"]), len(services))
            self.assertNotIn("DO-NOT-EXPORT", output.read_text())
            self.assertTrue(all(i["readiness"]["success"] == 2 for i in result["containers"]
                                if i["service"] in ("api", "api-b", "worker-a", "worker-b")))
            self.assertTrue(all(i["dependencyRoundTrip"]["s3RoundTrip"] for i in result["containers"]
                                if i["service"] in ("api", "api-b")))
            self.assertTrue(any(i.get("postgresState", {}).get("observed") for i in result["containers"]))

    def test_postgres_redis_fail_closed_with_invalid_runtime_reply(self):
        with patch.object(ha, "execute", return_value="not-valid-json"):
            self.assertFalse(ha.probe_postgres("postgres")["observed"])
        with patch.object(ha, "execute", return_value="role:master\nconnected_slaves:invalid\n"):
            self.assertFalse(ha.probe_redis("redis")["observed"])

    def test_invalid_cli_has_fail_closed_return_code(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "should-not-exist.json"
            self.assertEqual(ha.main(["node", "--project", "../escape", "--output", str(bad)]), 2)
            self.assertFalse(bad.exists())


if __name__ == "__main__":
    unittest.main()

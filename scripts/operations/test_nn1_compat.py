"""Регрессионные проверки допуска N/N-1 на реальных системах 0.51.6 (результаты фикстур не являются
свидетельствами GA)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import ha_inventory as inv
import multi_host as mh
import nn1_compat as nn


def report(label, version):
    digest = "repo/launcher@sha256:" + ("a" if version == "0.51.5" else "b") * 64
    def role(name):
        return {"service": name, "running": True, "health": "healthy",
                "containerId": label + "-" + name,
                "environment": {"LAUNCHER_REPLICA_ID": label + "-" + name},
                "readiness": {"success": 3, "sampled": 3, "versionVerified": True, "version": version}}
    return {"schema": mh.SCHEMA, "configurationValidated": True, "ready": True,
            "machineIdentity": "machine:" + label, "nodeId": label,
            "imageDigestRefs": {"api": digest, "worker": digest},
            "sharedEndpoints": {"postgres": "pg.example", "redis": "redis.example", "s3": "s3.example", "public": "edge.example"},
            "live": {"dockerEngineIdentity": "docker:" + label,
                     "containers": [role("api"), role("worker")]},
            "issues": [], "compatibility0516": {"liveVersion": version, "apiStatus": "ok", "bridgeProtocol": 3,
                                             "loadersSHA256": "f"*64, "runtimeRequirementsSHA256": "e"*64,
                                             "bridgeContractSHA256": "d"*64}}


class NN1Admission(unittest.TestCase):
    def test_catalog_pinned_to_real_old_sql_checksum(self):
        catalog, digest = nn.migration_catalog()
        self.assertEqual(digest, nn.CATALOG_SHA256_0515)
        self.assertGreaterEqual(len(catalog), 100)
        self.assertEqual(nn.validate_schema(dict(catalog), catalog)["pending"], 0)
        for changes in ({"extra": "a"*64}, {next(iter(catalog)): "b"*64}, {}):
            altered = dict(catalog)
            altered.update(changes)
            if not changes:
                altered.pop(next(iter(catalog)))
            with self.assertRaises(nn.CompatibilityError):
                nn.validate_schema(altered, catalog)
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            for f in (nn.ROOT / "services/api/internal/dbmigrate/sql").glob("*.sql"):
                (directory / f.name).write_bytes(f.read_bytes())
            first = next(directory.glob("*.sql"))
            first.write_bytes(first.read_bytes() + b"\n-- changed")
            with self.assertRaisesRegex(nn.CompatibilityError, "каталог изменился"):
                nn.migration_catalog(directory)

    def test_end_to_end_operator_gate_queries_both_remote_hosts_and_real_primary(self):
        nodes = {"a": "ops@a.example", "b": "ops@b.example"}
        reports = {"a": report("a", "0.51.5"), "b": report("b", "0.51.6")}
        argv = types.SimpleNamespace(node=[k + "=" + v for k,v in nodes.items()],
                                     directory="/opt/launcher/deploy/production", project="launcher",
                                     edge_url="https://edge.example", remote_script="/opt/launcher/scripts/operations/multi_host.py",
                                     pg_dsn_file=Path("/run/secrets/primary"), require_mixed=True)
        with patch.object(mh, "remote_call", side_effect=lambda target, *a, **kw: reports[target.split("@")[1][0]]), \
             patch.object(mh, "edge_ready", return_value=(True,{"success":3,"sampled":3})), \
             patch.object(nn, "live_pg_migrations", return_value=nn.migration_catalog()[0]):
            result = nn.verify(argv)
        self.assertTrue(result["verified"])
        self.assertEqual(result["hostCount"], 2)
        self.assertEqual(result["postgres"]["checkedMigrations"], len(nn.migration_catalog()[0]))
        with patch.object(mh, "remote_call", side_effect=lambda target, *a, **kw: reports[target.split("@")[1][0]]), \
             patch.object(mh, "edge_ready", return_value=(False,{"success":0,"sampled":3})), \
             patch.object(nn, "live_pg_migrations", return_value=nn.migration_catalog()[0]):
            with self.assertRaisesRegex(nn.CompatibilityError, "HTTPS edge"):
                nn.verify(argv)

    def test_real_mixed_hosts_with_matching_api_worker_and_protocol(self):
        pairs = {"a": report("a", "0.51.5"), "b": report("b", "0.51.6")}
        self.assertEqual(set(nn.validate_live_nodes(pairs, require_mixed=True).values()), nn.PAIR)
        # Совпадение версий допустимо после остановки последнего старого процесса.
        pairs["a"] = report("a", "0.51.6")
        self.assertEqual(len(set(nn.validate_live_nodes(pairs).values())), 1)
        with self.assertRaisesRegex(nn.CompatibilityError, "both N and N-1"):
            nn.validate_live_nodes(pairs, require_mixed=True)

    def test_reject_role_split_and_unsupported_versions(self):
        base = {"a": report("a", "0.51.5"), "b": report("b", "0.51.6")}
        variants = []
        x = json.loads(json.dumps(base)); x["b"]["live"]["containers"][1]["readiness"]["version"] = "0.51.5"; variants.append(x)
        x = json.loads(json.dumps(base)); x["b"]["live"]["containers"][0]["readiness"]["versionVerified"] = False; variants.append(x)
        x = json.loads(json.dumps(base)); x["a"]["live"]["containers"][0]["readiness"]["version"] = "0.51.4"; variants.append(x)
        x = json.loads(json.dumps(base)); x["b"]["sharedEndpoints"]["postgres"] = "other.pg"; variants.append(x)
        x = json.loads(json.dumps(base)); x["b"]["machineIdentity"] = "machine:a"; variants.append(x)
        x = json.loads(json.dumps(base)); x["b"]["imageDigestRefs"]["worker"] = "wrong"; variants.append(x)
        x = json.loads(json.dumps(base)); x["b"]["compatibility0516"]["bridgeContractSHA256"] = "c"*64; variants.append(x)
        x = json.loads(json.dumps(base)); x["b"]["compatibility0516"].pop("bridgeProtocol"); variants.append(x)
        x = json.loads(json.dumps(base)); x["a"]["live"]["containers"][0]["readiness"]["success"] = 2; variants.append(x)
        for i, pairs in enumerate(variants):
            with self.subTest(variant=i), self.assertRaises(nn.CompatibilityError):
                nn.validate_live_nodes(pairs)

    def test_pg_dsn_secure_and_never_argv_secret(self):
        with tempfile.TemporaryDirectory() as d:
            file = Path(d)/"secret"
            file.write_text("postgresql://user:password123@pg.internal:5432/launcher?sslmode=verify-full\n")
            file.chmod(0o600)
            env = nn.dsn_environment(file)
            self.assertEqual(env["PGPASSWORD"], "password123")
            self.assertEqual(env["PGSSLMODE"], "verify-full")
            seen = []
            def fake_run(argv, **kwargs):
                seen.append((argv,kwargs))
                self.assertNotIn("password123", " ".join(argv))
                self.assertIn("BEGIN TRANSACTION READ ONLY", kwargs["input"])
                return types.SimpleNamespace(returncode=0, stdout='primary\nshape-ok\n'+json.dumps({"version":"1","checksum":"a"*64})+'\n', stderr="")
            with patch.object(nn.subprocess, "run", side_effect=fake_run):
                actual = nn.live_pg_migrations(file)
            self.assertEqual(actual, {"1": "a"*64})
            file.chmod(0o644)
            with self.assertRaisesRegex(nn.CompatibilityError, "0600"):
                nn.dsn_environment(file)
            file.chmod(0o600)
            file.write_text("postgres://user:password123@pg.internal/db?sslmode=disable\n")
            with self.assertRaisesRegex(nn.CompatibilityError, "verify-full"):
                nn.dsn_environment(file)
            file.write_text("postgres://user:password123@pg.internal/db?sslmode=verify-full\n")
            with patch.object(nn.subprocess, "run", return_value=types.SimpleNamespace(returncode=0,stdout="replica\n",stderr="")):
                with self.assertRaisesRegex(nn.CompatibilityError, "writable primary"):
                    nn.live_pg_migrations(file)
            with patch.object(nn.subprocess, "run", return_value=types.SimpleNamespace(returncode=0,stdout="primary\nshape-mismatch\n",stderr="")):
                with self.assertRaisesRegex(nn.CompatibilityError, "schema shape"):
                    nn.live_pg_migrations(file)
            with patch.object(nn.subprocess, "run", return_value=types.SimpleNamespace(returncode=1,stdout="",stderr="password123")):
                with self.assertRaises(nn.CompatibilityError) as ctx:
                    nn.live_pg_migrations(file)
            self.assertNotIn("password123", str(ctx.exception))

    def test_inventory_reads_running_binary_version_from_http_not_docker_label(self):
        with patch.object(inv, "execute", side_effect=['{"status":"ready","version":"0.51.5"}',
                                                        '{"status":"ready","version":"0.51.5"}',
                                                        '{"status":"ready","version":"0.51.5"}']):
            a = inv.docker_ready("id", 3)
        self.assertTrue(a["versionVerified"])
        self.assertEqual(a["version"], "0.51.5")
        with patch.object(inv, "execute", side_effect=['{"status":"ready","version":"0.51.5"}',
                                                        '{"status":"ready","version":"0.51.6"}',
                                                        '{"status":"ready","version":"0.51.5"}']):
            a = inv.docker_ready("id", 3)
        self.assertFalse(a["versionVerified"])
        with patch.object(inv, "execute", return_value="ready\n"):
            self.assertIsNone(inv.docker_ready("id", 3)["version"])

    def test_local_protocol_probes_hit_live_paths(self):
        r = report("a", "0.51.5")
        results = {"/api/v1/status": {"status":"ok", "version":"0.51.5"},
                   "/api/v1/loaders": {"version":"0.51.5", "items":[{"id":"vanilla"}]},
                   "/api/v1/runtime/requirements": {"version":"0.51.5", "java":{"supportedMajorVersions":[21]}},
                   "/api/v1/server-bridge/capabilities?protocols=3,2": {"data": {
                       "toolVersion":"0.51.5", "negotiatedProtocolVersion":3,
                       "supportedProtocolVersions":[3,2],"rollingUpgrade":True,
                       "activeSigningKeyFingerprint":"key", "protocolV3FeatureDigest":"d"}}}
        def exec_cmd(argv, **kwargs):
            return json.dumps(results[argv[-1].split(":8080",1)[1]])
        with patch.object(mh, "live_observe", return_value=r), patch.object(inv,"execute",side_effect=exec_cmd):
            out = mh.local_compat_observe_0516(Path("/opt/launcher/deploy/production"),"launcher")
        self.assertEqual(out["compatibility0516"]["liveVersion"], "0.51.5")
        self.assertEqual(out["compatibility0516"]["bridgeProtocol"], 3)
        results["/api/v1/server-bridge/capabilities?protocols=3,2"]["data"]["negotiatedProtocolVersion"] = 2
        with patch.object(mh, "live_observe", return_value=r), patch.object(inv,"execute",side_effect=exec_cmd):
            with self.assertRaisesRegex(mh.DeploymentError, "ServerBridge"):
                mh.local_compat_observe_0516(Path("/opt/launcher/deploy/production"),"launcher")

if __name__ == "__main__":
    unittest.main()

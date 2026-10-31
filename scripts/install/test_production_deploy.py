"""Dependency-free unit and adversarial tests for DEP09."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

module_file = Path(__file__).with_name("production-deploy.py")
spec = importlib.util.spec_from_file_location("production_deploy_dep09", module_file)
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


def settings(mode="standard"):
    result = {
        name: "safe-value-" + name
        for name in (
            "LAUNCHER_AUTH_TOKEN_SECRET",
            "LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY",
            "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON",
            "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON",
            "LAUNCHER_WEBAUTHN_RP_ID",
            "LAUNCHER_WEBAUTHN_ORIGINS",
            "LAUNCHER_CORS_ALLOWED_ORIGINS",
            "POSTGRES_PASSWORD",
            "LAUNCHER_DATABASE_DSN",
            "LAUNCHER_IMAGE_TAG",
        )
    }
    result.update(
        LAUNCHER_PUBLIC_URL="https://launcher.example.org",
        LAUNCHER_WEBAUTHN_RP_ID="example.org",
        LAUNCHER_WEBAUTHN_ORIGINS="https://launcher.example.org",
        LAUNCHER_CORS_ALLOWED_ORIGINS="https://launcher.example.org",
        LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON='{"releases":["release"]}',
        LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON='{"releases":["bridge"]}',
        LAUNCHER_AUTH_TOKEN_SECRET="a" * 64,
        LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY="b" * 64,
        POSTGRES_PASSWORD="c" * 40,
        REDIS_PASSWORD="d" * 40,
        LAUNCHER_REPOSITORY_DRIVER="postgres",
        LAUNCHER_IMAGE_TAG="0.32.13",
        LAUNCHER_DEPLOYMENT_MODE=mode,
        LAUNCHER_SERVERBRIDGE_HA_REQUIRED="false",
    )
    if mode == "network-ha":
        for key in (
            "REDIS_PASSWORD",
            "LAUNCHER_REPLICA_ID",
            "LAUNCHER_STORAGE_S3_ENDPOINT",
            "LAUNCHER_STORAGE_S3_BUCKET",
            "LAUNCHER_STORAGE_S3_REGION",
            "LAUNCHER_STORAGE_S3_ACCESS_KEY",
            "LAUNCHER_STORAGE_S3_SECRET_KEY",
        ):
            result[key] = "d" * 40 if key == "REDIS_PASSWORD" else "safe-value-" + key
    return result


class DeploymentTests(unittest.TestCase):
    def test_preflight_rejects_placeholders_and_conflicting_mode(self):
        env = settings()
        deploy.preflight(env, "standard", docker=True)
        for name, value in [
            ("POSTGRES_PASSWORD", "CHANGE_ME_PASSWORD"),
            ("LAUNCHER_PUBLIC_URL", "http://localhost"),
            ("LAUNCHER_DEPLOYMENT_MODE", "network-ha"),
            ("LAUNCHER_SERVERBRIDGE_HA_REQUIRED", "true"),
        ]:
            edited = dict(env, **{name: value})
            with self.assertRaises(RuntimeError, msg=name):
                deploy.preflight(edited, "standard", docker=True)
        with self.assertRaises(RuntimeError):
            deploy.preflight(settings(), "network-ha", docker=True)
        deploy.preflight(settings("network-ha"), "network-ha", docker=True)

    def test_env_permissions_and_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("POSTGRES_PASSWORD=verygood\n")
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                deploy.read_env(path)
            path.chmod(0o600)
            self.assertEqual(deploy.read_env(path)["POSTGRES_PASSWORD"], "verygood")
            path.write_text("POSTGRES_PASSWORD=first\nPOSTGRES_PASSWORD=second\n")
            with self.assertRaises(RuntimeError):
                deploy.read_env(path)

    def test_compose_lifecycle_preserves_volumes_and_guards_purge(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            env_path = home / ".env"
            env_path.write_text("".join(f"{k}={v}\n" for k, v in settings().items()))
            env_path.chmod(0o600)
            calls = []

            def fake_exec(command, **_):
                calls.append(command)
                return SimpleNamespace(returncode=0)

            args = lambda action, **extra: SimpleNamespace(
                env=str(env_path),
                mode="standard",
                action=action,
                purge_data=extra.get("purge", False),
                confirm=extra.get("confirm", ""),
                backup_confirmed=extra.get("backup", False),
            )
            with patch.object(deploy, "execute", fake_exec):
                deploy.compose_run(args("up"))
                self.assertTrue(any("--wait" in x for x in calls))
                self.assertEqual(
                    json.loads((home / ".launcher-compose-state.json").read_text())[
                        "mode"
                    ],
                    "standard",
                )
                deploy.compose_run(args("down"))
                self.assertFalse(any("--volumes" in x for x in calls))
                with self.assertRaises(RuntimeError):
                    deploy.compose_run(args("uninstall", purge=True))
                self.assertFalse(any("--volumes" in x for x in calls))
                deploy.compose_run(
                    args("uninstall", purge=True, confirm="PURGE-LAUNCHER-VOLUMES")
                )
                self.assertTrue(any("--volumes" in x for x in calls))
                self.assertFalse((home / ".launcher-compose-state.json").exists())

    def test_compose_upgrade_requires_backup_and_mode_change_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            env_path = home / ".env"
            config = settings()
            env_path.write_text("".join(f"{k}={v}\n" for k, v in config.items()))
            env_path.chmod(0o600)
            args = lambda **kw: SimpleNamespace(
                env=str(env_path),
                mode=kw.get("mode", "standard"),
                action="up",
                purge_data=False,
                confirm="",
                backup_confirmed=kw.get("backup", False),
            )
            calls = []
            with patch.object(
                deploy, "execute", side_effect=lambda x, **y: calls.append(x)
            ):
                deploy.compose_run(args())
                config["LAUNCHER_IMAGE_TAG"] = "0.32.14"
                env_path.write_text("".join(f"{k}={v}\n" for k, v in config.items()))
                with self.assertRaises(RuntimeError):
                    deploy.compose_run(args())
                deploy.compose_run(args(backup=True))
                self.assertEqual(
                    json.loads((home / ".launcher-compose-state.json").read_text())[
                        "version"
                    ],
                    "0.32.14",
                )
                config = settings("network-ha")
                env_path.write_text("".join(f"{k}={v}\n" for k, v in config.items()))
                with self.assertRaises(RuntimeError):
                    deploy.compose_run(args(mode="network-ha", backup=True))

    def test_symlinks_and_mounts_never_deleted(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "owned"
            root.mkdir()
            outside = Path(base) / "outside"
            outside.write_text("do-not-delete")
            (root / "evil").symlink_to(outside)
            with self.assertRaises(RuntimeError):
                deploy.no_symlinks_or_mounts(root)
            self.assertEqual(outside.read_text(), "do-not-delete")

    def test_managed_dir_refuses_unrelated_content_and_wrong_marker(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / "release"
            root.mkdir()
            (root / "external").write_text("data")
            with self.assertRaises(RuntimeError):
                deploy.managed_dir(root, deploy.OWNER, create=True)
            (root / "external").unlink()
            deploy.managed_dir(root, deploy.OWNER, create=True)
            (root / deploy.OWNER).write_text("other")
            with self.assertRaises(RuntimeError):
                deploy.managed_dir(root, deploy.OWNER)

    def test_native_uninstall_requires_confirmation_before_any_action(self):
        with patch.object(deploy, "native_uninstall") as remove:
            with self.assertRaises(RuntimeError):
                deploy.main(["native", "uninstall", "--purge-data"])
            remove.assert_not_called()
            deploy.main(
                [
                    "native",
                    "uninstall",
                    "--purge-data",
                    "--confirm",
                    "PURGE-LAUNCHER-NATIVE-DATA",
                ]
            )
            remove.assert_called_once()

    def test_compose_files_match_real_modes(self):
        # Production CLI has no external Python dependencies.
        standard = deploy.COMPOSE.read_text()
        ha = deploy.HA.read_text()
        self.assertIn("profiles: [network-ha]", standard)
        self.assertIn("launcher_coordinator:", standard)
        self.assertIn('LAUNCHER_SERVERBRIDGE_HA_REQUIRED: "false"', standard)
        self.assertIn('LAUNCHER_SERVERBRIDGE_HA_REQUIRED: "true"', ha)
        self.assertIn("LAUNCHER_STORAGE_DRIVER: s3", ha)

    def test_native_signed_release_install_uninstall_and_rollback(self):
        from contextlib import nullcontext

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            install_root = base / "opt" / "launcher"
            state_root = base / "var" / "launcher"
            unit = base / "etc" / "launcher.service"
            unit.parent.mkdir()
            (base / "opt").mkdir()
            (base / "var").mkdir()
            env = base / "backend.env"
            settings_native = settings()
            settings_native["LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH"] = str(
                state_root / "coordinator" / "state.db"
            )
            settings_native["LAUNCHER_STORAGE_LOCAL_PATH"] = str(
                state_root / "storage" / "current"
            )
            env.write_text("".join(f"{k}={v}\n" for k, v in settings_native.items()))
            env.chmod(0o600)
            cli = base / "launcher-install"
            cli.write_text("trusted release verifier")
            cli.chmod(0o755)
            pub = base / "trusted.pub"
            pub.write_text("trusted pin")
            pub.chmod(0o600)
            bundle = base / "bundle.zip"
            bundle.write_bytes(b"only mocked in test")
            args = SimpleNamespace(
                env=str(env),
                installer=str(cli),
                trusted_key=str(pub),
                bundle=str(bundle),
                upgrade=False,
                backup_confirmed=False,
            )
            calls = []

            def fake_exec(argv, **kwargs):
                argv = [str(part) for part in argv]
                calls.append(argv)
                if argv[1] == "verify":
                    return SimpleNamespace(
                        stdout="verified Launcher 0.32.13\n", returncode=0
                    )
                if argv[1] == "install":
                    dest = Path(argv[-1])
                    (dest / "bin").mkdir(parents=True)
                    binary = dest / "bin" / "launcher-api"
                    binary.write_text("test program")
                    binary.chmod(0o755)
                return SimpleNamespace(
                    stdout="",
                    returncode=1
                    if argv[:3] == ["systemctl", "is-active", "--quiet"]
                    else 0,
                )

            with (
                patch.multiple(
                    deploy, INSTALL_ROOT=install_root, STATE_ROOT=state_root, UNIT=unit
                ),
                patch.object(deploy, "require_root"),
                patch.object(deploy, "exclusive_lock", return_value=nullcontext()),
                patch.object(deploy, "execute", side_effect=fake_exec),
                patch.object(deploy, "health_check") as check,
                patch.object(
                    deploy.pwd,
                    "getpwnam",
                    return_value=SimpleNamespace(
                        pw_uid=os.getuid(), pw_gid=os.getgid()
                    ),
                ),
            ):
                deploy.native_install(args)
                self.assertEqual(
                    os.readlink(install_root / "current"), "releases/0.32.13"
                )
                self.assertTrue(unit.exists())
                self.assertTrue((state_root / "coordinator").is_dir())
                self.assertTrue(check.called)
                with self.assertRaises(RuntimeError):
                    deploy.native_install(args)
                deploy.native_uninstall(SimpleNamespace(purge_data=False, confirm=""))
                self.assertTrue(state_root.exists())
                self.assertFalse(unit.exists())
                self.assertFalse(install_root.exists())
                # Roll back a failed first activation without removing unrelated state.
                check.side_effect = RuntimeError("health failed")
                with self.assertRaises(RuntimeError):
                    deploy.native_install(args)
                self.assertFalse((install_root / "current").exists())
                self.assertFalse(unit.exists())
                self.assertTrue(state_root.exists())


if __name__ == "__main__":
    unittest.main()

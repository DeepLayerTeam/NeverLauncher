#!/usr/bin/env python3
"""Launcher 0.32.13 DEP09 production deployment (Linux).

Standard Compose = PostgreSQL + SQLite coordinator, Redis optional.
Native = signed installer bundle + root-owned release + systemd.
No production SQLite-only backend or automatic live SQLite->PostgreSQL cutover.
"""

import argparse
import contextlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "deploy" / "production" / "docker-compose.yml"
HA = ROOT / "deploy" / "production" / "docker-compose.network-ha.yml"
UNIT_NAME = "launcher.service"
UNIT = Path("/etc/systemd/system") / UNIT_NAME
INSTALL_ROOT = Path("/opt/launcher")
STATE_ROOT = Path("/var/lib/launcher")
ENV_NATIVE = Path("/etc/launcher/backend.env")
OWNER = ".launcher-dep09-managed"
DATA_MARKER = ".launcher-dep09-data"
MARKER_VALUE = "launcher-0.32.13-deployment-v1\n"
UNIT_MARKER = "# Managed by Launcher DEP09 production-deploy.py"
VERSION_RE = re.compile(r"^verified Launcher ([a-zA-Z0-9][a-zA-Z0-9._-]{0,63})$", re.M)
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def fail(message):
    raise RuntimeError(message)


def execute(argv, *, capture=False, check=True):
    result = subprocess.run(
        [str(p) for p in argv],
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if check and result.returncode:
        fail(
            f"{argv[0]} {argv[1] if len(argv) > 1 else ''} failed (exit {result.returncode})"
        )
    return result


def safe_file(path, *, private=False, executable=False):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        fail(f"not a regular file: {path}")
    if info.st_mode & (0o077 if private else 0o022):
        fail(f"unsafe permissions: {path}")
    if executable and not info.st_mode & 0o111:
        fail(f"not executable: {path}")
    return info


def safe_directory(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        fail(f"unsafe directory permissions: {path}")


def write_exclusive(path, data, mode=0o600):
    fd = os.open(
        str(path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise
    sync_directory(Path(path).parent)


def sync_directory(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_text(path, content, perm=0o644):
    temp = Path(str(path) + ".new." + str(os.getpid()))
    write_exclusive(temp, content, perm)
    try:
        os.replace(temp, path)
        sync_directory(Path(path).parent)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def read_env(path):
    safe_file(path, private=True)
    if path.stat().st_size > 256 * 1024:
        fail("environment file is too large")
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail("invalid env file line")
        key, value = line.split("=", 1)
        if not ENV_KEY_RE.fullmatch(key) or key in values or "\x00" in value:
            fail("invalid or duplicate env key")
        values[key] = value.strip().strip('"').strip("'")
    return values


def preflight(values, mode, *, docker):
    needed = [
        "NEVERLAUNCHER_PUBLIC_URL",
        "NEVERLAUNCHER_AUTH_TOKEN_SECRET",
        "NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY",
        "NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON",
        "NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON",
        "NEVERLAUNCHER_WEBAUTHN_RP_ID",
        "NEVERLAUNCHER_WEBAUTHN_ORIGINS",
        "NEVERLAUNCHER_CORS_ALLOWED_ORIGINS",
    ]
    if docker:
        needed += ["POSTGRES_PASSWORD", "NEVERLAUNCHER_IMAGE_TAG"]
        if mode == "network-ha":
            needed += [
                "REDIS_PASSWORD",
                "NEVERLAUNCHER_REPLICA_ID",
                "NEVERLAUNCHER_STORAGE_S3_ENDPOINT",
                "NEVERLAUNCHER_STORAGE_S3_BUCKET",
                "NEVERLAUNCHER_STORAGE_S3_REGION",
                "NEVERLAUNCHER_STORAGE_S3_ACCESS_KEY",
                "NEVERLAUNCHER_STORAGE_S3_SECRET_KEY",
            ]
    else:
        needed.append("NEVERLAUNCHER_DATABASE_DSN")
    missing = [
        key
        for key in needed
        if not values.get(key)
        or values[key].upper().startswith(("CHANGE_ME", "REPLACE_ME"))
    ]
    if missing:
        fail("missing or placeholder production configuration: " + ", ".join(missing))
    public = values["NEVERLAUNCHER_PUBLIC_URL"]
    url = urllib.parse.urlsplit(public)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.path not in ("", "/")
        or url.query
        or url.fragment
        or any(c.isspace() for c in public)
    ):
        fail("production PUBLIC_URL must be an HTTPS origin")
    if values["NEVERLAUNCHER_WEBAUTHN_ORIGINS"] != public or public not in values[
        "NEVERLAUNCHER_CORS_ALLOWED_ORIGINS"
    ].split(","):
        fail("WebAuthn origins and CORS must contain the exact HTTPS public origin")
    rp = values["NEVERLAUNCHER_WEBAUTHN_RP_ID"].lower()
    hostname = url.hostname.lower()
    if not (hostname == rp or hostname.endswith("." + rp)):
        fail("WebAuthn relying-party ID does not match public hostname")
    for key in (
        "NEVERLAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON",
        "NEVERLAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON",
    ):
        try:
            policy = json.loads(values[key])
        except ValueError:
            fail(f"{key} must contain a nonempty JSON policy")
        if not isinstance(policy, (list, dict)) or not policy:
            fail(f"{key} must contain a nonempty JSON policy")
    if len(values["NEVERLAUNCHER_AUTH_TOKEN_SECRET"]) < 32:
        fail("authentication signing secret is too short")
    if not re.fullmatch(
        r"[0-9a-fA-F]{64}", values["NEVERLAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY"]
    ):
        fail("manifest signing key must be a 32-byte hex Ed25519 seed")
    if docker:
        for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD"):
            if key == "REDIS_PASSWORD" and mode != "network-ha":
                continue
            if not re.fullmatch(r"[A-Za-z0-9._~-]{24,}", values[key]):
                fail(f"{key} must be URL-safe and at least 24 characters")
    if not docker and values.get("NEVERLAUNCHER_REPOSITORY_DRIVER") != "postgres":
        fail(
            "native Backend must use PostgreSQL; SQLite-only HTTP repository is unsupported"
        )
    if not docker and not values.get(
        "NEVERLAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH"
    ):
        fail("native Standard requires a durable SQLite coordinator")
    if (
        mode == "standard"
        and values.get("NEVERLAUNCHER_SERVERBRIDGE_HA_REQUIRED", "").lower() == "true"
    ):
        fail("Standard mode cannot require HA")
    if values.get("NEVERLAUNCHER_DEPLOYMENT_MODE", mode) not in ("", mode):
        fail("env deployment mode conflicts with selected mode")
    if mode == "network-ha" and not docker:
        fail("native HA provisioning is not supported by this local-service installer")


@contextlib.contextmanager
def exclusive_lock(path):
    path = Path(path)
    if path.is_symlink():
        fail("refusing symlink lock path")
    fd = os.open(
        str(path), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    try:
        if os.fstat(fd).st_mode & 0o077:
            fail("lock file must be private")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def compose_args(env, mode):
    args = [
        "docker",
        "compose",
        "--project-name",
        "launcher",
        "--env-file",
        str(env),
        "-f",
        str(COMPOSE),
    ]
    if mode == "network-ha":
        args += ["-f", str(HA), "--profile", "network-ha"]
    return args


def compose_run(args):
    env = Path(args.env).resolve(strict=True)
    safe_file(env, private=True)
    safe_directory(env.parent)
    values = read_env(env)
    mode = args.mode
    preflight(values, mode, docker=True)
    state_file = env.parent / ".launcher-compose-state.json"
    with exclusive_lock(env.parent / ".launcher-compose.lock"):
        state = {}
        if state_file.exists():
            safe_file(state_file, private=True)
            state = json.loads(state_file.read_text())
        if state and state.get("mode") != mode:
            fail("deployment mode changed; uninstall old mode first (volumes retained)")
        if (
            args.action == "up"
            and state
            and state.get("version") != values["NEVERLAUNCHER_IMAGE_TAG"]
            and not args.backup_confirmed
        ):
            fail(
                "upgrade requires --backup-confirmed after verified database and blob backups"
            )
        base = compose_args(env, mode)
        if args.action == "check":
            execute(base + ["config", "--quiet"])
            print(f"Compose {mode} configuration valid")
        elif args.action == "up":
            execute(base + ["config", "--quiet"])
            execute(
                base
                + ["up", "-d", "--wait", "--wait-timeout", "120", "--remove-orphans"]
            )
            atomic_text(
                state_file,
                json.dumps({"mode": mode, "version": values["NEVERLAUNCHER_IMAGE_TAG"]})
                + "\n",
                0o600,
            )
            print(
                "Compose services started; inspect docker compose ps and /ready before accepting traffic"
            )
        elif args.action == "status":
            execute(base + ["ps"])
        elif args.action in ("down", "uninstall"):
            if args.action == "uninstall" and args.purge_data:
                if args.confirm != "PURGE-NEVERLAUNCHER-VOLUMES":
                    fail("purge requires --confirm PURGE-NEVERLAUNCHER-VOLUMES")
                execute(base + ["down", "--remove-orphans", "--volumes"])
            else:
                execute(base + ["down", "--remove-orphans"])
            if args.action == "uninstall":
                state_file.unlink(missing_ok=True)
                sync_directory(env.parent)
                print(
                    "Compose application removed; configuration and secrets retained; "
                    + (
                        "project volumes purged"
                        if args.purge_data
                        else "project volumes retained"
                    )
                )
        else:
            fail("unknown compose action")


def require_root():
    if os.geteuid() != 0:
        fail("native service operations require root")
    if sys.platform != "linux" or not Path("/run/systemd/system").exists():
        fail("native service operations require Linux with running systemd")


def no_symlinks_or_mounts(path):
    """Walk before deletion; never follow links or cross mount points."""
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.is_mount():
        fail("refusing linked/mounted removal target")
    for current, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            target = Path(current) / name
            if target.is_symlink() or target.is_mount():
                fail("refusing to delete tree containing symlink or mount")


def managed_dir(path, marker, *, create=False):
    if create and not path.exists():
        path.mkdir(mode=0o755, parents=True)
    safe_directory(path)
    owner_marker = path / marker
    if not owner_marker.exists():
        if not create:
            fail(f"missing ownership marker: {path}")
        # Refuse adopting an unrelated preexisting directory with content.
        if any(path.iterdir()):
            fail(f"nonempty unmanaged installation directory: {path}")
        write_exclusive(owner_marker, MARKER_VALUE)
    safe_file(owner_marker, private=True)
    if owner_marker.read_text() != MARKER_VALUE:
        fail("ownership marker mismatch")


def atomic_symlink(target, link):
    temp = Path(str(link) + ".new." + str(os.getpid()))
    os.symlink(target, temp)
    try:
        os.replace(temp, link)
        sync_directory(link.parent)
    finally:
        temp.unlink(missing_ok=True)


def existing_release():
    link = INSTALL_ROOT / "current"
    if not link.exists() and not link.is_symlink():
        return None
    if not link.is_symlink():
        fail("current release pointer is not a symlink")
    target = os.readlink(link)
    if not re.fullmatch(r"releases/[A-Za-z0-9][A-Za-z0-9._-]{0,63}", target):
        fail("current release pointer is outside managed releases")
    if not (INSTALL_ROOT / target).is_dir():
        fail("current release pointer is broken")
    return target


def service_unit(env_path):
    if any(c in str(env_path) for c in "\r\n %\\\"'"):
        fail("unsafe native environment path")
    return f"""{UNIT_MARKER}
[Unit]
Description=Launcher API (DEP09 managed)
Wants=network-online.target
After=network-online.target postgresql.service

[Service]
Type=simple
User=launcher
Group=launcher
WorkingDirectory=/var/lib/launcher
EnvironmentFile={env_path}
ExecStart=/opt/launcher/current/bin/launcher-api
Restart=on-failure
RestartSec=5
TimeoutStopSec=40
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=/var/lib/launcher
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
"""


def health_check(url):
    if url != "http://127.0.0.1:8080/ready":
        fail("native health check only supports fixed loopback /ready endpoint")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    for _ in range(15):
        try:
            with opener.open(urllib.request.Request(url), timeout=2) as resp:
                if resp.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    fail("native readiness check failed; refusing successful activation")


def native_install(args):
    require_root()
    if safe_file(args.env, private=True).st_uid != 0:
        fail("native environment must be root-owned")
    values = read_env(Path(args.env))
    preflight(values, "standard", docker=False)
    binary_info = safe_file(args.installer, executable=True)
    key_info = safe_file(args.trusted_key)
    if binary_info.st_uid != 0 or key_info.st_uid != 0:
        fail("trusted installer and pinned public key must be root-owned")
    safe_file(args.bundle)
    with exclusive_lock(Path("/run/launcher-deploy.lock")):
        # Never replace unmanaged systemd units.
        if UNIT.exists() and UNIT_MARKER not in UNIT.read_text():
            fail("systemd unit is not managed by DEP09")
        managed_dir(INSTALL_ROOT, OWNER, create=True)
        releases = INSTALL_ROOT / "releases"
        releases.mkdir(mode=0o755, exist_ok=True)
        safe_directory(releases)
        old = existing_release()
        if old and (not args.upgrade or not args.backup_confirmed):
            fail(
                "upgrade requires --upgrade and --backup-confirmed (verify backups independently)"
            )
        verified = execute(
            [
                args.installer,
                "verify",
                "--bundle",
                args.bundle,
                "--trusted-key",
                args.trusted_key,
            ],
            capture=True,
        )
        matched = VERSION_RE.search(verified.stdout or "")
        if not matched:
            fail("trusted installer did not report signed bundle version")
        version = matched.group(1)
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or tuple(
            map(int, version.split("."))
        ) < (0, 32, 13):
            fail("DEP09 requires a signed release version 0.32.13 or later")
        if old and tuple(map(int, version.split("."))) <= tuple(
            map(int, old.split("/")[1].split("."))
        ):
            fail("native upgrade version must increase monotonically")
        target = releases / version
        if target.exists() or target.is_symlink():
            fail("signed release directory already exists (no overwrite)")
        execute(
            [
                args.installer,
                "install",
                "--bundle",
                args.bundle,
                "--trusted-key",
                args.trusted_key,
                "--target",
                target,
            ]
        )
        binary = target / "bin/launcher-api"
        safe_file(binary, executable=True)
        # Only the dedicated API user may write durable state, not binaries/secrets.
        if not STATE_ROOT.exists():
            STATE_ROOT.mkdir(mode=0o700)
            write_exclusive(STATE_ROOT / DATA_MARKER, MARKER_VALUE)
        safe_directory(STATE_ROOT)
        if not (STATE_ROOT / DATA_MARKER).exists():
            fail("refusing unmanaged state directory")
        safe_file(STATE_ROOT / DATA_MARKER, private=True)
        if (STATE_ROOT / DATA_MARKER).read_text() != MARKER_VALUE:
            fail("state marker mismatch")
        if execute(["id", "-u", "launcher"], capture=True, check=False).returncode:
            execute(
                [
                    "useradd",
                    "--system",
                    "--home-dir",
                    str(STATE_ROOT),
                    "--shell",
                    "/usr/sbin/nologin",
                    "launcher",
                ]
            )
        identity = pwd.getpwnam("launcher")
        os.chown(STATE_ROOT, identity.pw_uid, identity.pw_gid)
        os.chmod(STATE_ROOT, 0o700)
        # Provision runtime paths; no implicit writes outside the managed data root.
        data_paths = [
            STATE_ROOT / p
            for p in ("storage", "backups", "coordinator", "extensions", "factory")
        ]
        for name in (
            "NEVERLAUNCHER_STORAGE_LOCAL_PATH",
            "NEVERLAUNCHER_BACKUP_ROOT",
            "NEVERLAUNCHER_EXTENSION_ROOT",
            "NEVERLAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH",
        ):
            value = values.get(name, "")
            if name.endswith("SQLITE_PATH"):
                value = str(Path(value).parent) if value else ""
            if value:
                directory = Path(value)
                if not directory.is_absolute() or STATE_ROOT not in directory.parents:
                    fail(
                        f"{name} must be inside managed state root for native installation"
                    )
                data_paths.append(directory)
        for directory in data_paths:
            cursor = directory
            missing = []
            while cursor != STATE_ROOT and not cursor.exists():
                missing.append(cursor)
                cursor = cursor.parent
            if cursor != STATE_ROOT and not (
                cursor.is_dir() and STATE_ROOT in cursor.parents
            ):
                fail("unsafe runtime path")
            for path in reversed(missing):
                path.mkdir(mode=0o700)
                os.chown(path, identity.pw_uid, identity.pw_gid)
            safe_directory(directory)
            if directory.stat().st_uid != identity.pw_uid:
                fail(f"runtime directory not owned by service user: {directory}")
        # A managed first install must not collide with a third-party unit.
        old_unit = UNIT.read_text() if UNIT.exists() else None
        if (
            execute(
                ["systemctl", "is-active", "--quiet", UNIT_NAME], check=False
            ).returncode
            == 0
        ):
            execute(["systemctl", "stop", UNIT_NAME])
        try:
            atomic_text(UNIT, service_unit(Path(args.env)), 0o644)
            atomic_symlink("releases/" + version, INSTALL_ROOT / "current")
            execute(["systemctl", "daemon-reload"])
            execute(["systemctl", "enable", "--now", UNIT_NAME])
            health_check("http://127.0.0.1:8080/ready")
        except BaseException:
            execute(["systemctl", "stop", UNIT_NAME], check=False)
            if old is not None:
                atomic_symlink(old, INSTALL_ROOT / "current")
            else:
                (INSTALL_ROOT / "current").unlink(missing_ok=True)
            if old_unit is not None:
                atomic_text(UNIT, old_unit)
            else:
                UNIT.unlink(missing_ok=True)
            execute(["systemctl", "daemon-reload"], check=False)
            if old is not None:
                execute(["systemctl", "start", UNIT_NAME], check=False)
            raise
        print(
            "Launcher 0.32.13 native service activated; old release retained for rollback"
        )


def native_uninstall(args):
    require_root()
    with exclusive_lock(Path("/run/launcher-deploy.lock")):
        managed_dir(INSTALL_ROOT, OWNER)
        if args.purge_data:
            safe_directory(STATE_ROOT)
            safe_file(STATE_ROOT / DATA_MARKER, private=True)
            if (STATE_ROOT / DATA_MARKER).read_text() != MARKER_VALUE:
                fail("state marker mismatch")
            no_symlinks_or_mounts(STATE_ROOT)
        if UNIT.exists():
            safe_file(UNIT)
            if UNIT_MARKER not in UNIT.read_text():
                fail("refusing to remove foreign systemd unit")
            execute(["systemctl", "disable", "--now", UNIT_NAME])
            UNIT.unlink()
            execute(["systemctl", "daemon-reload"])
        previous = existing_release()
        link = INSTALL_ROOT / "current"
        if previous:
            link.unlink()
        releases = INSTALL_ROOT / "releases"
        if releases.exists():
            no_symlinks_or_mounts(releases)
            shutil.rmtree(releases)
        (INSTALL_ROOT / OWNER).unlink()
        # Preserve unexpected files instead of deleting operator data.
        if not any(INSTALL_ROOT.iterdir()):
            INSTALL_ROOT.rmdir()
        if args.purge_data:
            if args.confirm != "PURGE-NEVERLAUNCHER-NATIVE-DATA":
                fail("purge requires --confirm PURGE-NEVERLAUNCHER-NATIVE-DATA")
            shutil.rmtree(STATE_ROOT)
        print(
            "Native service removed; external PostgreSQL and /etc secrets untouched; "
            + (
                "local application data deleted"
                if args.purge_data
                else "local application data retained"
            )
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="provider", required=True)
    cp = sub.add_parser("compose")
    cp.add_argument("action", choices=["check", "up", "status", "down", "uninstall"])
    cp.add_argument("--env", default=str(COMPOSE.parent / ".env"))
    cp.add_argument("--mode", required=True, choices=["standard", "network-ha"])
    cp.add_argument(
        "--backup-confirmed",
        action="store_true",
        help="operator has verified external DB/blob backup before image upgrade",
    )
    cp.add_argument("--purge-data", action="store_true")
    cp.add_argument("--confirm", default="")
    np = sub.add_parser("native")
    np.add_argument("action", choices=["install", "uninstall"])
    np.add_argument("--installer", default="/usr/local/bin/launcher-install")
    np.add_argument("--bundle")
    np.add_argument("--trusted-key")
    np.add_argument("--env", default=str(ENV_NATIVE))
    np.add_argument("--upgrade", action="store_true")
    np.add_argument("--backup-confirmed", action="store_true")
    np.add_argument("--purge-data", action="store_true")
    np.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    if args.provider == "compose":
        if args.purge_data and args.action != "uninstall":
            fail("--purge-data allowed only with uninstall")
        compose_run(args)
    elif args.action == "install":
        if not args.bundle or not args.trusted_key:
            fail("native install requires --bundle and independent --trusted-key")
        native_install(args)
    else:
        # Check destructive confirmation BEFORE any service or file mutation.
        if args.purge_data and args.confirm != "PURGE-NEVERLAUNCHER-NATIVE-DATA":
            fail("purge requires --confirm PURGE-NEVERLAUNCHER-NATIVE-DATA")
        native_uninstall(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as e:
        print("launcher-deploy:", e, file=sys.stderr)
        sys.exit(1)

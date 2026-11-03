#!/usr/bin/env python3
"""Launcher 0.32.13 DEP09 production deployment (Linux).

Standard Compose = PostgreSQL + SQLite coordinator, Redis optional.
Native = signed installer bundle + root-owned release + systemd.
No production SQLite-only backend or automatic live SQLite->PostgreSQL cutover.
"""

import argparse
import contextlib
import email.utils
import hashlib
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
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


def preflight(values, mode, *, docker, tls_required=True):
    needed = [
        "LAUNCHER_PUBLIC_URL",
        "LAUNCHER_AUTH_TOKEN_SECRET",
        "LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY",
        "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON",
        "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON",
        "LAUNCHER_WEBAUTHN_RP_ID",
        "LAUNCHER_WEBAUTHN_ORIGINS",
        "LAUNCHER_CORS_ALLOWED_ORIGINS",
    ]
    if docker:
        needed += ["POSTGRES_PASSWORD", "LAUNCHER_IMAGE_TAG"]
        if tls_required:
            needed += ["LAUNCHER_TLS_CERT_PATH", "LAUNCHER_TLS_KEY_PATH"]
        if mode == "network-ha":
            needed += [
                "REDIS_PASSWORD",
                "LAUNCHER_REPLICA_ID",
                "LAUNCHER_STORAGE_S3_ENDPOINT",
                "LAUNCHER_STORAGE_S3_BUCKET",
                "LAUNCHER_STORAGE_S3_REGION",
                "LAUNCHER_STORAGE_S3_ACCESS_KEY",
                "LAUNCHER_STORAGE_S3_SECRET_KEY",
            ]
    else:
        needed.append("LAUNCHER_DATABASE_DSN")
    missing = [
        key
        for key in needed
        if not values.get(key)
        or values[key].upper().startswith(("CHANGE_ME", "REPLACE_ME"))
    ]
    if missing:
        fail("missing or placeholder production configuration: " + ", ".join(missing))
    public = values["LAUNCHER_PUBLIC_URL"]
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
    if docker and url.port not in (None, 443):
        fail("direct production Compose requires public HTTPS on port 443")
    if values["LAUNCHER_WEBAUTHN_ORIGINS"] != public or public not in values[
        "LAUNCHER_CORS_ALLOWED_ORIGINS"
    ].split(","):
        fail("WebAuthn origins and CORS must contain the exact HTTPS public origin")
    rp = values["LAUNCHER_WEBAUTHN_RP_ID"].lower()
    hostname = url.hostname.lower()
    if not (hostname == rp or hostname.endswith("." + rp)):
        fail("WebAuthn relying-party ID does not match public hostname")
    for key in (
        "LAUNCHER_GUARD_RELEASE_ALLOWLIST_JSON",
        "LAUNCHER_BRIDGE_RELEASE_ALLOWLIST_JSON",
    ):
        try:
            policy = json.loads(values[key])
        except ValueError:
            fail(f"{key} must contain a nonempty JSON policy")
        if not isinstance(policy, (list, dict)) or not policy:
            fail(f"{key} must contain a nonempty JSON policy")
    if len(values["LAUNCHER_AUTH_TOKEN_SECRET"]) < 32:
        fail("authentication signing secret is too short")
    if not re.fullmatch(
        r"[0-9a-fA-F]{64}", values["LAUNCHER_MANIFEST_SIGNING_PRIVATE_KEY"]
    ):
        fail("manifest signing key must be a 32-byte hex Ed25519 seed")
    if docker:
        compose_project(values)
        for key in ("POSTGRES_PASSWORD", "REDIS_PASSWORD"):
            if key == "REDIS_PASSWORD" and mode != "network-ha":
                continue
            if not re.fullmatch(r"[A-Za-z0-9._~-]{24,}", values[key]):
                fail(f"{key} must be URL-safe and at least 24 characters")
    if not docker and values.get("LAUNCHER_REPOSITORY_DRIVER") != "postgres":
        fail(
            "native Backend must use PostgreSQL; SQLite-only HTTP repository is unsupported"
        )
    if not docker and not values.get("LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH"):
        fail("native Standard requires a durable SQLite coordinator")
    if (
        mode == "standard"
        and values.get("LAUNCHER_SERVERBRIDGE_HA_REQUIRED", "").lower() == "true"
    ):
        fail("Standard mode cannot require HA")
    if values.get("LAUNCHER_DEPLOYMENT_MODE", mode) not in ("", mode):
        fail("env deployment mode conflicts with selected mode")
    if mode == "network-ha" and not docker:
        fail("native HA provisioning is not supported by this local-service installer")




def host_preflight(*, fresh):
    """Validate the actual Linux host and Docker daemon before manipulating data."""
    if sys.platform != "linux" or os.uname().machine.lower() not in (
        "x86_64", "amd64", "aarch64", "arm64"
    ):
        fail("production Compose requires Linux x64 or ARM64")
    if os.geteuid() != 0:
        fail("production Compose preflight must run as root to read TLS keys")
    if not shutil.which("docker"):
        fail("Docker Engine and Compose v2 are required")
    result = execute(["docker", "info", "--format", "{{.DockerRootDir}}"], capture=True)
    docker_root = (result.stdout or "").strip()
    if not docker_root or not Path(docker_root).is_absolute() or not Path(docker_root).is_dir():
        fail("cannot determine an accessible Docker data directory")
    execute(["docker", "compose", "version"], capture=True)
    meminfo = Path("/proc/meminfo").read_text()
    match = re.search(r"^MemTotal:\s+(\d+) kB$", meminfo, re.M)
    if not match or int(match.group(1)) < 2 * 1024 * 1024:
        fail("production host requires at least 2 GiB RAM")
    if shutil.disk_usage(docker_root).free < 8 * 1024 ** 3:
        fail("Docker filesystem needs at least 8 GiB free for first-run builds")
    if fresh:
        for port in (80, 443):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.bind(("0.0.0.0", port))
                except OSError:
                    fail(f"port {port} is already occupied; clean-host preflight failed")


def tls_paths(values):
    """Verify actual trust-chain, hostname, expiry and private-key match before Compose."""
    cert = Path(values["LAUNCHER_TLS_CERT_PATH"])
    key = Path(values["LAUNCHER_TLS_KEY_PATH"])
    if not cert.is_absolute() or not key.is_absolute() or cert == key:
        fail("TLS certificate and key must have different absolute host paths")
    if cert.is_symlink() or key.is_symlink():
        fail("TLS files must not be symlinks (copy the ACME files with install)")
    for path, private in ((cert, False), (key, True)):
        safe_file(path, private=private)
        if path.stat().st_size > 1024 * 1024 or path.stat().st_size == 0:
            fail("TLS file is empty or too large")
    if key.stat().st_uid != 0:
        fail("TLS private key must be root-owned")
    hostname = urllib.parse.urlsplit(values["LAUNCHER_PUBLIC_URL"]).hostname

    def openssl(*argv):
        try:
            proc = subprocess.run(["openssl", *map(str, argv)], capture_output=True,
                                  check=False, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            fail("openssl is required and must complete certificate validation")
        if proc.returncode:
            fail("TLS certificate is invalid, untrusted, expired, mismatched or has the wrong hostname")
        return proc.stdout

    openssl("x509", "-in", cert, "-noout", "-checkhost", hostname)
    openssl("x509", "-in", cert, "-noout", "-checkend", "604800")
    openssl("verify", "-CApath", "/etc/ssl/certs", "-untrusted", cert, cert)
    leaf_public = openssl("x509", "-in", cert, "-pubkey", "-noout")
    key_public = openssl("pkey", "-in", key, "-pubout")
    if hashlib.sha256(leaf_public).digest() != hashlib.sha256(key_public).digest():
        fail("TLS private key does not match the certificate")


def public_json(url, *, payload=None, headers=None, expected_status=None):
    """No proxies, redirects, insecure TLS, implicit retries or credential output."""
    if urllib.parse.urlsplit(url).scheme != "https":
        fail("refusing public operation without HTTPS")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *unused):
            return None

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect(),
    )
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url, data=body,
        headers={"Accept": "application/json", **({"Content-Type": "application/json"} if body else {}), **(headers or {})},
        method="POST" if body is not None else "GET",
    )
    try:
        with opener.open(request, timeout=12) as response:
            if response.status != (expected_status if expected_status is not None else (201 if body is not None else 200)):
                fail(f"public endpoint rejected operation (HTTP {response.status})")
            content = response.read(1024 * 1024 + 1)
            if len(content) > 1024 * 1024:
                fail("unexpectedly large public API response")
            return json.loads(content)
    except urllib.error.HTTPError as exc:
        # Never print response bodies: they can contain reflected secrets.
        fail(f"public API returned HTTP {exc.code}; inspect server audit securely")
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        fail(f"public HTTPS unavailable or untrusted ({type(exc).__name__})")
    except (UnicodeError, json.JSONDecodeError):
        fail("public API returned invalid JSON")


def verify_public_ready(values, expected_version=None):
    public = values["LAUNCHER_PUBLIC_URL"].rstrip("/")
    status = public_json(public + "/ready")
    if status.get("status") != "ready":
        fail("public HTTPS /ready is not ready")
    if expected_version is not None and status.get("version") != expected_version:
        fail("live API version does not match selected release image")
    return status


def bootstrap_first_admin(args):
    """Actually create, authenticate and verify the one-time admin on running API."""
    env = Path(args.env).resolve(strict=True)
    safe_file(env, private=True)
    safe_directory(env.parent)
    values = read_env(env)
    preflight(values, "standard", docker=True)
    tls_paths(values)
    if not values.get("LAUNCHER_BOOTSTRAP_TOKEN") or len(values["LAUNCHER_BOOTSTRAP_TOKEN"]) < 32:
        fail("first admin requires a strong LAUNCHER_BOOTSTRAP_TOKEN in private env")
    address = email.utils.parseaddr(args.email)
    if address[1] != args.email or "@" not in args.email or len(args.email) > 254 or any(c.isspace() for c in args.email):
        fail("invalid administrator email")
    password_file = Path(args.password_file)
    info = safe_file(password_file, private=True)
    if info.st_uid != os.geteuid() or info.st_size > 4096 or info.st_size < 12:
        fail("admin password file must be owned by invoking user and have 12-4096 bytes")
    password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
    if len(password) < 12 or any(c in password for c in "\r\n\x00"):
        fail("administrator password must be at least 12 characters, single-line")
    public = values["LAUNCHER_PUBLIC_URL"].rstrip("/")
    with exclusive_lock(env.parent / ".launcher-compose.lock"):
        state_file = env.parent / ".launcher-compose-state.json"
        safe_file(state_file, private=True)
        state = json.loads(state_file.read_text())
        if state != {"mode": "standard", "version": values["LAUNCHER_IMAGE_TAG"]}:
            fail("first-admin requires matching locally installed Standard Compose state")
        verify_public_ready(values, values["LAUNCHER_IMAGE_TAG"])
        before = public_json(public + "/api/v1/install/readiness").get("data", {})
        if before.get("bootstrapTokenConsumed") or any(
            c.get("id") == "admin-user" and c.get("status") == "ready"
            for c in before.get("checks", [])
        ):
            fail("bootstrap already consumed or administrator exists; not retrying")
        response = public_json(
            public + "/api/v1/install/bootstrap-admin",
            payload={"email": args.email, "displayName": args.display_name,
                     "password": password, "actor": "production-deploy 0.45.1"},
            headers={"X-Launcher-Bootstrap-Token": values["LAUNCHER_BOOTSTRAP_TOKEN"]},
        )
        if response.get("data", {}).get("status") != "admin-created" or response.get("data", {}).get("email") != args.email:
            fail("API did not confirm creation of the requested administrator")
        after = public_json(public + "/api/v1/install/readiness").get("data", {})
        if not after.get("bootstrapTokenConsumed") or not any(
            c.get("id") == "admin-user" and c.get("status") == "ready"
            for c in after.get("checks", [])
        ):
            fail("administrator creation is not durable in installation status")
        # A real authenticated login proves the password and local auth backend work.
        login = public_json(public + "/api/v1/admin/login", payload={"email": args.email, "password": password}, expected_status=200)
        if not login.get("token") or login.get("user", {}).get("email") != args.email:
            fail("administrator was created but a real password login did not succeed")
        print("First administrator created, bootstrap token consumed, login verified over trusted HTTPS")
        print("Remove the password file securely; log in to Admin and create the first project")


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


def compose_project(values):
    # Namespacing prevents an isolated acceptance deployment from touching the
    # ordinary production project's containers, networks or named volumes.
    project = values.get("LAUNCHER_COMPOSE_PROJECT", "launcher")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{2,40}", project):
        fail("invalid LAUNCHER_COMPOSE_PROJECT (lowercase Docker Compose project)")
    return project


def compose_args(env, mode):
    project = compose_project(read_env(env))
    args = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--env-file",
        str(env),
        "-f",
        str(COMPOSE),
    ]
    if mode == "network-ha":
        args += ["-f", str(HA), "--profile", "network-ha"]
    values = read_env(env)
    if any(key.startswith("LAUNCHER_0523_HOST_") for key in values):
        if mode != "standard" or not re.fullmatch(r"nl0523[a-z0-9]{8,20}", project):
            fail("0523 host-control integration may only run in an isolated Standard project")
        for key in ("LAUNCHER_0523_HOST_TARGETS_FILE", "LAUNCHER_0523_HOST_CA_FILE", "LAUNCHER_0523_HOST_TOKEN_FILE"):
            value = values.get(key, "")
            if not value or not Path(value).is_absolute():
                fail("missing absolute 0523 host-control trust file: " + key)
            safe_file(value, private=True)
        args += ["-f", str(ROOT / "deploy/production/docker-compose.owner-e2e-0523.yml")]
    return args


def compose_run(args):
    env = Path(args.env).resolve(strict=True)
    safe_file(env, private=True)
    safe_directory(env.parent)
    values = read_env(env)
    mode = args.mode
    preflight(values, mode, docker=True, tls_required=args.action in ("check", "up"))
    state_file = env.parent / ".launcher-compose-state.json"
    with exclusive_lock(env.parent / ".launcher-compose.lock"):
        if args.action in ("check", "up"):
            tls_paths(values)
        state = {}
        if state_file.exists():
            safe_file(state_file, private=True)
            state = json.loads(state_file.read_text())
        if state and state.get("mode") != mode:
            fail("deployment mode changed; uninstall old mode first (volumes retained)")
        if args.action in ("check", "up"):
            host_preflight(fresh=not bool(state))
        if (
            args.action == "up"
            and state
            and state.get("version") != values["LAUNCHER_IMAGE_TAG"]
            and not args.backup_confirmed
        ):
            fail(
                "upgrade requires --backup-confirmed after verified database and blob backups"
            )
        if args.action == "up" and not state and len(values.get("LAUNCHER_BOOTSTRAP_TOKEN", "")) < 32:
            fail("fresh production deployment requires a strong one-time LAUNCHER_BOOTSTRAP_TOKEN")
        base = compose_args(env, mode)
        if args.action == "check":
            execute(base + ["config", "--quiet"])
            print(f"Compose {mode} configuration valid")
        elif args.action == "up":
            execute(base + ["config", "--quiet"])
            execute(
                base
                + ["up", "--build", "-d", "--wait", "--wait-timeout", "120", "--remove-orphans"]
            )
            verify_public_ready(values, values["LAUNCHER_IMAGE_TAG"])
            atomic_text(
                state_file,
                json.dumps({"mode": mode, "version": values["LAUNCHER_IMAGE_TAG"]})
                + "\n",
                0o600,
            )
            print("Compose started: real backend ready through trusted public HTTPS; first administrator still needs bootstrap")
        elif args.action == "status":
            execute(base + ["ps"])
        elif args.action in ("down", "uninstall"):
            if args.action == "uninstall" and args.purge_data:
                if args.confirm != "PURGE-LAUNCHER-VOLUMES":
                    fail("purge requires --confirm PURGE-LAUNCHER-VOLUMES")
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
            "LAUNCHER_STORAGE_LOCAL_PATH",
            "LAUNCHER_BACKUP_ROOT",
            "LAUNCHER_EXTENSION_ROOT",
            "LAUNCHER_SINGLE_NODE_COORDINATOR_SQLITE_PATH",
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
            if args.confirm != "PURGE-LAUNCHER-NATIVE-DATA":
                fail("purge requires --confirm PURGE-LAUNCHER-NATIVE-DATA")
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
    cp.add_argument("action", choices=["check", "up", "status", "down", "uninstall", "first-admin"])
    cp.add_argument("--env", default=str(COMPOSE.parent / ".env"))
    cp.add_argument("--mode", required=True, choices=["standard", "network-ha"])
    cp.add_argument(
        "--backup-confirmed",
        action="store_true",
        help="operator has verified external DB/blob backup before image upgrade",
    )
    cp.add_argument("--purge-data", action="store_true")
    cp.add_argument("--confirm", default="")
    cp.add_argument("--email", help="first administrator email")
    cp.add_argument("--display-name", default="Administrator")
    cp.add_argument("--password-file", help="private mode-0600 file holding initial admin password")
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
        if args.action == "first-admin":
            if args.mode != "standard" or not args.email or not args.password_file:
                fail("compose first-admin requires --mode standard, --email and --password-file")
            bootstrap_first_admin(args)
        else:
            compose_run(args)
    elif args.action == "install":
        if not args.bundle or not args.trusted_key:
            fail("native install requires --bundle and independent --trusted-key")
        native_install(args)
    else:
        # Check destructive confirmation BEFORE any service or file mutation.
        if args.purge_data and args.confirm != "PURGE-LAUNCHER-NATIVE-DATA":
            fail("purge requires --confirm PURGE-LAUNCHER-NATIVE-DATA")
        native_uninstall(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as e:
        print("launcher-deploy:", e, file=sys.stderr)
        sys.exit(1)

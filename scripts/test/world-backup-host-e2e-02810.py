import argparse, json, os, pathlib, shutil, subprocess, tempfile, time

parser = argparse.ArgumentParser()
parser.add_argument("--cli", required=True, help="path to built nl CLI executable")
nl = str(pathlib.Path(parser.parse_args().cli).resolve())
base = pathlib.Path(tempfile.mkdtemp(prefix="nl-world-e2e-"))
root = base / "server"
root.mkdir()
(root / "paper.jar").write_bytes(b"fixture")
(root / "server.properties").write_text("level-name=world\n")
(root / "world" / "playerdata").mkdir(parents=True)
(root / "plugins" / "Essentials" / "userdata").mkdir(parents=True)
(root / "plugins" / "Essentials" / "userdata" / "uuid.yml").write_text("balance: 42\n")
(root / "world" / "playerdata" / "uuid.dat").write_bytes(b"inventory")
java = root / "java"
java.write_text("""#!/bin/sh
if [ "$1" = "-version" ]; then echo 'openjdk version "21.0.1"' >&2; exit 0; fi
while IFS= read -r cmd; do
 if [ "$cmd" = "stop" ]; then echo "saved from Minecraft stop" > world/level.dat; exit 0; fi
done
exit 5
""")
java.chmod(0o755)
store = base / "backups"
dest = base / "restored"
cmd = lambda *a: subprocess.run(
    [nl, *a], capture_output=True, text=True, timeout=45, check=True
)
cmd(
    "server-bridge",
    "host",
    "configure",
    "--server-root",
    str(root),
    "--platform",
    "paper",
    "--server-jar",
    "paper.jar",
    "--java",
    str(java),
    "--restart-policy",
    "never",
)
run = subprocess.Popen(
    [nl, "server-bridge", "host", "run", "--server-root", str(root)],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
try:
    runtime = root / ".launcher/server-bridge/host/runtime.json"
    deadline = time.time() + 8
    while time.time() < deadline:
        if runtime.exists():
            state = json.loads(runtime.read_text())
            if state.get("status") == "running":
                break
        time.sleep(0.05)
    else:
        raise RuntimeError("host never started")
    create = cmd(
        "server-bridge",
        "host",
        "world-backup",
        "create",
        "--server-root",
        str(root),
        "--backup-root",
        str(store),
        "--consistency",
        "stop",
    )
    payload = json.loads(create.stdout)
    bid = payload["manifest"]["id"]
    assert (
        store / bid / "payload/world/level.dat"
    ).read_text() == "saved from Minecraft stop\n"
    assert run.wait(timeout=8) == 0
    cmd(
        "server-bridge",
        "host",
        "world-backup",
        "verify",
        "--server-root",
        str(root),
        "--backup-root",
        str(store),
        "--id",
        bid,
    )
    cmd(
        "server-bridge",
        "host",
        "world-backup",
        "restore",
        "--server-root",
        str(root),
        "--backup-root",
        str(store),
        "--id",
        bid,
        "--confirm",
        bid,
        "--destination",
        str(dest),
    )
    assert (dest / "world/playerdata/uuid.dat").read_bytes() == b"inventory"
    assert (
        dest / "plugins/Essentials/userdata/uuid.yml"
    ).read_text() == "balance: 42\n"
    assert (dest / "world/level.dat").read_text() == "saved from Minecraft stop\n"
    print(
        "PASS actual CLI + POSIX child process graceful stop -> backup SHA-256 -> verify -> isolated restore; backup ID",
        bid,
    )
finally:
    if run.poll() is None:
        run.terminate()
    try:
        run.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        run.kill()
        run.communicate()
    shutil.rmtree(base)

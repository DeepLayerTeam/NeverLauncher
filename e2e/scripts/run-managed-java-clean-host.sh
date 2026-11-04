#!/usr/bin/env bash
# Execute against a built Runtime binary and an authentic, pinned Temurin
# distribution. Unlike fixture-only probes, this installs and runs the JVM
# with no java executable available through PATH, then repairs it offline.
set -euo pipefail
if (( $# != 4 )); then
  echo "Usage: $0 /absolute/path/runtime /path/MANAGED_JRE_MANIFEST.json SHA256 MAJOR" >&2
  exit 64
fi
runtime="$(realpath "$1")"
manifest="$(realpath "$2")"
digest="$3"
major="$4"
[[ -x "$runtime" && -f "$manifest" ]] || { echo 'runtime binary or manifest missing' >&2; exit 1; }
[[ "$digest" =~ ^[0-9a-fA-F]{64}$ ]] || { echo 'manifest digest must be SHA-256' >&2; exit 1; }
[[ "$major" =~ ^(8|16|17|21|25)$ ]] || { echo 'invalid Java major' >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/runtimes"
# Do not auto-discover a release manifest beside the original binary during
# the second, explicitly manifest-free cache recovery operation.
cp "$runtime" "$work/runtime"
chmod +x "$work/runtime"
runtime="$work/runtime"
# No system Java, javac or java home. tar and gzip are used only for extraction.
for executable in tar gzip; do
  source_bin="$(command -v "$executable")"
  ln -s "$source_bin" "$work/bin/$executable"
done
python="$(command -v python3)"
if [[ -n "$(PATH="$work/bin" command -v java 2>/dev/null || :)" ]]; then
  echo 'test PATH unexpectedly contains java' >&2
  exit 1
fi
run_ensure() {
  env -u JAVA_HOME -u JDK_JAVA_OPTIONS -u JAVA_TOOL_OPTIONS \
    PATH="$work/bin" LAUNCHER_OFFLINE=1 "$runtime" java ensure \
    --major "$major" --distribution temurin --runtime-root "$work/runtimes" \
    --manifest "$manifest" --manifest-sha256 "$digest" > "$work/result.json"
}
run_ensure
java_exe="$("$python" -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["status"]=="ready"; print(r["javaExecutable"])' "$work/result.json")"
[[ -x "$java_exe" ]] || { echo 'managed Java executable missing' >&2; exit 1; }
env -u JAVA_HOME PATH="$work/bin" "$java_exe" -version > "$work/java-version.log" 2>&1
# Force a damaged inventory and an interrupted extraction; the installer
# must quarantine the former, clean the latter, and restore the same JVM.
install_dir="$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["installDirectory"])' "$work/result.json")"
touch "$install_dir/UNEXPECTED_FILE"
mkdir -p "$(dirname "$install_dir")/.staging-dead-worker"
printf 'partial' > "$(dirname "$install_dir")/.staging-dead-worker/partial"
# No pinned manifest during recovery: force the unpinned but SHA-256-bound
# local archive repair path. Offline mode forbids network fallback.
env -u JAVA_HOME -u JDK_JAVA_OPTIONS -u JAVA_TOOL_OPTIONS \
  PATH="$work/bin" LAUNCHER_OFFLINE=1 "$runtime" java ensure \
  --major "$major" --distribution temurin --runtime-root "$work/runtimes" > "$work/result.json"
"$python" - "$work/result.json" <<'PY'
import json,sys
result=json.load(open(sys.argv[1]))
assert result['status']=='ready', result
assert not result['cached'], 'damaged Java must be reinstalled, not accepted as cache hit'
PY
[[ ! -e "$install_dir/UNEXPECTED_FILE" ]] || { echo 'broken runtime was not repaired' >&2; exit 1; }
[[ ! -e "$(dirname "$install_dir")/.staging-dead-worker" ]] || { echo 'stale staging was not removed' >&2; exit 1; }
# Final offline execution uses the verified managed JVM, never a host Java.
env -u JAVA_HOME PATH="$work/bin" "$java_exe" -version > "$work/recovered-version.log" 2>&1
printf 'Managed Java 0.40.7 clean-host install, corruption recovery and JVM execution: PASS\n'

#!/usr/bin/env bash
set -euo pipefail

certification_platform_validate() {
  local label="$1" os_name="$2" arch="$3" java_bin="$4"
  case "$os_name" in linux|windows|macos) ;; *) echo "[$label] unsupported target OS: $os_name" >&2; return 2 ;; esac
  case "$arch" in x86_64|aarch64) ;; *) echo "[$label] unsupported target architecture: $arch" >&2; return 2 ;; esac
  [[ -n "$java_bin" && -f "$java_bin" ]] || { echo "[$label] target Java executable is unavailable: $java_bin" >&2; return 2; }
  for cmd in go cargo python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "[$label] required command missing: $cmd" >&2; return 1; }
  done
  if [[ "$os_name" == "linux" ]]; then
    command -v xvfb-run >/dev/null 2>&1 || { echo "[$label] required command missing: xvfb-run" >&2; return 1; }
  fi
}

certification_exe_suffix() {
  [[ "$1" == "windows" ]] && printf '.exe' || true
}

certification_prepare_windows_sensor() {
  local target_os="$1" root="$2" runtime_bin="$3"
  [[ "$target_os" == "windows" ]] || return 0
  local sensor_manifest="$root/runtime/neverguard-sensor/Cargo.toml"
  local sensor_dll="$root/runtime/neverguard-sensor/target/debug/neverguard_sensor.dll"
  local destination="$(dirname "$runtime_bin")/neverguard-sensor.dll"
  cargo build --quiet --manifest-path "$sensor_manifest" --lib
  [[ -s "$sensor_dll" ]] || { echo "[certification] built NeverGuard Sensor DLL missing: $sensor_dll" >&2; return 1; }
  cp "$sensor_dll" "$destination"
  [[ -s "$destination" ]] || { echo "[certification] NeverGuard Sensor DLL copy failed" >&2; return 1; }
}

certification_run_client() {
  local os_name="$1" runtime_bin="$2" output="$3"
  shift 3
  if [[ "$os_name" == "linux" ]]; then
    export LIBGL_ALWAYS_SOFTWARE=1
    xvfb-run -a -s '-screen 0 1280x720x24 +extension GLX +render -noreset' "$runtime_bin" "$@" > "$output"
  elif [[ "$os_name" == "macos" && "${NEVERLAUNCHER_E2E_MINECRAFT_VERSION:-}" == "26.3" && ( "${NEVERLAUNCHER_E2E_LOADER:-}" == "fabric" || "${NEVERLAUNCHER_E2E_LOADER:-}" == "vanilla" ) ]]; then
    # Some hosted macOS Vanilla/Fabric 26.3 runs abort in SDL 3 before
    # creating a window. ForgeBootstrap uses a different first-thread mode.
    # Re-run the *real, verified* client once only when the first result proves
    # that exact native abort. No retry for JVM exceptions, security failures,
    # missing dependencies, normal exits, or other Minecraft/loader versions.
    local first_rc=0
    "$runtime_bin" "$@" > "$output" || first_rc=$?
    local client_root="$(dirname "$output")/materialized-client"
    local eligibility="$(dirname "$output")/../../scripts/compatibility/retry-macos-sdl3.py"
    if python3 "$eligibility" --report "$output" --client-root "$client_root"; then
      cp "$output" "${output%.json}.first-attempt.json"
      printf '[certification] macOS SDL 3 SIGABRT: repeat full %s client certification once\n' "${NEVERLAUNCHER_E2E_LOADER:-}" >&2
      local second_rc=0
      "$runtime_bin" "$@" > "$output" || second_rc=$?
      # Preserve the second report even when the native process fails again;
      # never leave an old, successful retry.json as evidence of a failed run.
      python3 - "$output" "${output%.json}.first-attempt.json" "$(dirname "$output")/certification-retry.json" <<'PYRETRY' 
import hashlib, json, sys
last, first, output = sys.argv[1:]
with open(first, 'rb') as f:
    first_bytes = f.read()
with open(last, 'rb') as f:
    final_bytes = f.read()
final = json.loads(final_bytes)
payload = {
  'schemaVersion': '1.0',
  'reason': 'macos-26.3-sdl3-sigabrt',
  'attempts': 2,
  'firstEvidenceSha256': hashlib.sha256(first_bytes).hexdigest(),
  'lastEvidenceSha256': hashlib.sha256(final_bytes).hexdigest(),
  'lastStatus': final.get('status'),
  'lastSuccess': final.get('status') == 'passed' and (
      final.get('success') is True or final.get('timedOut') is True),
}
with open(output, 'w', encoding='utf-8') as f:
    json.dump(payload, f, sort_keys=True, indent=2)
    f.write('\n')
if not payload['lastSuccess']:
    raise SystemExit('second macOS SDL 3 certification attempt did not pass')
PYRETRY
      return "$second_rc"
    else
      return "$first_rc"
    fi
  else
    "$runtime_bin" "$@" > "$output"
  fi
}

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
  else
    "$runtime_bin" "$@" > "$output"
  fi
}

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

certification_run_client() {
  local os_name="$1" runtime_bin="$2" output="$3"
  shift 3
  if [[ "$os_name" == "linux" ]]; then
    export LIBGL_ALWAYS_SOFTWARE=1
    xvfb-run -a -s '-screen 0 1280x720x24' "$runtime_bin" "$@" > "$output"
  else
    "$runtime_bin" "$@" > "$output"
  fi
}

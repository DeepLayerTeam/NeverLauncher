#!/usr/bin/env bash
# Реальный жизненный цикл локального Minecraft-сервера для обязательных проверок нативной
# совместимости. Используется в пяти сценариях сертификации установленных клиентов.

certification_live_cleanup() {
  if [[ -n "${LIVE_JOIN_DAEMON_PID:-}" ]]; then
    # Координатор должен остановить настоящую JVM и закрыть окончательный журнал сервера,
    # прежде чем привязать квитанции по SHA-256. Межплатформенный маркер остановки работает
    # и в Windows Git Bash, где SIGTERM может обойти блоки finally Python.
    : > "$ROOT/e2e/runtime/live-server-stop.request"
    local attempt
    for ((attempt=0;attempt<120;attempt++)); do
      kill -0 "$LIVE_JOIN_DAEMON_PID" 2>/dev/null || break
      sleep 0.25
    done
    if kill -0 "$LIVE_JOIN_DAEMON_PID" 2>/dev/null; then
      kill "$LIVE_JOIN_DAEMON_PID" 2>/dev/null || true
    fi
    wait "$LIVE_JOIN_DAEMON_PID" 2>/dev/null || true
    unset LIVE_JOIN_DAEMON_PID
  fi
}

certification_live_start() {
  local loader="$1" resolved="$2" cli="$3" profile_root="$4"
  local root="$ROOT/e2e/runtime"
  local -a args=(serve --runtime "$root" --target "$TARGET_ID" --minecraft "$MINECRAFT_VERSION"
    --loader "$loader" --loader-version "$resolved" --java "$JAVA_BIN" --cli "$cli"
    --pins "${LAUNCHER_E2E_SERVER_PINS:-}" --bundle-dir "${LAUNCHER_E2E_SERVER_BUNDLE_DIR:-}")
  # Не используйте старую квитанцию и не оставляйте предыдущий сервер в повторно используемом рабочем каталоге.
  [[ ! -e "$root/live-server-ready.json" && ! -e "$root/live-server-witness.json" && ! -e "$root/live-server-stopped.json" && ! -e "$root/live-server-stop.request" && ! -e "$root/live-join.json" ]] || {
    echo '[live-join] stale matching-server receipt' >&2; return 2;
  }
  python3 "$ROOT/e2e/scripts/live_join_0524.py" "${args[@]}" > "$root/live-server-execution.log" 2>&1 &
  LIVE_JOIN_DAEMON_PID=$!
  trap certification_live_cleanup EXIT
  local attempt
  for ((attempt=0;attempt<480;attempt++)); do
    if [[ -s "$root/live-server-ready.json" ]]; then break; fi
    if ! kill -0 "$LIVE_JOIN_DAEMON_PID" 2>/dev/null; then
      cat "$root/live-server-execution.log" >&2; echo '[live-join] dedicated server startup failed' >&2; return 3;
    fi
    sleep 0.5
  done
  [[ -s "$root/live-server-ready.json" ]] || { echo '[live-join] no dedicated server readiness' >&2; return 3; }
  LIVE_JOIN_SERVER_PORT="$(python3 - "$root/live-server-ready.json" "$TARGET_ID" <<'PY'
import json,sys
ready=json.load(open(sys.argv[1],encoding='utf-8'))
p=ready.get('port')
if ready.get('targetId') != sys.argv[2] or type(p) is not int or not 1 <= p <= 65535:
    raise SystemExit('invalid dedicated server port/identity')
print(p)
PY
)" || return 3
  # Настраивайте только этот одноразовый корневой каталог клиента. Это предотвращает предупреждение
  # Minecraft о мультиплеере при первом запуске, которое мешало бы Quick Play даже при доступном сервере.
  if [[ ! -e "$profile_root/options.txt" ]]; then
    cat > "$profile_root/options.txt" <<'OPTIONS'
onboardAccessibility:false
skipMultiplayerWarning:true
joinedFirstServer:true
pauseOnLostFocus:false
OPTIONS
  fi
}

certification_live_finish() {
  local loader="$1" resolved="$2" profile="$3"
  local root="$ROOT/e2e/runtime"
  # Runtime завершился; запечатывайте журнал сервера только после остановки
  # выделенной JVM, иначе поздние строки завершения нарушат его SHA-256.
  [[ -s "$root/live-server-witness.json" ]] || {
    echo '[live-join] no contemporaneous client-online RCON witness' >&2
    return 3
  }
  certification_live_cleanup
  [[ -s "$root/live-server-stopped.json" ]] || {
    echo '[live-join] dedicated JVM was not alive at orderly shutdown' >&2
    return 3
  }
  python3 "$ROOT/e2e/scripts/live_join_0524.py" verify \
    --runtime "$root" --target "$TARGET_ID" --minecraft "$MINECRAFT_VERSION" \
    --loader "$loader" --loader-version "$resolved" \
    --profile "$profile" --java-major "$JAVA_MAJOR" || {
      [[ -e "$root/live-server-execution.log" ]] && tail -c 12000 "$root/live-server-execution.log" >&2
      echo '[live-join] actual client did not join matching dedicated server' >&2
      return 3
    }
}

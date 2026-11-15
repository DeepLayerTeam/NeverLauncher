#!/usr/bin/env bash
# Реальный жизненный цикл локального Minecraft-сервера для обязательных проверок нативной
# совместимости. Используется в пяти сценариях сертификации установленных клиентов.

certification_live_cleanup() {
  if [[ -n "${LIVE_JOIN_PROXY_PID:-}" ]]; then
    kill "$LIVE_JOIN_PROXY_PID" 2>/dev/null || true
    wait "$LIVE_JOIN_PROXY_PID" 2>/dev/null || true
    unset LIVE_JOIN_PROXY_PID
  fi
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
    echo '[live-join] устаревшая квитанция подходящего сервера' >&2; return 2;
  }
  python3 "$ROOT/e2e/scripts/live_join.py" "${args[@]}" > "$root/live-server-execution.log" 2>&1 &
  LIVE_JOIN_DAEMON_PID=$!
  trap certification_live_cleanup EXIT
  local attempt
  for ((attempt=0;attempt<480;attempt++)); do
    if [[ -s "$root/live-server-ready.json" ]]; then break; fi
    if ! kill -0 "$LIVE_JOIN_DAEMON_PID" 2>/dev/null; then
      cat "$root/live-server-execution.log" >&2; echo '[live-join] ошибка запуска выделенного сервера' >&2; return 3;
    fi
    sleep 0.5
  done
  [[ -s "$root/live-server-ready.json" ]] || { echo '[live-join] выделенный сервер не подтвердил готовность' >&2; return 3; }
  LIVE_JOIN_SERVER_PORT="$(python3 - "$root/live-server-ready.json" "$TARGET_ID" <<'PY'
import json,sys
ready=json.load(open(sys.argv[1],encoding='utf-8'))
p=ready.get('port')
if ready.get('targetId') != sys.argv[2] or type(p) is not int or not 1 <= p <= 65535:
    raise SystemExit('Недопустимый порт или идентификатор выделенного сервера')
print(p)
PY
)" || return 3
  # The loopback proxy forwards actual game traffic only after the block atlas is ready.
  # Its endpoint is bound to the original server by live_join.verify; RCON still observes that server.
  if [[ "$loader" == vanilla && "${TARGET_OS:-}" == linux && "$MINECRAFT_VERSION" =~ ^1\.(14|15|16|17|18)(\.[0-9]+)?$ ]]; then
    [[ ! -e "$root/resource-ready-proxy.port" && ! -e "$root/resource-ready-proxy.json" ]] || return 3
    python3 "$ROOT/e2e/scripts/vanilla-1171-resource-ready-proxy.py" \
      --minecraft "$MINECRAFT_VERSION" --backend-port "$LIVE_JOIN_SERVER_PORT" \
      --logs "$profile_root/logs" --port-file "$root/resource-ready-proxy.port" \
      --evidence "$root/resource-ready-proxy.json" --timeout 90 > "$root/resource-ready-proxy.log" 2>&1 &
    LIVE_JOIN_PROXY_PID=$!
    for ((attempt=0;attempt<80;attempt++)); do
      [[ -s "$root/resource-ready-proxy.port" ]] && break
      kill -0 "$LIVE_JOIN_PROXY_PID" 2>/dev/null || return 3
      sleep 0.25
    done
    [[ -s "$root/resource-ready-proxy.port" ]] || return 3
    LIVE_JOIN_SERVER_PORT="$(cat "$root/resource-ready-proxy.port")"
    [[ "$LIVE_JOIN_SERVER_PORT" =~ ^[0-9]+$ ]] && (( LIVE_JOIN_SERVER_PORT >= 1 && LIVE_JOIN_SERVER_PORT <= 65535 )) || return 3
  fi
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
    echo '[live-join] отсутствует актуальное подтверждение RCON о нахождении клиента в сети' >&2
    return 3
  }
  certification_live_cleanup
  [[ -s "$root/live-server-stopped.json" ]] || {
    echo '[live-join] выделенная JVM не работала в момент штатного завершения' >&2
    return 3
  }
  python3 "$ROOT/e2e/scripts/live_join.py" verify \
    --runtime "$root" --target "$TARGET_ID" --minecraft "$MINECRAFT_VERSION" \
    --loader "$loader" --loader-version "$resolved" \
    --profile "$profile" --java-major "$JAVA_MAJOR" || {
      [[ -e "$root/live-server-execution.log" ]] && tail -c 12000 "$root/live-server-execution.log" >&2
      echo '[live-join] реальный клиент не подключился к соответствующему выделенному серверу' >&2
      return 3
    }
}

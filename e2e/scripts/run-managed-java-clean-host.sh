#!/usr/bin/env bash
# Проверяйте собранный бинарник Runtime и подлинный закреплённый дистрибутив Temurin. В
# отличие от тестов только на фикстурах здесь JVM устанавливается и запускается без
# доступного через PATH исполняемого java, затем восстанавливается офлайн.
set -euo pipefail
if (( $# != 4 )); then
  echo "Использование: $0 /absolute/path/runtime /path/MANAGED_JRE_MANIFEST.json SHA256 MAJOR" >&2
  exit 64
fi
runtime="$(realpath "$1")"
manifest="$(realpath "$2")"
digest="$3"
major="$4"
[[ -x "$runtime" && -f "$manifest" ]] || { echo 'runtime binary or manifest missing' >&2; exit 1; }
[[ "$digest" =~ ^[0-9a-fA-F]{64}$ ]] || { echo 'manifest digest must be SHA-256' >&2; exit 1; }
[[ "$major" =~ ^(8|16|17|21|25)$ ]] || { echo 'неверный основной номер версии Java' >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/runtimes"
# При второй операции восстановления кэша без манифеста не обнаруживайте
# автоматически манифест релиза рядом с исходным бинарником.
cp "$runtime" "$work/runtime"
chmod +x "$work/runtime"
runtime="$work/runtime"
# Нет системных Java, javac и JAVA_HOME. tar и gzip используются только для распаковки.
for executable in tar gzip; do
  source_bin="$(command -v "$executable")"
  ln -s "$source_bin" "$work/bin/$executable"
done
python="$(command -v python3)"
if [[ -n "$(PATH="$work/bin" command -v java 2>/dev/null || :)" ]]; then
  echo 'тестовая переменная PATH неожиданно содержит java' >&2
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
# Создайте повреждённый список и прерванную распаковку: установщик должен
# отправить первый в карантин, очистить вторую и восстановить ту же JVM.
install_dir="$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["installDirectory"])' "$work/result.json")"
touch "$install_dir/UNEXPECTED_FILE"
mkdir -p "$(dirname "$install_dir")/.staging-dead-worker"
printf 'partial' > "$(dirname "$install_dir")/.staging-dead-worker/partial"
# При восстановлении нет закреплённого манифеста: принудительно используйте путь ремонта локального
# архива, закреплённого только по SHA-256. Офлайн-режим запрещает сетевой резервный вариант.
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
# Итоговый офлайн-запуск использует проверенную управляемую JVM, а не Java хоста.
env -u JAVA_HOME PATH="$work/bin" "$java_exe" -version > "$work/recovered-version.log" 2>&1
printf 'Установка Managed Java 0.40.7 на чистом хосте, восстановление после повреждения и запуск JVM: PASS\n'

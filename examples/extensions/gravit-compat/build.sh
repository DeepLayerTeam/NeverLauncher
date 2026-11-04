#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
folder=examples/extensions/gravit-compat
# Очищается только созданный вывод примеров; исходники Java, переданные пользователем, сохраняются.
rm -rf "$folder/build/package"
python3 tools/gravit-port/port.py \
  --source "$folder/src" \
  --module-class ru.example.gravit.PortedModule \
  --manifest "$folder/launcher-extension.json" \
  --output "$folder/build/package"

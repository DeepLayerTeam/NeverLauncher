#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
cd "$root"
folder=examples/extensions/gravit-compat
# Only generated example outputs are cleaned; user-supplied Java sources are retained.
rm -rf "$folder/build/package"
python3 tools/gravit-port/port.py \
  --source "$folder/src" \
  --module-class ru.example.gravit.PortedModule \
  --manifest "$folder/neverlauncher-extension.json" \
  --output "$folder/build/package"

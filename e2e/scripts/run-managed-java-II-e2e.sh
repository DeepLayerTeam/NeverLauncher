#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNTIME_BIN="${NEVERLAUNCHER_RUNTIME_BIN:-${ROOT_DIR}/runtime/neverruntime/target/release/neverruntime}"
WORK_DIR="${NEVERLAUNCHER_MANAGED_JAVA_E2E_DIR:-${ROOT_DIR}/e2e/runtime/managed-java-II}"
RUNTIME_ROOT="${WORK_DIR}/runtimes"
EVIDENCE="${WORK_DIR}/MANAGED_JAVA_II_EVIDENCE.json"

if [[ ! -x "${RUNTIME_BIN}" ]]; then
  echo "neverruntime бинарный файл не исполняемый: ${RUNTIME_BIN}" >&2
  exit 1
fi

rm -rf "${WORK_DIR}"
mkdir -p "${RUNTIME_ROOT}"

python3 - "${EVIDENCE}" <<'PY'
import json, sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
    "schemaVersion": "1.0",
    "product": "NeverLauncher",
    "feature": "Managed Java II",
    "requiredMajors": [8, 16, 17, 21, 25],
    "results": []
}, indent=2) + "\n", encoding="utf-8")
PY

for major in 8 16 17 21 25; do
  first="${WORK_DIR}/java-${major}-install.json"
  second="${WORK_DIR}/java-${major}-cache.json"

  "${RUNTIME_BIN}" java ensure \
    --major "${major}" \
    --distribution temurin \
    --runtime-root "${RUNTIME_ROOT}" >"${first}"

  python3 - "${first}" "${major}" <<'PY'
import json, os, subprocess, sys
p, major = sys.argv[1], int(sys.argv[2])
data = json.load(open(p, encoding="utf-8"))
assert data["status"] == "ready", data
assert data["distribution"] == "temurin", data
assert data["majorVersion"] == major, data
assert data["imageType"] in {"jre", "jdk"}, data
assert data["cached"] is False, data
assert len(data["archiveSha256"]) == 64, data
java = data["javaExecutable"]
assert os.path.isfile(java), java
proc = subprocess.run([java, "-version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
assert proc.returncode == 0, proc.stdout
PY

  "${RUNTIME_BIN}" java ensure \
    --major "${major}" \
    --distribution temurin \
    --runtime-root "${RUNTIME_ROOT}" >"${second}"

  python3 - "${first}" "${second}" "${EVIDENCE}" "${major}" <<'PY'
import json, sys
first_path, second_path, evidence_path, major = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
first = json.load(open(first_path, encoding="utf-8"))
second = json.load(open(second_path, encoding="utf-8"))
assert second["status"] == "ready", second
assert second["majorVersion"] == major, second
assert second["cached"] is True, second
assert second["javaExecutable"] == first["javaExecutable"], (first, second)
assert second["archiveSha256"] == first["archiveSha256"], (first, second)
evidence = json.load(open(evidence_path, encoding="utf-8"))
evidence["results"].append({
    "majorVersion": major,
    "imageType": first["imageType"],
    "releaseName": first["releaseName"],
    "archiveSha256": first["archiveSha256"],
    "archiveSize": first["archiveSize"],
    "installVerified": True,
    "cacheReuseVerified": True,
})
open(evidence_path, "w", encoding="utf-8").write(json.dumps(evidence, indent=2) + "\n")
PY

done

python3 - "${EVIDENCE}" <<'PY'
import json, sys
p=sys.argv[1]
data=json.load(open(p, encoding="utf-8"))
assert [x["majorVersion"] for x in data["results"]] == [8,16,17,21,25], data
data["status"]="passed"
open(p,"w",encoding="utf-8").write(json.dumps(data, indent=2)+"\n")
PY

echo "Управляемый Java II E2E: Java 8/16/17/21/25 установка + кэш проверка пройден"

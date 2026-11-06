#!/usr/bin/env python3
"""Проверить *собранные* производственные байты Desktop и фронтенда на текущей ОС.

Вызывается только ПОСЛЕ успеха cargo build --release и npm run build; при отсутствии исполняемого
файла или наличии лишь статического манифеста без сборки PASS не возвращается.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "release"))
from release_policy import rc_extended
from certification_run import identity, CertificationBlocked

ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inspect(binary: Path, frontend: Path, commit: str) -> dict:
    version = (ROOT / "VERSION").read_text().strip()
    if not rc_extended(version) or not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("Некорректная версия RC или коммит исходников")
    if not binary.is_file() or binary.is_symlink() or binary.stat().st_size < 1_000_000:
        raise ValueError("Отсутствует реально собранный исполняемый файл Desktop")
    if os.name != "nt" and not os.access(binary, os.X_OK):
        raise ValueError("Исполняемый файл Desktop нельзя запустить")
    if not frontend.is_dir() or frontend.is_symlink():
        raise ValueError("Отсутствует каталог собранного интерфейса")
    main = frontend / "index.html"
    js = list((frontend / "assets").glob("*.js"))
    if not main.is_file() or not js:
        raise ValueError("Отсутствует промышленная сборка HTML и JavaScript")
    # Используйте настоящие сгенерированные артефакты, а не свидетельство только
    # по исходникам или package.json.
    files = sorted([main, *js])
    for path in files:
        if (
            path.is_symlink()
            or path.stat().st_size == 0
            or not path.resolve().is_relative_to(frontend.resolve())
        ):
            raise ValueError("Ресурс production-сборки небезопасен или пуст")
    return {
        "schemaVersion": "launcher.rc.desktop-build.v1",
        "version": version,
        "status": "passed",
        "simulated": False,
        "commit": commit,
        "platform": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "binarySha256": sha256(binary),
        "binarySizeBytes": binary.stat().st_size,
        "frontendAssets": len(files),
        "frontendSha256": hashlib.sha256(
            "".join(
                path.relative_to(frontend).as_posix() + ":" + sha256(path) + "\n"
                for path in files
            ).encode()
        ).hexdigest(),
        "scope": "Реальная сборка нативного компонента и производственного интерфейса; не подтверждает игровой процесс через GUI",
        "timestampUtc": datetime.now(timezone.utc).isoformat(),
        "certificationRun": identity(version, commit, root=ROOT),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--frontend", type=Path, required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    # Никогда не оставляйте устаревший успешный результат после последующей
    # ошибки.
    a.output.unlink(missing_ok=True)
    try:
        result = inspect(a.binary, a.frontend, a.commit)
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError) as e:
        print("Рабочая сборка Desktop ЗАБЛОКИРОВАНА: " + str(e), file=sys.stderr)
        return 3
    print(
        "Нативный Desktop и производственный интерфейс проверены на " + result["platform"]
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

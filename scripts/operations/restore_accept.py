#!/usr/bin/env python3
"""Измерять реальное восстановление Network-HA на новом хосте по проверенному снимку.

RTO отсчитывается от времени инцидента, переданного оператором, и включает реакцию и восстановление.
Верхняя оценка RPO — возраст принятого снимка на момент инцидента; нельзя сертифицировать
ненаблюдавшиеся записи. При необходимости проверяется сохранность подтверждённого PostgreSQL canary
и совпадение восстановленных байтов S3/мира (DR-раннер).
"""
from __future__ import annotations

import argparse
import io
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

import dr as dr


def parse_utc(value: str) -> datetime:
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise dr.DrillError("Некорректная временная метка инцидента в UTC") from exc
    if date.tzinfo is None:
        raise dr.DrillError("Временная метка инцидента в UTC должна содержать часовой пояс")
    return date.astimezone(timezone.utc)


def exposure_seconds(snapshot_time: str, incident: datetime) -> float:
    saved = parse_utc(snapshot_time)
    if incident < saved:
        raise dr.DrillError("Инцидент произошёл раньше снимка; некорректный интервал восстановления")
    if incident > datetime.now(timezone.utc):
        raise dr.DrillError("Временная метка инцидента находится в будущем")
    return round((incident - saved).total_seconds(), 3)


def write_report(path: Path, report: dict) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise dr.DrillError("Для отчёта требуется новый путь в существующем каталоге")
    with tempfile.NamedTemporaryFile("w", dir=path.parent, encoding="utf-8",
                                     prefix=".restore-report-", delete=False) as out:
        stage = Path(out.name)
        json.dump(report, out, ensure_ascii=False, indent=2)
        out.write("\n"); out.flush(); os.fsync(out.fileno())
    try:
        if path.exists() or path.is_symlink():
            raise dr.DrillError("Файл назначения отчёта появился во время восстановления")
        stage.rename(path)
    finally:
        if stage.exists(): stage.unlink()


def run_restore(project: str, confirm: str, env_file: Path, snapshot: Path,
                url: str, bucket: str, s3_endpoint: str | None,
                destinations: dict[str, Path], incident: datetime, report_path: Path,
                checkpoint: str | None, checksum: str | None) -> dict:
    dr.ensure_isolated(project, confirm)
    if report_path.exists() or report_path.is_symlink():
        raise dr.DrillError("Отчёт уже существует")
    manifest = dr.verify_snapshot(snapshot)
    if manifest.get("schema") != 3 or manifest.get("mode") != "network-ha":
        raise dr.DrillError("Для приёмки на чистом узле требуется проверенный снимок Network-HA")
    if manifest.get("version") != dr.target_release(env_file):
        raise dr.DrillError("Версия восстановления должна соответствовать снимку, а не версии целевого обновления")
    upper_bound = exposure_seconds(manifest["createdUtc"], incident)
    if bool(checkpoint) != bool(checksum):
        raise dr.DrillError("Токен контрольной точки и SHA-256 необходимо указывать вместе")
    if checkpoint and (not re.fullmatch(r"[0-9a-f]{32}", checkpoint)
                       or not re.fullmatch(r"[0-9a-f]{64}", checksum or "")):
        raise dr.DrillError("Некорректный токен контрольной точки или контрольная сумма")
    dr.COMPOSE_FILES[:] = [dr.COMPOSE, dr.ROOT / "deploy/production/docker-compose.network-ha.yml"]
    dr.COMPOSE_PROFILES[:] = ["network-ha"]
    start = time.monotonic()
    outcome = dr.restore_fresh(project, env_file, snapshot, confirm, ready_url=url,
                               target_s3_bucket=bucket, s3_endpoint=s3_endpoint,
                               world_destinations=destinations)
    try:
        if not outcome.get("applicationVerified") or not outcome.get("serverbridgeFenced") or outcome.get("redisRestored") is not False:
            raise dr.DrillError("Неполное восстановление Network-HA нельзя принять")
        if checkpoint:
            # Проверяйте реальные восстановленные байты PostgreSQL, а не исходную
            # квитанцию.
            result = dr.compose(project, env_file, "exec", "-T", "postgres", "sh", "-ec",
                'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql -X -A -t -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                stdin=io.BytesIO(
                    (f"SELECT payload_sha256 FROM launcher_chaos_canaries_0456 WHERE token='{checkpoint}';\n").encode()), timeout=30)
            if result.stdout.decode().strip() != checksum:
                raise dr.DrillError("Подтверждённая контрольная точка не сохранилась в восстановленном PostgreSQL")
    except Exception:
        # Не открывайте восстановленное приложение, если дополнительные независимые
        # приёмочные проверки провалились после успешного завершения базового скрипта
        # DR.
        for service in ("nginx", "admin", "api", "api-b", "worker-a", "worker-b"):
            try:
                dr.compose(project, env_file, "stop", "-t", "10", service, timeout=30)
            except (dr.DrillError, OSError):
                pass
        raise
    restored_at = datetime.now(timezone.utc)
    report = {
        "schema": 1, "status": "passed", "release": manifest["version"],
        "incidentUtc": incident.isoformat(), "snapshotUtc": manifest["createdUtc"],
        "recoveredUtc": restored_at.isoformat(), "targetProject": project,
        "restoredPostgres": True, "restoredWorlds": outcome.get("restoredWorlds"),
        "restoredS3Readback": manifest["storage"] == "s3-objects",
        "discardedOldRedisLeases": True, "serverbridgeFenced": True,
        "backendReady": True, "checkpointPreserved": bool(checkpoint),
        "rtoSecondsMeasured": round((restored_at - incident).total_seconds(), 3),
        "restoreExecutionSecondsMeasured": round(time.monotonic() - start, 3),
        "rpoSecondsUpperBoundFromSnapshotAge": upper_bound,
        "rpoInterpretation": "Верхняя граница возраста снимка, а НЕ подтверждённая длительность потери данных",
        "limits": ["Не заменяет журнал операций записи источника", "Приёмка восстановления должна проводиться на новом реальном узле", "Автоматическая повторная регистрация узлов ServerBridge запрещена"],
    }
    write_report(report_path, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--ready-url", required=True)
    parser.add_argument("--target-s3-bucket", required=True)
    parser.add_argument("--s3-endpoint")
    parser.add_argument("--world-destination", action="append", default=[], metavar="NAME=/absolute/fresh/world")
    parser.add_argument("--incident-utc", required=True, help="Реальная временная метка инцидента ISO 8601 с часовым поясом")
    parser.add_argument("--checkpoint-token", help="Подтверждённый токен PostgreSQL canary до резервирования")
    parser.add_argument("--checkpoint-sha256", help="SHA-256 содержимого подтверждённого PostgreSQL canary")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = run_restore(args.project, args.confirm, args.env_file, args.snapshot,
                           args.ready_url, args.target_s3_bucket, args.s3_endpoint,
                           dr.parse_world_args(args.world_destination), parse_utc(args.incident_utc),
                           args.report, args.checkpoint_token, args.checkpoint_sha256)
        print(json.dumps({"status": "passed", "rtoSecondsMeasured": data["rtoSecondsMeasured"],
                          "rpoUpperBoundSeconds": data["rpoSecondsUpperBoundFromSnapshotAge"],
                          "report": str(args.report)}))
        return 0
    except (dr.DrillError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status":"failed", "reason":str(exc)[:240]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

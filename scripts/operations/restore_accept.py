#!/usr/bin/env python3
"""Measure actual fresh-host Network-HA restore against a verified snapshot.

RTO starts at the operator-supplied incident timestamp, includes response and
restore time. RPO upper bound is the age of the accepted snapshot at the
incident; cannot certify unobserved writes. Optionally confirm a PostgreSQL
acknowledged canary survived and match restored S3/world bytes (DR runner).
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

import dr_03512 as dr


def parse_utc(value: str) -> datetime:
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise dr.DrillError("invalid incident UTC timestamp") from exc
    if date.tzinfo is None:
        raise dr.DrillError("incident UTC timestamp needs timezone")
    return date.astimezone(timezone.utc)


def exposure_seconds(snapshot_time: str, incident: datetime) -> float:
    saved = parse_utc(snapshot_time)
    if incident < saved:
        raise dr.DrillError("incident predates snapshot; recovery window invalid")
    if incident > datetime.now(timezone.utc):
        raise dr.DrillError("incident timestamp is in the future")
    return round((incident - saved).total_seconds(), 3)


def write_report(path: Path, report: dict) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise dr.DrillError("report target must be new path in existing directory")
    with tempfile.NamedTemporaryFile("w", dir=path.parent, encoding="utf-8",
                                     prefix=".restore-report-", delete=False) as out:
        stage = Path(out.name)
        json.dump(report, out, ensure_ascii=False, indent=2)
        out.write("\n"); out.flush(); os.fsync(out.fileno())
    try:
        if path.exists() or path.is_symlink():
            raise dr.DrillError("report target appeared during restore")
        stage.rename(path)
    finally:
        if stage.exists(): stage.unlink()


def run_restore(project: str, confirm: str, env_file: Path, snapshot: Path,
                url: str, bucket: str, s3_endpoint: str | None,
                destinations: dict[str, Path], incident: datetime, report_path: Path,
                checkpoint: str | None, checksum: str | None) -> dict:
    dr.ensure_isolated(project, confirm)
    if report_path.exists() or report_path.is_symlink():
        raise dr.DrillError("report exists")
    manifest = dr.verify_snapshot(snapshot)
    if manifest.get("schema") != 3 or manifest.get("mode") != "network-ha":
        raise dr.DrillError("fresh-host acceptance requires verified Network-HA snapshot")
    if manifest.get("version") != dr.target_release(env_file):
        raise dr.DrillError("restore version must match snapshot, not target upgrade version")
    upper_bound = exposure_seconds(manifest["createdUtc"], incident)
    if bool(checkpoint) != bool(checksum):
        raise dr.DrillError("checkpoint token and SHA-256 must be supplied together")
    if checkpoint and (not re.fullmatch(r"[0-9a-f]{32}", checkpoint)
                       or not re.fullmatch(r"[0-9a-f]{64}", checksum or "")):
        raise dr.DrillError("invalid checkpoint token/digest")
    dr.COMPOSE_FILES[:] = [dr.COMPOSE, dr.ROOT / "deploy/production/docker-compose.network-ha.yml"]
    dr.COMPOSE_PROFILES[:] = ["network-ha"]
    start = time.monotonic()
    outcome = dr.restore_fresh(project, env_file, snapshot, confirm, ready_url=url,
                               target_s3_bucket=bucket, s3_endpoint=s3_endpoint,
                               world_destinations=destinations)
    try:
        if not outcome.get("applicationVerified") or not outcome.get("serverbridgeFenced") or outcome.get("redisRestored") is not False:
            raise dr.DrillError("incomplete Network-HA restore may not be accepted")
        if checkpoint:
            # Verify the actual restored PostgreSQL bytes, not a source receipt.
            result = dr.compose(project, env_file, "exec", "-T", "postgres", "sh", "-ec",
                'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql -X -A -t -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"',
                stdin=io.BytesIO(
                    (f"SELECT payload_sha256 FROM launcher_chaos_canaries_0456 WHERE token='{checkpoint}';\n").encode()), timeout=30)
            if result.stdout.decode().strip() != checksum:
                raise dr.DrillError("acknowledged checkpoint was not retained in restored PostgreSQL")
    except Exception:
        # Do not expose a restored application if additional independent
        # acceptance checks failed after the underlying DR script returned.
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
        "rpoInterpretation": "snapshot-age upper bound, NOT proven actual data-loss duration",
        "limits": ["not a substitute for source write journal", "restore acceptance must use fresh actual host", "no automatic reenrollment of ServerBridge nodes"],
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
    parser.add_argument("--incident-utc", required=True, help="real incident ISO 8601 timestamp with timezone")
    parser.add_argument("--checkpoint-token", help="acknowledged PostgreSQL canary token before backup")
    parser.add_argument("--checkpoint-sha256", help="acknowledged PostgreSQL canary content SHA-256")
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

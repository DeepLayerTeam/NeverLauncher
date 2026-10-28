# 0.35.12 acceptance — execution evidence and limitations

Source archive: NeverLauncher 0.35.11. New version: 0.35.12.

## Actual local results

- Python unittest security suite `python -m unittest discover -s scripts/operations -p 'test_dr_03512.py' -v`: **11/11 passed**.
- Tar member traversal, link and duplicate-path rejection exercised using actual gzip tar fixture bytes.
- Actual local snapshot SHA-256 verification exercised; tampered archive rejected.
- Destructive operations reject non-isolated projects, mismatched confirmation, nonempty target state, unsafe S3 HTTP endpoint and non-loopback chaos URL.
- S3 readback mismatch produces a hard failure (test uses a mocked AWS CLI; it is **not** an actual S3 server run).
- Existing Go backup/restore has gained bounded archive extraction and post-upload S3 readback, but **Go tests and production compile were not executed locally** (installed Go 1.23.2, project requires Go 1.27.3).
- Docker Engine, Docker Compose, PostgreSQL containers, Redis and S3 server are not available in this local sandbox. **No real component outage or live DR was executed.** No actual RPO/RTO numbers are claimed.

## Evidence still required before GA

- Real Docker Compose standard + network-ha outage tests, PostgreSQL fail-closed / recovery and Redis fail-closed / recovery.
- Restore into a newly provisioned independent project; verify PostgreSQL rows, files and S3 readback, ServerBridge, job queue reconciliation and release publication.
- Verify external secret restore, off-host retention, storage-consistency under load, queue saturation, node-loss behaviour and cross-region recovery separately.
- Verify no discrepancies in Go suite with supported toolchain and no change to client/ServerBridge availability.

Result: **implementation delivered, locally checked at Python test level; production HA/DR acceptance not verified.**

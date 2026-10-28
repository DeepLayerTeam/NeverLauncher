# 0.35.14 acceptance — available local execution

Source: supplied `NeverLauncher-main(20261028-193924).zip` (VERSION 0.35.13), edited to 0.35.14.

## Implemented

- New native acceptance execution (`scripts/rc/native_03514.py`): compiled NeverRuntime + real localhost HTTP transport + restricted Ed25519 fixture + independent SHA-256, positive and negative runtime operations.
- Actual compiled Desktop/React artifact verification (`platform_03514.py`) and 3-OS CI matrix. Compilation requires platform toolchains; no prebuilt binary from this patch is claimed.
- Exact-commit source RC integration (`gate_03514.py`) and authenticated disposable Backend acceptance; old G/M catalogue remains historical and does not convert 54 entries into a target certification.
- Real isolated operational backup/verify/restore/chaos orchestrator (`operations_03514.py`) with a protected production workflow job requiring staging resources.
- Current-version support in previously hardcoded live 0.32.16 Go gate and protected 0.35.0 Backend preflight. Added owner lifecycle and PostgreSQL stable immutability tests to the actual live Go gate.
- Critical real release-signing fix: protected Backend runtime gate now enforced for release versions from 0.35.0 onward, including 0.35.14 and 0.36.0.

## Verification limits

Local Python positive/negative tests cover runner and preflight logic, and bash/YAML syntax can be verified here. **Native Rust/Cargo, full React build, Go 1.27.3, PostgreSQL/Redis/S3 Docker, real operator DR, signed platform installers, protected live Backend runtime, player Minecraft and ServerBridge tests were not executed in this environment.** A new workflow is not evidence that its remote run succeeded.

**Release decision: BLOCKED / NOT GA-CERTIFIED** until the new native matrix and the existing protected production/live runtime, game, security, signing and DR jobs return independent actual evidence for this exact source SHA. No fabricated benchmarks, HA claims, RTO/RPO values or green end-to-end marks are included.

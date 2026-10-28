# 0.35.9 acceptance — available evidence

## Scope

- Native Desktop schema `1.0` → `1.1` migration, preserving settings and exact legacy backup
- Installed signed release requirements comparison and player acknowledgement
- Player-owned file collision archive with SHA-256, explicit approval and fail-closed source validation
- No bypass of existing transactional-release collision and signed-install verification

## Local results

- `npm run test:update-migration`: **3/3 passed**; signatures, target identity, updated release and error states.
- `npm run test:downloads`: **4/4 passed**.
- `npm run test:components`: **3/3 passed**.
- `npm run test:launch-modes`: **4/4 passed**.
- `npm run test:accessibility`: **7/7 passed**.
- `npm run test:extension-security`: **4/4 passed**.
- `npm run test:offline`: **3/3 passed**.
- TypeScript/TSX syntax checked via TypeScript parser on changed source files.
- `python3 scripts/version/manage.py check`: synchronized version **0.35.9**.

## Pending

Rust compiler and Cargo are unavailable in this local runtime. The new Rust unit tests for preserved-conflict file bytes, changed preview, symlink refusal and legacy JSON backup are added but **not executed locally**. Production Tauri compilation, native cross-platform E2E, full `npm run build`, signed launcher installer verification and end-to-end Minecraft launch remain **unverified**. Do not convert a CI workflow declaration into positive evidence.

A preserved untracked player file is archived only after its owner requests the operation. Already-owned files modified outside the installer continue to block release switching rather than risk silent data loss.

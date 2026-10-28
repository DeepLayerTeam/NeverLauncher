# 0.35.3 player workspace acceptance — local execution receipt

Source: user-provided NeverLauncher-main(20261028-141943).zip (0.35.2).

Implemented: route navigation, native-backed build selection, profile-scoped server selection, first-class optional mods, textures, downloads, account workflows and native launch history.

Local executions (28 October 2026):

- `npm run test:workspace`: navigation and renderer action tests (10 tests): PASS.
- Existing component tests (3), launch modes (4), textures/official boundary (23), account flow (14) and sentry (2): PASS, total 46.
- TypeScript TSX AST syntax parse: PASS for modified/new TSX.
- `npm ci --offline --ignore-scripts`: BLOCKED — npm cache lacks `vite@8.0.14`, so `npm run build` and end-to-end React/Tauri compilation are UNVERIFIED locally.
- Native Windows/Linux/macOS GUI and live Minecraft ServerBridge: NOT RUN. Do not claim GA based on local unit tests.

CI job `desktop-workspace-0353.yml` installs exact lockfile dependencies and attempts the real `npm run build` plus regressions on an online Ubuntu runner; existence of the workflow is not evidence that it has run successfully.

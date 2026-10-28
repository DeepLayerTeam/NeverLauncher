# 0.35.8 — Offline acceptance evidence

Source: `NeverLauncher-main(20261028-163852).zip` (reported by user as 0.35.7). Changes implement local replay of an installed owner-signed offline release.

## Local observations

- `npm run test:offline`: **3/3 pass** — offline never carries automatic server connection; online settings preserved; concrete recovery actions.
- `npm run test:launch-modes`: **4/4 pass** — realm separation and signed offline permission.
- `npm run test:accessibility`: **7/7 pass**.
- `npm run test:downloads`: **4/4 pass**.
- `npm run test:extension-security`: **4/4 pass**.
- `npm run test:components`: **3/3 pass**.
- `npm run test:official`: **15/15 pass**.
- `npm run test:textures`: **23/23 pass**, including the repeated official tests.
- `npm run test:auth-experience`: **14/14 pass**.
- `npm run test:sentry`: **2/2 pass**.
- `python3 scripts/version/manage.py check`: version sync confirmed at 0.35.8.

## Native/platform evidence still required

`cargo`/`rustc` are not installed in the execution environment. Rust tests are added but **NOT RUN** locally; no claim is made of successful Tauri linking, native compilation, live entitlement validation, or real Minecraft gameplay. `.github/workflows/desktop-offline-policy-0358.yml` runs native tests on Windows, Linux and macOS with a Rust toolchain and builds the Desktop UI; its CI result has not been observed.

## Prior risk addressed

0.35.7's cached offline load changed `settings.offlineEnabled` but not `minecraftIdentity`, allowing a UI mode mismatch. The renderer could also request an offline cache without a complete native binding to owner scope. 0.35.8 reuses the actual native launcher/installer and adds owner binding, active release, component preset and SHA-256 verification, plus a local-only identity transition. The source-only status is **implementation present; packaged production acceptance pending**.

# NeverLauncher 0.35.7 acceptance evidence — 2026-10-28

## Executed locally

- `npm run test:accessibility`: 7/7 passed — preference validation, supported zoom, Windows/Linux/macOS modifier handling, IME/input protection, roving keyboard navigation, translation coverage for navigation, native trust fail-closed.
- `npm run test:downloads`: 4/4 passed.
- `npm run test:extension-security`: 4/4 passed.
- `npm run test:components`: 3/3 passed.
- `npm run test:launch-modes`: 4/4 passed.
- `npm run test:official`: 15/15 passed.
- `npm run test:textures`: 23/23 passed (includes 15 official-auth tests).
- `npm run test:auth-experience`: 14/14 passed.
- `npm run test:sentry`: 2/2 passed.
- Desktop TS/TSX syntax parsed with TypeScript compiler API. This **does not** prove typechecking or build success.

## Not verified locally

- `npm ci` cannot fetch Vite 8.0.14 and other dependencies; full `tsc`, Vite production build, Tauri packaging and WebView accessibility E2E have not been completed. Do not report them as passing.
- Rust/Cargo toolchain is absent. Native window commands are implemented but not compiled/tested on this environment. CI matrix includes macOS, Windows and Linux native compilation of the new Rust unit tests. No CI completion evidence was available when this report was written.
- WCAG full conformance, screen-reader output, and complete EN translation of all older/advanced views are **not certified**.

## Security invariant

No permissions were added to existing Tauri capability JSON. The only newly exposed Tauri commands are `desktop_native_ui_info_0357` and allowlisted `desktop_window_action_0357`, scoped to the invoking WebviewWindow. They cannot launch a process, read files or issue arbitrary native commands. The UI applies native loading and signed-first-run restrictions to shortcut navigation and core action buttons. 

# NeverLauncher 0.35.5 acceptance report

Scope: the 0.35.4 user-provided archive updated to 0.35.5, not a certified native binary.

| Verification | Outcome | Evidence / limitation |
| --- | --- | --- |
| Owner signed v1 edit and re-sign | PASS (local) | `apps/admin/tests/branding_0355.test.mjs`; real WebCrypto Ed25519 |
| Delegated signed v2 edit, policy and re-sign | PASS (local) | same suite; valid root-signed policy and active delegated signer |
| Prestarter accepts both exported versions | PASS (local) | tests spawn real `go run ./cmd/verify-branding` and validate output |
| Tampered signature / wrong signing key | PASS (local) | rejected, never reports successful signed download |
| XSS/theme injection, SVG, unsafe URL, invalid sizes | PASS (local) | signer validation and Go negative cases |
| Full Admin tests | PASS (local) | `cd apps/admin && node --experimental-strip-types --test tests/*.test.mjs` |
| Prestarter tests | PASS (local) | `cd prestarter && go test ./... -count=1` |
| Desktop / Admin TSX source syntax | PASS (local) | TypeScript transpileModule parse; **not typechecking or bundling** |
| Admin / Desktop production build | NOT RUN | offline npm cache lacks vite@8.0.14 |
| Native Rust tests | NOT RUN | Rust toolchain not installed on local host |
| Installer platform signature / native launch | NOT RUN | no Windows/macOS/Linux signing platform or native E2E fixture |

Fix to historical fixture: `TestDesktopReceivesSignedFirstRunBinding` now provisions an owner-signed HTTPS backend before launching a Desktop test, matching the enforced 0.35.2 unattended first-run requirement. This is a test setup correction, **not a relaxation** of production validation.

No release gate claims are advanced by this report; all blocked checks remain pending.

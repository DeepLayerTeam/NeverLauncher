# NeverLauncher 0.46.2 — real delivery and independent acceptance

This is the executable verification path for *actual* release files. It does not
mint signatures or substitute test data for native executables. No release
passes if the six signed packages are absent or if the native OS checks fail.

## Production release pipeline

1. Run required CI on exact committed source. Windows production builder must
   sign both x64 and ARM64 executables with Authenticode/RFC3161 and check them
   using SignTool. macOS production builder must validate Developer ID signatures,
   hardened runtime, Gatekeeper, notarization and stapling for both targets.
   Linux x64 and ARM64 binaries must originate on native target hosts.
2. Run `scripts/release/build-release.sh` with the required independently signed
   six-platform GA, Guard, compatibility, operational and live runtime evidence,
   the exact commit and separate release signing credentials in environment.
   Never supply signing credentials via the archive or the repository.
3. The build writes `DELIVERY_VERIFIED_0462.json` by inspecting ZIP/TAR contents.
   The Go release command requires this file, adds its SHA-256 to the signed
   RELEASE_MANIFEST and verifies package/cohort evidence. It must not produce
   a publishable bundle if any executable has the wrong platform/architecture.
4. Before and after release signing, the build checks that the release manifest
   enumerates the exact *on-disk* six package hashes. It runs the independent
   Ed25519/GA/Operations checks already present in release 0.46.1.
5. Production GitHub publication rehashes the local bundle, copies immutable
   bytes, uploads a draft release, downloads **all** draft release assets and
   compares hashes. Starting with 0.46.2 it also re-inspects inner executable
   formats and manifest bindings before promotion to public. Public production
   delivery E2E runs after publication using the original pinned trust keys.

## Manual preflight

```bash
VERSION="$(cat VERSION)"
python3 scripts/version/manage.py check
python3 scripts/release/inputs_guard_0461.py verify
python3 scripts/release/delivery_verify_0462.py --bundle "dist/release-$VERSION" --release-manifest
```

To independently accept bytes served from an immutable HTTPS staging/CDN path,
**first** upload the exact signed release assets without repacking. Then run:

```bash
python3 scripts/release/staged_accept_0462.py \
  --bundle "dist/release-$(cat VERSION)" \
  --base-url "https://your-staging.example/releases/v$(cat VERSION)" \
  --cli "dist/release-$(cat VERSION)/launcher-cli-linux-x64" \
  --public-key /secure/pinned-release-root.pem \
  --trust-policy /secure/release-trust-policy.json \
  --operator-key /secure/independent-operations-ga-public.pem \
  --report /secure/staging-acceptance-0462.json
```

The staging verifier refuses HTTP, redirects, wrong-version URLs, truncated
or changed files, missing release manifests, incomplete six-platform packages,
invalid signatures and invalid distribution attestations. The report is only
written after each byte has been downloaded and the production CLI has verified
both local and downloaded final packages. It is operational evidence and must
be separately approved under the independent GA policy for signing; it is not
an approval by itself. Report must not be committed as a signed receipt.

## Verification boundaries

- A PE certificate table / Mach-O LC_CODE_SIGNATURE is structural evidence,
  **not** proof that a signature chains to an authorized issuer. Native
  Authenticode, codesign, stapling and trust policy validation are separate,
  mandatory checks. No unsigned/development package can satisfy the required
  Windows production manifest mode.
- `SOURCE_COMMIT`, `VERSION` and independent operator receipts must belong to
  the exact candidate. CI skipped or missing jobs, a reused earlier receipt,
  a re-signed different archive, or a GitHub draft with differing downloaded
  bytes must remain release blockers.
- Cryptographically reproducible unsigned payload across independent builders
  is the distinct goal of 0.47.0, not a claim made by 0.46.2.

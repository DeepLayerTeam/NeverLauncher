# NeverLauncher 0.53.0 — source baseline and independent native reproducibility

## Canonical tracked files

- `primary-payload.json` defines the exact six unsigned artifact names for `VERSION` (0.53.0).
- `baseline.json` pins the actual current build/release inputs, lockfiles, SDK/tooling and workflows.
- `python3 scripts/release/inputs_guard_0461.py verify` must pass before and after release builds; `freeze` is an explicit reviewed rebaseline, **not** verification.
- Legacy `*_0470.py` filenames identify the origin of tools, not a hard-coded release version.

## Boundaries

The six **unsigned** packages in `primary-payload.json` contain the real compiled executable payload captured **before** platform signing. Both builder cohorts must produce byte-for-byte identical ZIP/TAR.GZ archives including all regular members. They are not copies of already-signed packages. Reproducibility does not turn a fabricated executable into a valid launcher; native acceptance and existing release/signature gates remain mandatory.

`reproducible_0470.py` is executable Python, not a contract-only scaffold. It verifies CPU format (PE64/ELF64/Mach-O), required compiled components, path safety, extraction size limits, entire archive SHA-256 and every member's digest and mode. `unsigned_package_0470.py` builds canonical packages from actual compiled component files before Authenticode/codesign and refuses missing executables/overwrites.

## Independent runs

The source-based reproducibility tests run in `.github/workflows/ci.yml`; separate native builder cohorts and independently signed, exact-byte evidence are required for an actual release. No automated six-platform release PASS is implied by those unit tests. Both builders must build real OS/CPU artifacts; the comparison verifier re-reads all archived bytes and validates signatures. The release gate rejects missing, altered or cross-commit evidence. Windows and macOS capture occurs before platform signing, Linux before delegated package signing. Developer ad-hoc packages are never treated as signed production deliverables.

External prerequisites: native runners, compatible Go/Rust/Java/Node dependencies, `LAUNCHER_COMPONENT_SET_ED25519_PUBLIC_KEY` (the exact public key embedded into both builds), separate builder Ed25519 signing identities, their independently pinned public keys, and a clean exact commit. A successful workflow requires actual native builds; the local source tests cannot satisfy it.

## Verification commands

Each builder captures the real six unsigned artifacts and signs its canonical JSON:

```sh
python3 scripts/release/reproducible_0470.py capture \
  --bundle /actual/unsigned --builder builder-a --runner physical-runner-a \
  --commit <FULL_GIT_COMMIT> --out /evidence/a.json
python3 scripts/release/reproducible_0470.py sign \
  --report /evidence/a.json --private-key /external/a-ed25519.pem --out /evidence/a.sig
```

Repeat with different runner and **different trusted key** for builder B. Both immutable sets must then be compared using `reproducible_0470.py compare --a-report ... --a-sig ... --a-key ... --a-dir ... --b-report ... --b-sig ... --b-key ... --b-dir ... --out ...`. This command requires all six archives and every member to match, and re-reads the files instead of accepting JSON declarations.

Platform signing changes final PE/Mach-O data; comparing signed installer ZIPs to unsigned archives byte-for-byte is not a valid reproducibility test. Windows acceptance requires native Authenticode chain and RFC3161 timestamp checks; macOS requires codesign, Gatekeeper and notarization; Linux requires the existing release Ed25519 signature and digest checks. A third independently trusted operator must perform these actual OS/CLI checks for the **exact signed files**, audit the signing transformation, and create a canonical signed `neverlauncher.native-signing-approval.v1` report. The `link` command verifies its detached Ed25519 signature, exact unsigned comparison digest, all six signed-package SHA-256 digests, external release manifest SHA-256, signed release verification claim, and independence of all three trust keys. The existing release CLI actually verifies the Ed25519 release signature before this step. The command refuses any missing target or missing native approval; it does **not** execute Windows/macOS native validation in Linux.

### Real native verification receipts (mandatory)

On native platforms, use `scripts/release/native_verify_0470.py --target windows-x64 --unsigned-dir /verified/unsigned --signed-dir /frozen/signed --release-cli /path/to/launcher-cli --public-key /trusted/release-root.pem --trust-policy /trusted/trust-policy.json --trust-state /verified/trust-state.json --out /evidence/windows-x64.json` (replace target/paths for each OS). It checks the actual release CLI Ed25519 trust decision and actual signed package, as well as Windows signtool and timestamp chain, Linux unchanged executable bytes, or macOS codesign, Gatekeeper and stapled notarization. On Windows the certificate-directory/checksum normalization also verifies that the signer did not alter executable code or unrelated PE content.

The independent operator signs the canonical native receipts using `reproducible_0470.py sign`; store them as `<target>.json` and `<target>.sig` for all six targets. Their exact SHA-256 hashes must appear in the independently signed approval report under `targets[target].nativeReceiptSha256`. The `link` command requires `--native-reports-dir`, verifies each native receipt against its actual target, its actual unsigned/final SHA-256 and the release manifest, and refuses missing or fabricated unsigned-to-signed claims. For macOS, notarized Mach-O signature transformations still need separate operator audit because codesign modifies the load-command/linkedit layout; mere notarization does not prove an unchanged original code payload.

The approval report is created **after** final signing and native acceptance; an independent operator cannot pre-approve unknown future signed bytes. For a one-shot release build, the approval must therefore reference an already frozen final candidate with identical final bytes and manifest (staging → promotion); any change requires reapproval. `build-release.sh` blocks publication without the externally approved record. `REPRODUCIBILITY_LINK_0470.json` is an external second-signature receipt, not a stealth modification of a previously signed release manifest.

## Hard acceptance threshold

- Two independent *real* build cohorts on the six named OS/CPU targets; six full archive SHA-256 pairs must match.
- The tracked `baseline.json` source-input hashes (regenerated only by reviewed `inputs_guard_0461.py freeze`), source commit and immutable release contract match; no uncontrolled lockfile changes.
- Native validators inspect each actual final signed package and verify the applicable platform signature; release CLI verifies the final Ed25519 manifest.
- Different pinned keys authenticate builder A, builder B and operator; all evidence applies to the same exact bytes.
- Missing/cancelled/skipped/failed targets are **BLOCKED**, never `PASS`.

**Local source tests do not certify this release.** The project cannot claim independent six-platform reproducibility or notarization until this external pipeline has actually completed successfully and the output/attestations exist. It is intentional that no fabricated successful receipts or release binaries are checked into the source tree.

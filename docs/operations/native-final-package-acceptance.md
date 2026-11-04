# NeverLauncher 0.52.2 — приёмка окончательного нативного установщика

## что действительно запускается

`native_packages_0522.py run` does **not** compile a substitute binary, call a fake
`main`, or accept cross-compilation as proof. It downloads an externally pinned
immutable index and the actual **final** package on each **native** disposable
runner. Before invoking it, it validates the download length and SHA-256 against
an independently approved source index. The exact six targets are Windows,
Linux and macOS, each x64/ARM64. Missing even one target fails the full gate.

| OS | Mandatory platform verification | Real installer execution |
| --- | --- | --- |
| Windows x64/ARM64 | Authenticode `Get-AuthenticodeSignature` (chain valid, **independently pinned certificate thumbprint**) | Execute downloaded `.exe verify`, `.exe install --root <isolated> --no-start`, `verify-installed`, `uninstall` |
| Linux x64/ARM64 | `gpgv` detached signature, pinned keyring SHA-256 and signer fingerprint; `.deb` project/version/native architecture | `sudo dpkg -i` on a **throwaway** runner; execute **system-installed** `/usr/lib/launcher/bundle/neverinstaller` `verify`/`install`/`verify-installed`/`uninstall` |
| macOS x64/ARM64 | Apple Installer certificate chain + pinned Team ID; `spctl` install assessment; stapled notarization; installed app codesign/Gatekeeper/Team ID | `sudo installer -pkg ... -target /` on a **throwaway** runner; execute **installed** `Launcher.app/Contents/MacOS/Launcher` with the same real actions |

An `install` succeeds only if the existing Go `neverinstaller` provisions the
signed Prestarter, content and managed Java and commits an active generation.
No source-built replacements, symbolic link substitutions, manually asserted
`PASS`, unsigned/development packages or skipped provisioning count.

**This is package installation/first provisioning, not E2E Minecraft gameplay.**
Game start, official login, signed world join, anti-cheat behavior and the complete
compatibility matrix belong to the subsequent 0.52.3–0.52.11 work and remain
BLOCKED until actually witnessed. The test uses private disposable project
accounts. No runner ever installs a package over a pre-existing macOS app.
The executable cannot prove by itself that the host was physically independent;
the trusted native runner scheduling / hardware inventory requires separate
operational validation for GA. A successful self-reported CI run is not an
independent 0.53.0 release approval.

## Подготовка и независимое закрепление окончательных файлов

1. Run the protected `native-installers.yml` production job from the **exact
   release commit**. Windows signs Authenticode, Linux signs detached `.asc`,
   macOS signs Developer ID, submits the final `.pkg` to Apple notarytool, checks
   **Accepted** and staples the ticket. An unsigned test build cannot be used.
2. Publish the **same exact final bytes** (`.exe`, `.deb`, `.deb.asc`, `.pkg`) to
   a non-mutable release/staging HTTPS URL. Do not rebuild them after approval.
3. Flatten the six packages and both Linux detached signatures in one release
   directory and generate a digest-bearing index:

```sh
python3 scripts/acceptance/native_packages_0522.py index \
  --packages /absolute/release/final-files \
  --base-url 'https://download.example.net/releases/v0.52.2/' \
  --version 0.52.2 --commit <40-hex-release-commit> \
  --project <signed-project-id> \
  --output /absolute/release/native-final-sources-0522.json
```

4. Approve `indexSha256` and `indexSize` **out of band** (protected environment,
   signed change ticket). Hosting a hash inside the downloaded index is not
   independent pinning. Publish `native-final-sources-0522.json` unchanged.
   Every asset must be reachable over HTTPS at its exact expected name and size.
5. Restrict the protected `production-acceptance` environment to approved release refs
   (`main` / trusted `v*` tags), require operator approval and set
   `NL_NATIVE_ACCEPTANCE_INDEX_SHA256` to the independently approved index hash
   and `LAUNCHER_BRANDED_PROJECT_ID` to the actual signed project. The workflow
   refuses release inputs that differ from these protected values. Configure
   this environment with
   `NL_NATIVE_ACCEPTANCE_WINDOWS_SIGNER_SHA1`,
   `NL_NATIVE_ACCEPTANCE_LINUX_GPG_FINGERPRINT`,
   `NL_NATIVE_ACCEPTANCE_LINUX_KEYRING_SHA256`,
   `NL_NATIVE_ACCEPTANCE_APPLE_TEAM_ID` as separately trusted variables and
   `NL_NATIVE_ACCEPTANCE_GPG_KEYRING_BASE64` as a secret containing the pinned
   minimal trusted binary GPG keyring. Never take trust identities from the
   release package, index, CI output or HTTPS response itself.
6. Dispatch `.github/workflows/native-final-packages-0522.yml` from that exact
   release commit with the independently approved `manifest_url`,
   `manifest_sha256`, `manifest_size` and signed `project`.

The workflow executes the six *native* jobs in parallel with `fail-fast: false`
and then `six-native-gate` fetches the same independently pinned index again,
replays package identities, verifies all required command logs by SHA-256,
requires each process exit code 0 and checks exact Git commit/run/attempt.
There is no `always-pass`, `continue-on-error`, `optional platform` or bypass
for missing hosts. The CLI exits 2 on verification/installation failure.

Each successful native runner publishes `receipt.json` and bounded **redacted**
per-command logs. Failed runs publish `blocked.json` with redacted diagnostic logs;
never a PASS receipt. Raw package bytes, signed bootstrap configuration, original
unredacted process output, GPG trust material and release URL queries are never
uploaded as CI artifacts. Some secrets may be emitted by third-party programs
in unanticipated formats; treat any downloaded CI logs as restricted until an
operator reviews them. CI receipt integrity protects against accidental mixing,
missing logs and basic artifact tampering, **not** a fully malicious CI runner.
Run on freshly provisioned, dedicated GitHub-hosted disposable runners only.
The installed Linux package/macOS app is left for hosted-runner disposal; it
must **not** run on an employee workstation or persistent self-hosted runner.

## Независимая проверка после CI с криптографическим закреплением

The CI summary is **not** a trusted human or physical-machine attestation. An
independent operator must separately inspect the six native runner logs and
release bytes. To prevent post-review alterations, the operator can additionally
sign the exact **recomputed** six-target summary. The tool refuses to sign a
missing target, a changed log, a wrong run or a reused source index.

```sh
python3 scripts/acceptance/native_packages_0522.py sign-review \
  --results /absolute/receipt-folders --source-index /absolute/native-final-sources-0522.json \
  --manifest-sha256 <approved-index-hash> --version 0.52.2 \
  --commit <40-hex-commit> --project <signed-project-id> \
  --run-id <run-id> --attempt <run-attempt> \
  --reviewer <independent-operator> --private-key /secure/reviewer-private.pem \
  --public-key /secure/reviewer-public.pem \
  --public-key-sha256 <independently-pinned-SPKI-DER-SHA256> \
  --output /secure/unused/native-package-review.json

python3 scripts/acceptance/native_packages_0522.py verify-review \
  --results /absolute/receipt-folders --source-index /absolute/native-final-sources-0522.json \
  --manifest-sha256 <approved-index-hash> --version 0.52.2 \
  --commit <40-hex-commit> --project <signed-project-id> \
  --run-id <run-id> --attempt <run-attempt> \
  --reviewer <independent-operator> --public-key /secure/reviewer-public.pem \
  --public-key-sha256 <independently-pinned-SPKI-DER-SHA256> \
  --receipt /secure/native-package-review.json
```

Use an Ed25519 PEM private key with `0600` permissions **outside checkout**.
`public-key-sha256` is SHA-256 of DER SubjectPublicKeyInfo, delivered out of
band. Receipt is exclusive-create and signed over all six raw receipt digests
and package/source binding. Verified review returns
`CI_OBSERVED_SIGNED_REVIEW_NOT_GA`; it does not elevate CI into GA.

## Что означает PASS и чего он не подтверждает

- A full candidate matrix yields `CI_OBSERVED_REVIEW_REQUIRED`, not `GA_PASS`.
  It binds six SHA-256-pinned native packages, operating-system signature and
  Gatekeeper/GPG/Authenticode verification, real system install (Linux/macOS),
  real installer execution, verified committed Prestarter installation and
  clean uninstall of the isolated application data.
- A missing/modified receipt or log, a stale source commit, other run attempt,
  wrong product version, wrong signer, non-HTTPS package, missing Apple ticket,
  emulated/foreign runner or broken live provisioning leaves the candidate
  **BLOCKED**. For independent GA, separately re-run and sign a review of the
  delivered bytes with genuine human/hardware witnesses; source-build CI alone
  is insufficient.
- Windows `.exe` installation is per-user via the real installer executable;
  it does not exercise Windows MSI/Store distribution (not part of this package
  family). Linux/macOS exercise the native system package managers, plus the
  installed Go application. Desktop GUI/gameplay will be covered separately.

Local regression command (security tests only, **not** real-platform evidence):

```sh
python3 -m unittest scripts/acceptance/test_native_packages_0522.py -v
python3 scripts/version/manage.py check
```

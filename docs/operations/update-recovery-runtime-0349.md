# NeverLauncher 0.34.9 — V09 real update / recovery / rollback runtime certification

## What actually runs

The V09 stage is executed by `e2e/scripts/staged_lifecycle_0349.py` **after** the normal staged client has passed real startup, loader readiness, live authentication, matching-server join and gameplay checks. It invokes the existing production `neverlauncher client install`, `update`, `verify`, `repair`, `rollback` and `neverlauncher update recover` commands, and `neverruntime adopt-staged` / `launch`. It does not implement a replacement/mock updater.

The baseline MUST be the exact signed, previously released client bytes from the **same project and profile**, not a rebuilt or fabricated old version. Export the `payload` directory from that prior release's independently verified staged run; create a ZIP with `staged-package-description.json`, `signed-release-manifest.json`, and all listed paths at ZIP root. Pin the whole ZIP via SHA-256 in the attestation-host configuration, and retain the origin release ID and original artifact hashes in your release records. Never include credential files or runner grants in this ZIP. The worker checks every file and the signed manifest identity before it begins the upgrade. NeverRuntime verifies the Ed25519 manifest under the operator-pinned release signing public key before launching the previous installation.

Host-only attestor configuration (in addition to the existing V04–V08 inputs):

```
--previous-bundle-file /sealed/releases/0.34.8.zip
--previous-sha $(sha256sum /sealed/releases/0.34.8.zip | cut -d' ' -f1)
--replacement-java-home /sealed/java/approved-alternative-jre
--managed-java-manifest-file /sealed/java/approved-temurin/MANAGED_JRE_MANIFEST.json
--managed-java-sha $(sha256sum /sealed/java/approved-temurin/MANAGED_JRE_MANIFEST.json | cut -d' ' -f1)
```

The previous release and alternate JRE are mounted read-only into an isolated, image-digest-pinned worker. Java replacement must be a **different Java binary with the exact major version required by the signed current release**; missing JRE, same binary, or a failed real GUI launch results in blocked/failed V09, not an asserted pass. The trusted attestor never mounts its signing key or production data into the worker.

For the **observational CI workflow**, configure `NL_VALIDATION_PREVIOUS_BUNDLE_URL` (HTTPS), `NL_VALIDATION_PREVIOUS_BUNDLE_SHA256`, `NL_VALIDATION_REPLACEMENT_JAVA`, `NL_VALIDATION_MANAGED_JRE_BUNDLE_URL`, `NL_VALIDATION_MANAGED_JRE_BUNDLE_SHA256`, and `NL_VALIDATION_MANAGED_JRE_MANIFEST_SHA256`. The CI downloader checks the prior bundle digest before running; the worker checks the internal manifests and file hashes again. This workflow never signs stable certification evidence.

## Real failure scenarios

1. Install and verify the older version on an empty client tree. Flip a byte in the **current signed input file** and run the normal update: it must fail, leaving all previous installed file hashes unchanged.
2. Restore the real staged bytes and upgrade with `client update`. Require `applied-and-verified` and a durable rollback snapshot.
3. Flip a byte in an installed file and a separate preferred cache copy. `client repair` must reject the corrupt cache. Remove the damaged cache entry, retry the normal repair from verified staged content, and check the complete installed file set.
4. Run the **same actual signed downloader** against an HTTP connection terminated partway through an actual staged file. Require nonzero failure, removal of `.partial`, and successful verified retry against the same original staged bytes. The fault-injection HTTP endpoint is loopback and never used as a stand-in for the package source in real materialization.
5. Install the previous version in two isolated directories. Run the real updater and terminate its process group with SIGKILL after observing its **durable** `staging` and `committing` journal phases (one scenario per directory). Run public `neverlauncher update recover`. The previous release must remain byte-identical, followed by a successful real update/reverification. If a journal phase could not actually be observed, the stage fails closed; no synthetic result is emitted.
6. Adopt the new signed client from the installed bytes with NeverRuntime; launch it through an alternate JRE and verify Java binary digest, version/major, renderer and positively observed menu/loader readiness. Independently run `neverruntime java ensure --manifest --manifest-sha256` in an isolated managed runtime root using an operator-pinned Temurin archive. Corrupt its installed Java executable, run the **same** manager again, require non-cached reinstatement with the original SHA-256 and successful real Minecraft menu launch through that recovered managed Java.
7. `client rollback` to the exact snapshot created before the successful update. Verify **every previously signed file's** size and SHA-256. Adopt and positively launch the restored version with NeverRuntime again.

A signed `update-recovery` attestation is impossible without `update-recovery.json` and independently verified on-disk previous-release bytes, CLI transaction reports, two runtime readiness reports and the required crash/recovery evidence. `update-recovery` is mandatory in the Backend staging report validator and evidence verifier; changing the worker report cannot skip it.

**Limitations:** This V09 implementation exercises Linux GUI runners and both a distinct alternate Java binary and the production `neverruntime java ensure` distribution manager. The manager is required to quarantine an intentionally damaged Java binary, reinstall it from a pinned Temurin archive, and successfully relaunch Minecraft. This does not replace a full Java-manager cross-platform release matrix. A fully trusted run requires the previously approved release ZIP, an alternative JRE of the matching major, a pinned Managed Java distribution manifest and its pinned vendor archive, the real Minecraft package, matching server, and live provider identities. Running Python unit tests alone is not a successful Minecraft runtime certification.

Stable remains blocked by the separate V11 stage-one gate until the end-to-end publication integration is delivered and certified.

Managed JRE bundle layout: `MANAGED_JRE_MANIFEST.json` at ZIP root alongside its vendor `.tar.gz` named in `targets[].archive`. The manifest must declare `productVersion=0.34.9`, exact platform/architecture, archive SHA-256 and size, java entry path and Temurin vendor. The operator's independent checksum pins the manifest and the container calls the production managed-Java installer (no substitute script). The host attestor mounts the uncompressed bundle directory read-only.

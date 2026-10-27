# NeverLauncher 0.33.9 — Player Migration Assistant (MIG09)

## Player workflow

1. Obtain NeverLauncher from the **project owner's official distribution**. Verify its publisher/signature via the existing Never installer/updater and operating-system signing guidance. MIG09 does **not** sign an installer or treat an arbitrary migration URL as trusted.
2. Complete first-run Backend binding, choose your Never project/profile/channel and pin the owner's independent Never Ed25519 public key. Load a valid **signed** release manifest.
3. Open **Переход с Gravit** and choose the existing legacy directory. The assistant suggests known candidate locations but never traverses the user's home recursively. Select the correct installation yourself.
4. Preview the manifest-pinned files available from the old installation. The inspection verifies real SHA-256/size bytes and rejects symlinks and unsafe paths. No files are moved/deleted.
5. Confirm. MIG09 re-scans and rechecks the source, then publishes matching objects to NeverRuntime's existing, **per-object OS-locked** content cache. Each object is rehashed during publication. Partial failures are safe: repeat the operation; objects already cached are reused.
6. Return to **Загрузка** and perform the ordinary signed release installation/repair; cached objects are restored by NeverRuntime's existing download pipeline and independently checked again. Files not found in the old installation download normally.
7. Optional components are **suggested by signed file hashes only**. The user must explicitly select and install the permitted preset using Never's existing component chooser. Unsupported Gravit actions are never executed.
8. With explicit player approval, only Minecraft `options.txt` display preferences (`fullscreen`, bounded `overrideWidth`, `overrideHeight`) are proposed; other preferences remain unchanged.
9. Sign in to NeverLauncher again and complete device enrollment / Guard attestation as required. Gravit auth sessions, device private keys and trust anchors are **not migrated**.

## Security and operational boundaries

- Signed Never manifest is mandatory. The old source and arbitrary local files are always untrusted.
- No bulk copying, autoexecution, symlink traversal, arbitrary extension imports, password transfer, credential storage, trusted key migration, or deletion of the old directory.
- Source layouts are bounded to the explicitly chosen directory, `.minecraft/`, `updates/<profile>`, `clients/<profile>`, and `<profile>`; unknown custom layouts may need manual selection of a different root.
- At most 30,000 signed selected files and 100 GiB of signed bytes are inspected per preview. An individual file is capped at 16 GiB. Only three whitelisted settings fields are considered.
- Content adoption is **cache-only**, not a live release install. It does not mark old bytes as Never-owned or publish an unsigned release. NeverRuntime's signed release installation remains necessary.
- Different Gravit layouts or patched jars can produce fewer matches, not an unsafe fallback. Unknown files are downloaded from Never's signed source instead of adopted.
- Existing CacheStore locks serialize with concurrent downloads and other processes. A failed scan leaves the game's installation untouched; a failed publication may leave previously verified cache objects, which are safe to reuse.
- `cargo test --lib player_migration_0339` and desktop build/check are required gates. Production acceptance additionally requires real Windows/macOS/Linux builds, signed installer validation, and end-to-end installation into a clean profile.

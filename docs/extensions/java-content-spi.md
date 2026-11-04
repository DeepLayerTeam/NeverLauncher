# 0.48.6 Java Content & Distribution SPI

The shipped Java SDK supplies `ContentServices.CONTRACT` and `ContentProvider`. A signed and enabled extension registers a concrete provider with `ExtensionContext.providers()` then selects it; the *existing* provider registry enforces API compatibility, bounded lifecycle and graceful shutdown. This release adds no public unsigned release route.

## Working operations

- `source(projectId,path)` resolves a SHA-256/size-pinned asset in existing project storage or a URL restricted to HTTPS. `runtime().content().readChecked(asset)` reads the real bytes **only** through the authenticated `storage.read` / `http.fetch` Go Host broker and checks size and SHA-256 before return. Existing permission grants, project scope and revocation continue to apply; HTTPS uses the Go DNS/IP filtering and signed outbound network policy where applicable.
- `texture(projectId,profileId,kind)` resolves pinned skin/cape bytes through the same broker and validation path. This does not grant access to another user's private texture.
- `metadata(projectId,releaseId,original)` produces supplemental metadata but refuses changes to `signature`, `files`, project/profile/channel/version and the game-trust generation/epoch. It does not re-sign release manifests.
- `preparePackage(projectId,name,bytes)` actually transforms bytes through the selected Java provider. Result is explicitly `requiresSigning=true` and carries a new SHA-256. It must pass existing integrity validation, signing, and publish gates **after** transformation; no automatic release is created.
- `delivery(projectId,path)` resolves a verified content source. There is **no** direct public HTTP redirect to an unverified provider URL and no delegated Minecraft trust decision.

The Go supervisor supports explicit authenticated `content.health`, `content.source.resolve`, `content.texture.resolve`, `content.metadata.enrich`, `content.package.prepare`, `content.delivery.resolve` JVM RPC. Content lookup/metadata callbacks require a current project-scoped `release:read` grant; package preparation requires `release:prepare`. Grants are revalidated after each callback. Commands are allowlisted and the existing 1.8-second deadline and 64 KiB RPC envelope remain enforced; package RPC is limited to 24 KiB, while in-JVM broker asset reads are bounded to 512 KiB. Larger production payloads still use the core's existing file upload/storage/distribution flow, not the callback transport.

## Production package upload integration (opt-in)

On the existing authenticated `POST /api/v1/packages/{packageId}/files` multipart upload route, the optional field `contentExtensionId=org.example.content-spi` selects a **running project-scoped** Java extension already granted `release:prepare`. Only files of at most 24 KiB may be processed by the synchronous Java RPC transport; larger uploads continue via the existing unmodified storage pipeline **without** this optional field. The backend validates the caller-supplied `sha256` against the original upload, calls the selected Java package transformer, rechecks the live extension grant, verifies the new bytes/size/SHA-256, stores those bytes through the existing `Storage.Save`, and records both old and new digests in the audit trail. On any failure, no untransformed fallback is stored. Signed or published packages cannot be transformed. The existing package validate, sign (Ed25519), stage and publish operations remain mandatory.

Do not pass `contentExtensionId` for an upload of a full game client or other large file; this version deliberately **does not** stream large artifacts through JVM RPC. It does not bypass existing content delivery or trust policy and does not automatically route public game downloads through Java.

## Build and test

```
sh sdk/java/core/build.sh test
sh examples/extensions/java-content-spi/build.sh
python3 examples/extensions/java-content-spi/test-runner.py
```

The sample is an actual executable Java Host JAR plus signable `.nlext` payload tree; `nl extension pack`/`verify` and the trusted publisher workflow remain required for installation. Host callbacks are tested using authenticated loopback HTTP, actual source bytes, tampered-content rejection and runtime permission revocation.

## Boundaries and outstanding acceptance

**This SPI does not replace existing package-upload, public client-download, release signing, Minecraft entitlement or texture-ownership authority.** A source provider may propose bytes or metadata, but it cannot make unverified artifacts trusted. A selected provider is integrated into bounded admin package uploads when `contentExtensionId` is explicitly supplied. Other source/texture/delivery resolution can be called via Java SDK and internal Go RPC, but **does not automatically intercept the public client distribution path**. This is a functional bounded SPI, **not** certification of the full production distribution workflow. Release GA still requires independent CI on JDK 17/21 and Go 1.27.3, native packaging, migration and Minecraft E2E gates.

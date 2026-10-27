# NeverLauncher 0.33.7 — Content & Profile Migration (MIG07)

## Scope and security guarantees

MIG07 imports **actual byte-verified content** from the same Gravit ZIP accepted
by MIG03, not file names alone. No Gravit JAR or module is executed on the API
host. Profiles are converted by `ConvertGravitProfile02210`; optional selections
are checked by `ConvertGravitOptionalView02411`. Unknown profile behavior, file
relocations, unsafe commands and unsupported optionals block automatic content
import. Source ZIP is spooled to a private temporary file and not retained.

A new Never Profile v2 and an owned Build Workspace are reserved in one
PostgreSQL transaction (`0095_gravit_content_0337.sql`). Source bytes are
rehash-checked per ZIP entry, encrypted with the normal authenticated workspace
object cipher and durably indexed via the existing revision-CAS repository.
Interruptions do not create new profiles or releases. Retry **the exact same**
run ID, source ZIP, profile path, owner, channel and version. The normal builder
revalidates all encrypted data, runtime/classpath settings and profile digest
before creating an unsigned draft release.

**No signing or publishing happens as part of file upload.** For migrated
packages, the existing release signer additionally checks every expected file
hash, size, ownership and optional component catalog against the MIG07 receipt.
It refuses altered or missing content. Normal high-assurance sign and publish
permissions and gates remain in force. No cutover is possible from MIG07.

## Operator runbook

1. Create and execute the durable MIG01 baseline. Analyze the Gravit installation
   with MIG02 and save its MIG03 source inventory (the original ZIP is needed at
   every import request). Select exactly one `profiles/*.json` profile.
2. Preview the import; review every `blocked`/`manual` field in the response.
   Supported profile client files are selected only from
   `updates/<profile-basename>/` or `clients/<profile-basename>/`, plus shared
   `libraries/` and `assets/`. Other profiles, auth, keys, modules, textures and
   ServerWrapper files are excluded. Paths may not collide after case-folding.
3. Confirm the run ID and import. On interrupted uploads repeat the same command;
   already-staged objects are decrypted and SHA-256 reverified, missing objects
   are restaged. Import pauses on any invalid source, disallowed target path,
   oversized individual file or failed build-workspace validation.
4. Build the staged workspace through the standard authenticated Build Workspace
   UI/API; verify the resulting unsigned v3 package.
5. If the preview reports supported optional actions, apply the converted
   component catalog to that unsigned v3 draft. Any manual catalog edits or
   changes to the package files cause the apply operation to fail. The normal
   package signer blocks migrated releases until the catalog matches.
6. Run standard package validation, sign with newly provisioned Never Ed25519
   keys through the existing phishing-resistant fresh-auth API, and then use
   standard approval/publish operations. Check launch, Forge/NeoForge classpath,
   profile settings, optional selections, and assets in the subsequent MIG10
   rehearsal before any cutover.

```bash
nl migrate gravit preview-content --backend https://never.example --token "$TOKEN" \
  --run "$RUN" --source ./gravit.zip --profile-path profiles/demo.json \
  --profile-id demo --loader forge --channel stable --version migrated-1 \
  --output ./content-preview.json
nl migrate gravit import-content --backend https://never.example --token "$TOKEN" \
  --run "$RUN" --source ./gravit.zip --profile-path profiles/demo.json \
  --profile-id demo --loader forge --channel stable --version migrated-1 \
  --output ./content-import.json
nl migrate gravit content --backend https://never.example --token "$TOKEN" \
  --run "$RUN" --profile-path profiles/demo.json
# After normal workspace build, for supported optional mods:
nl migrate gravit apply-optionals --backend https://never.example \
  --token "$TOKEN" --run "$RUN" --profile-path profiles/demo.json
```

**Important**: release preparation is not compatible with handing over Gravit
bootstrap classes or its own LaunchServer modules. A classpath referenced by
ClientProfile must be present in the authenticated source files, otherwise the
import is blocked. No source downloader, JAR launcher or unknown module adapter
is executed. The limit per staged file is 64 MiB (existing encrypted workspace
buffering), up to 25,000 files; MIG03 limits continue to apply (512 MiB
compressed / 2 GiB expanded). More complex source layouts require manual
selection and a separate verified build, never a guessed path rewrite.

**TextureProvider assets** belong to player identity, not a client release.
Use the existing production `services/api/cmd/gravit-textures-import-02510`
operator tool with source PostgreSQL/JSON records, independently verified PNG
objects and an explicit MIG04 UUID mapping. It supports dry-run and durable
upload receipts, does not fetch source `file_url`, and never silently overwrites
existing player textures. This is a separate offline operation; MIG07 does not
implicitly move `skins/`, `capes/` or `cloaks/` ZIP entries into the game client.

## Deployment/testing

Apply SQL migration `0095` in the standard migration runner before content
imports. Production requires access to the existing encrypted Build Workspace
storage and valid Never manifest signing configuration. Run
`.github/workflows/gravit-content-migration-0337.yml` using Go 1.27.3,
PostgreSQL 17, and Node 22; the workflow tests the real SQL transaction,
workspace retry, source parser with race detector, CLI and Admin build. The
content preview and CLI unit tests alone are **not production certification**.

Reports do not contain old password hashes, auth tokens, or private key
material. Source ZIPs may contain secrets, so store them offline and use HTTPS.
Never sign or publish when any manual/blocked compatibility issue remains
unresolved; a successful file import is not proof of runtime compatibility,
ServerBridge readiness, world-data preservation or permitted cutover.

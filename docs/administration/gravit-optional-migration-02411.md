# Gravit OptionalFile / OptionalView → NeverLauncher 0.24.11

This migration is **an executable Admin workflow**, not a direct import of
Gravit code or unverified filesystem paths. It converts recognized
`ClientProfile.updateOptional` entries to catalog v5 and then reuses the normal
Backend preview → atomic draft save → Ed25519 signing workflow.

## Admin workflow

1. Create an **unsigned Manifest v3** package in Release Workspace for the
   appropriate project/profile. All optional JARs must first be uploaded to
   this package with ownership `optional`. Upload paths must match the Gravit
   `file` action's original paths, without renaming. The Backend hashes actual
   bytes and controls the package's file inventory.
2. Open **Component Graph Editor → Gravit OptionalFile / OptionalView**.
   Upload a strict JSON ClientProfile (`updateOptional` array), or a raw array
   of OptionalFile objects. This does not fetch data from Gravit or run code.
3. Click **Проверить перенос Gravit** and inspect/export the per-field report.
   If any `blocked` or `manual` result exists, the automatic conversion is
   **not** applicable. Correct the source/ownership or port unsupported
   behavior manually in the signed graph editor, with independent review.
4. If the report is compatible and Backend graph preview succeeds, click
   **Перенести в редактор**. This changes only the local editor state. Run the
   standard Backend validation again, then save. The save performs revision
   CAS, full catalog validation and digest recomputation under package lock.
5. Sign, stage and publish through existing release controls. The consumer
   uses the normal verified native resolver. A Gravit payload cannot edit a
   previously signed snapshot or inject JVM commands.

## Supported lossless or controlled transformations

| Gravit | Never signed catalog v5 |
| --- | --- |
| `name` | Stable `gravit-<slug>-<hash>` component ID derived from exact name |
| `info` | Description |
| `mark`, `visible`, `limited:false` | Default selection and visibility |
| `category` | Category with stable name-derived ID |
| `dependenciesFile[].name`, `conflictFile[].name` | Exact-name lookup → stable component ID |
| `actions: [{type:'file',files:{'mods/a.jar':''}}]` | Owned signed `File` action, only for actual staged optional paths |
| `actions: [{type:'classpath',args:['mods/a.jar']}]` | Signed `ClassPath` action, only if owned and `useAltClasspath:false` |
| `actions: [{type:'jvmArgs'|'clientArgs',args:[]}]` | Only Never allowlisted signed arguments |
| `triggersList` required, non-inverted `os` | OS condition (`MUSTDIE`→`windows`, `MACOSX`→`macos`) |
| `triggersList` required, non-inverted `arch` | Supported arch condition |
| `triggersList` required, non-inverted `java` | Java major range (999 is unbounded) |

Component version `1.0.0` is an explicitly reported **migration placeholder**:
Gravit OptionalFile has no equivalent reliable SemVer. Review and update it
before introducing versioned dependency constraints. The source's unchanged
SHA-256 is included in the report so the reviewed input can be identified.

## Intentional blockers

- Missing, modified, unmanaged or already-owned staged file paths.
- Source → destination renames, directory moves and implicit directory copy.
- `groupFile` with selections, `isPreset:true`, and visual hierarchy
  `subTreeLevel>1`: Gravit selection semantics differ and need manual review.
- Dynamic/auto triggers (`required:false`), inverted triggers, arbitrary
  JavaFX requirements and unknown trigger fields.
- `limited:true` or nonzero Gravit permission bitmasks. Never cannot infer
  verified server entitlements from Gravit integer masks.
- System/alternate classpath, unsupported actions, unknown fields, unsafe JVM
  options and launch/authentication overrides.
- Unrecognized dependency target names, duplicate JSON members/names, cycles,
  file conflicts and invalid signed-catalog topology.
- Action-only optional components (Never catalog requires file ownership).

**This is not a migration of Gravit's runtime `OptionalView.enabled` user
selection state.** This endpoint recognizes a ClientProfile's `updateOptional`
component definitions or that definition array alone. User selection import
uses Never's separate signed component-ID selection workflow.

## API

`POST /api/v1/packages/{packageId}/component-catalog/gravit-preview`

Permission: `release:prepare` on the package, same as catalog preview/save.
JSON body: `{ "expectedRevision": 1, "source": "<verbatim Gravit JSON text>" }`.
The `source` can alternatively be a JSON object or array for API clients. A
JSON **string** preserves original source bytes for the SHA-256 report and
nested duplicate-key detection. A success response includes `migration`,
`preview`, `canApply` and diagnostics. It never writes to the repository.

Commit is intentionally performed through the existing
`PUT /api/v1/packages/{packageId}/component-catalog` with the reviewed
candidate and original expected revision. The Backend recomputes the digest.

## Verification

Go: `cd services/api && go test ./internal/model -run TestGravitOptional`.
Admin: `cd apps/admin && npm test`.
HTTP integration: `cd services/api && go test ./internal/httpapi -run TestGravitOptional`.
The last command requires the repository's external Go dependencies; full
end-to-end release signing, Desktop download and Minecraft launch must also
pass in production CI before declaring the full release certified.

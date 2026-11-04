# NeverLauncher 0.49.2 — complete Gravit profile discovery and verifiable dry-run

The existing `migrate gravit inventory` and `assess` operations establish a
verified source baseline. The new `dry-run-all` operation converts **each**
source ClientProfile on a single immutable ZIP upload using the same real
converter, optional-component validator, module inspection, identity extraction
and migration-plan calculator used for individual imports. It is read-only:
no players, profiles, worlds, extensions, permissions, files or channels are
created or replaced by this command.

## предварительные требования

Use the existing authenticated Backend with PostgreSQL storage, a prepared
`source_assessment` Gravit migration run and the *same* source ZIP that was
approved through `compatibility` and `inventory`. Invoke from an operator host
with a pinned TLS certificate and a short-lived bearer token. The Backend
rejects any change to the uploaded archive SHA-256, complete inventory manifest,
compatibility report, migration run revision/fence or live target snapshot.

Make an explicit mapping JSON file in an existing private directory (0600):

```json
[
  {
    "profilePath": "profiles/client-one.json",
    "profileId": "new-one",
    "profileName": "Client One",
    "loader": "vanilla",
    "channel": "stable",
    "version": "migration-1"
  },
  {
    "profilePath": "profiles/client-two.json",
    "profileId": "new-two",
    "profileName": "Client Two",
    "loader": "forge",
    "channel": "stable",
    "version": "migration-1"
  }
]
```

The mapping must contain **every** `client_profile` from the approved inventory
exactly once, with unique destination IDs and explicit destination settings.
There is an operational limit of 32 profiles per source. If a Gravit project
has more than 32, split it into explicitly separate reviewed migration runs;
never omit profiles from a report and then call it complete.

```bash
launcher migrate gravit dry-run-all \
  --backend https://launcher.example.org \
  --token "$LAUNCHER_TOKEN" \
  --run '<existing-run-id>' \
  --source /private/gravit-source.zip \
  --mapping /private/profile-map.json \
  --output /private/gravit-all-profiles.json

launcher migrate gravit verify-dry-run-all \
  --backend https://launcher.example.org \
  --token "$LAUNCHER_TOKEN" \
  --run '<existing-run-id>' \
  --source /private/gravit-source.zip \
  --mapping /private/profile-map.json \
  --report /private/gravit-all-profiles.json
```

The CLI creates the initial report with `0600` permissions, refusing to
replace an existing file. The verification command reuploads the full original
ZIP and mapping to the *live* Backend, recalculates all profiles against the
current target, verifies both report digests, and rejects changed reports,
source content, mappings and target state. An unkeyed SHA-256 is an integrity
check, not a signed authorization or independently witnessed attestation.

Inspect each `profiles[]` row: source client directory, deterministic
`filesSha256` and `planSha256`, count/transfer bytes, actual classpath library
references, optional dependencies/conflicts and explicit `blockers`. A report
with unresolved identity, version, module or client dependencies is `blocked`
and CLI exits nonzero. `manual` means **review required**, not approval to
publish or cut over.

An overlapping `dir` (including nested directories), duplicate destination ID,
missing profile, broken required classpath or cycle of optional-component
requirements is never silently merged. Unknown/unsupported Gravit behavior
remains in the blocker or manual list; no legacy JAR is loaded/executed.

For each accepted profile, subsequently use the original individual `dry-run`
operation, signed content staging/import and actual release validation; those
operations enforce their own durable plan and compare-and-swap guards. The
multi-profile report is not persisted as an alternate source of trust and
cannot bypass the ordinary import gates. Subsequent 0.49.3+ work addresses
full content migration and operational cutover.

## Acceptance evidence and limits

Local Go unit/regression tests demonstrate archive inventory, content
conversion and plan hashing on synthetic multi-profile ZIPs, including source
profile ID collisions, overlapping client directories and tampered reports.
They **do not** prove a migration of an independently supplied real Gravit
project. PostgreSQL/live Backend, signed native packages, real Java agents,
Minecraft login/join and multi-profile player/world continuity must be checked
on provisioned test installations. Any absent independent evidence means
production GA remains blocked.

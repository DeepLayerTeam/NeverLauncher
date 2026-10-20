# NeverLauncher CLI 0.24.9 — Components Tooling

`nl components` operates **offline** on signed Manifest v3 releases with component catalog schemas 1.0–5.0. The command is part of the existing Go CLI, not a separate demonstration binary or server endpoint. It uses the same versioned catalog digest, topology, condition, dependency, conflict and action implementations as the API (kept in `cli/internal/componentmodel` due to the CLI's separate module boundary).

## Trust and input

Production usage **requires** a trusted `--public-key` file: 32-byte Ed25519 public key in hex or accepted PEM form, provisioned independently from the manifest. The CLI checks the embedded signing key matches this trust anchor, verifies the signed Go manifest representation (including catalog and file metadata), recomputes catalog digest and rejects unowned/duplicate/unsafe component files. It does not treat the key contained in the manifest as a trust anchor.

`--allow-unsigned` is **only** for checking local drafts. It opts out of signature validation; JSON then explicitly reports `signatureVerified: false`. Do not use its output as release evidence. There is deliberately no `--permissions` argument: local claims are not verifiable account entitlements. Components guarded by permissions fail closed.

## Commands

```bash
# Verify the manifest's signature, catalog digest and every static preset graph.
nl components validate --manifest release.json --public-key publisher.pub --output validate.json

# Calculate an exact catalog selection under an explicitly specified runtime.
nl components resolve --manifest release.json --public-key publisher.pub \
  --preset quality --os linux --arch x86_64 --java-major 21 \
  --minecraft 1.21.1 --loader fabric --loader-version 0.16.1 \
  --output resolved.json

# Export the checked catalog and signed file metadata to deterministic JSON.
nl components export --manifest release.json --public-key publisher.pub --output catalog.json

# Compare catalog components and resolved file sets across two signed releases.
nl components diff --old previous.json --new release.json --public-key publisher.pub \
  --old-preset optimized --preset quality --os linux --arch x86_64 \
  --java-major 21 --minecraft 1.21.1 --loader fabric --loader-version 0.16.1 \
  --output diff.json

# Validate a local unsigned draft (never use for release approval):
nl components validate --manifest draft.json --allow-unsigned
```

Without `--output`, the only normal stdout data is JSON. `--output -` also writes to stdout. With `--output FILE`, the file is written using a temporary file and atomic rename. Output contains no volatile timestamps, random identifiers or runtime-generated ordering. Failures write a structured `status: error` JSON object, with `code`, `message`, and available component identifiers, and return a nonzero exit status.

### JSON semantics

- `validate`: `valid`, `signatureVerified`, `catalogRevision`, `catalogDigest`, `componentCount`, `presetCount`.
- `resolve`: resolved component IDs (in signed catalog order), reasons (`required`, `default`, `preset`, `dependency`), owner-scoped files sorted by path, owner-authored actions, `downloadBytes`, and a deterministic analysis-only `planSha256`.
- `export`: digest, topology, components, categories, groups, presets, conditions, signed actions, and file metadata.
- `diff`: component changes by stable ID (`addedComponents`, `removedComponents`, `changedComponents`), old/new resolved plans, and added/removed/changed file metadata.

`downloadBytes` is the total size of selected signed files, not a network traffic forecast after cache lookup. `planSha256` is an offline analytical digest and **not** an installer journal ID, ServerBridge attestation or signed manifest. The resolver never downloads, deletes, installs, executes component actions, or mutates manifests.

`--os` / `--arch` default to the platform running the CLI; Java, loader, and Minecraft version remain unset unless explicitly provided. If a selected component requires missing context, resolution fails rather than assuming compatibility. Static `validate` checks the graph and every preset without claiming that any particular runtime or user has satisfied its conditions.

## Verification

```bash
cd cli
go test ./internal/componentmodel ./cmd/neverlauncher -run 'TestCLIComponents' -count=1
go vet ./internal/componentmodel ./cmd/neverlauncher
```

To test a real signed v5 fixture, use `runtime/neverruntime/tests/fixtures/catalog_actions_0245_go_signed.json` and supply its expected publisher public key through a separately trusted file. Backend and CLI copies of the component engine are compared in the parity regression test to detect drift; keeping them synchronized is a release requirement.

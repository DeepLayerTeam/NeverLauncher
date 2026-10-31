# Launcher 0.22.3 — Runtime Constraints

## What runs

The production paths are `model.ValidateManifestSchema` (and its v2-only runtime constraints), `adminVersionManifestUpdate`, release publication integrity checks, and `runtime::{verify_manifest_signature,create_launch_plan_with_credentials,launch_with_timeout}`. New fields are stored in the existing signed Manifest v2 JSON; no SQL schema change is needed. Old Manifest v1 payloads and signatures remain unmodified.

### Example fields inside a v2 manifest

```json
{
  "runtime": {
    "java": {
      "majorVersion": 21,
      "minimumMajorVersion": 17,
      "recommendedMajorVersion": 21,
      "maximumMajorVersion": 25,
      "distribution": "temurin",
      "allowCustomPath": true
    },
    "memory": {"minimumMb": 2048, "recommendedMb": 4096, "maximumMb": 8192},
    "jvmArgs": ["-Xms2G", "-Xmx4G", "-Dexample=value with spaces"],
    "launch": {
      "classpathStrategy": "manifest",
      "classpathEntries": ["libraries/a.jar", "libraries/b.jar"],
      "environmentAllowlist": ["LANG", "DISPLAY"],
      "nativesDirectory": "natives"
    }
  }
}
```

* `java.majorVersion` remains mandatory in a runnable release and remains the default required Java major. `recommendedMajorVersion` selects the exact Java major for v2 when set. A Mojang compatibility profile must match its signed version metadata's major requirement. Custom Java paths must satisfy the managed/runtime selector's exact version check. `minimumMajorVersion`/`maximumMajorVersion` reject contradictory policies and prevent out-of-range selection.
* `memory` is in MiB. `-Xms`/`-Xmx` in JVM args are parsed, range-checked and rejected if duplicated or inconsistent. Missing values are filled from the profile memory policy during plan construction. The validation is applied before and after policy defaults, including Mojang-resolved arguments. Changing the UI memory preference is a separate feature of 0.22.9 and does not bypass this policy.
* `classpathEntries` / `modulepathEntries` are ordered lists of relative required JAR files in the same signed release. Duplicate, unsigned, unsafe, or platform-inapplicable entries are rejected; missing required content blocks real launch. When omitted, existing manifest-JAR discovery or signed Mojang compatibility resolution is retained.
* `mainModule` must be a Java module entrypoint of the form `module` or `module/qualified.Main`; it requires `modulepathEntries`. The Rust process builder uses `--module-path` and `-m` instead of the class main class for this mode. It does not call a shell.
* `environmentAllowlist` is an **allowlist of inherited variable names**, not values injected from a manifest. When nonempty, the child receives only those available inherited variables (plus Windows SystemRoot/WINDIR); Java option-injection variables are always excluded for v2. With an empty list, normal host environment inheritance remains, except for the unsafe Java override variables.
* V2 rejects shell-control characters in JVM/game args, launch-entrypoint overrides via `-cp`, `-jar`, `-m`, Java agents/bootclasspath/module-patch/command-on-error flags, and unknown classpath strategies. Authorized Java custom-agent behavior will require the signed custom-args feature in the later P07 milestone.

### Publication and backward compatibility

Existing published v1 releases are not re-signed or migrated. Incomplete draft manifests may remain persisted while being edited, but a v2 release cannot pass publication integrity checks without a usable Java major and valid runtime constraints. Editing a v2 draft changes the signed payload; the release must be re-signed using the existing publication path. The profile snapshot's identity and digest remain immutable.

### Verification

The Go `internal/model` test suite exercises valid Java module/classpath and environment policies and a matrix of rejection cases. The Rust unit suite exercises runtime policy and shell-free argument construction; its full execution requires the Rust toolchain and dependency cache. CI needs production API integration, end-to-end signed manifest import, real Java launch (classpath and modulepath), and multi-OS distribution tests before this version can be certified for GA.

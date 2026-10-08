# NeverExtensions Trust, Recovery & Certification — 0.20.12

The required certification target is Linux, Windows and macOS, enforced by `.github/workflows/neverextensions-trust-recovery-02012.yml`.
The checked-in `trust-recovery-targets-02012.json` defines the required platform set and checks; it intentionally contains no manually editable PASS state.

Each platform runner builds the Backend and CLI and executes trust-policy, revoked-key, quarantine, malicious-package, crash-loop kill-switch and migration tests. The aggregate job rejects missing/non-PASS evidence and publishes both JSON and Markdown public compatibility matrices as CI artifacts. This prevents a release from presenting a platform as certified without runner-produced evidence.

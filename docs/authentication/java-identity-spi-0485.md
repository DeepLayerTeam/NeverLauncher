# NeverLauncher 0.48.5 — Java IdentityProvider

Java extensions with `backend` target may register an `IdentityProvider` implementation through `ctx.providers().register(new ProviderDescriptor<>(IdentityServices.CONTRACT, ...))` and select it in `Extension.start()`. Implement `authenticatePassword`, `resolveIdentity`, `verifyProviderSession`, `revokeProviderSession`. These return `VerifiedIdentity` with a stable **issuer and subject** (not email) and `IdentityProof` containing provider-only session credentials and authentication methods. Throw `IdentityFailure` with stable codes for expected authentication failures. Never log secrets.

Install the signed extension globally and approve its **`auth:provider`** permission. In the existing Admin Auth Provider Wizard create a managed `java` provider with config:

```json
{"id":"company","extensionId":"example.identity","displayName":"Company Java Provider"}
```

Test and activate a revision using the normal admin approval process. The Go managed connector first checks that the running JVM reports an active SPI provider; subsequent login and explicit account-link flows call the authenticated loopback RPC. No new Java-facing public HTTP endpoint or direct database capability is added.

**Security:** the Go host checks the manifest and live grant both before and after each `auth.*` call; only a global extension can act as an identity provider. Disabling/quarantining the extension or revoking the grant causes Java auth requests to fail closed. `federation.Core` remains the only source of canonical account links, role policy, MFA and NeverLauncher sessions. Auto-provision is disabled for managed Java providers; users must be linked through existing routes with recent authentication and fresh provider proof. Provider session validation is not validation of a NeverLauncher session, and provider-token revocation does not replace the existing Never session revocation API. Official Microsoft/Minecraft ownership and entitlements must continue through the official code paths. Never accept an external provider's assertion of official Minecraft ownership as proof.

**Scope:** 0.48.5 provides password authentication, identity resolution and provider session validation/revocation; browser/OIDC flows remain owned by existing native connectors. Production release is blocked until independent CI and historical migration/release gates pass.

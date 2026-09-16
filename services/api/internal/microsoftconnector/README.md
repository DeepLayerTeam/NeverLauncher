# Microsoft Connector (0.11.6)

Production Microsoft identity provider for NeverLauncher Federation Core. It delegates standard OpenID Connect mechanics to `internal/oidcconnector` and adds Microsoft-specific tenant, issuer, cloud and stable-identity rules.

## Trust model

- Authorization Code + PKCE `S256`; no implicit flow.
- `tid + oid` is the external identity key. Email, `preferred_username` and display name are profile attributes only.
- `common` / `organizations` / `consumers` metadata is validated with tenant-specific token issuer and the `issuer` attached to the actual JWKS signing key.
- Optional `allowedTenantIds` narrows multitenant authorities.
- Only RS256 ID tokens are accepted by the Microsoft specialization.
- `offline_access` is always requested so refresh credentials can be rotated server-side.
- Microsoft refresh credentials never become Never access/refresh tokens and are encrypted before persistence.
- External groups/roles cannot assign a Never role except through explicit local `roleMappings` policy during JIT creation.

## Configuration

```json
[
  {
    "id": "microsoft",
    "cloud": "global",
    "tenant": "organizations",
    "clientId": "00000000-0000-0000-0000-000000000000",
    "clientSecretEnv": "MICROSOFT_CLIENT_SECRET",
    "redirectUris": ["https://launcher.example.com/api/v1/auth/oidc/microsoft/callback"],
    "postLogoutRedirectUris": ["https://launcher.example.com/"],
    "allowedTenantIds": ["11111111-2222-3333-4444-555555555555"],
    "provisioning": {"mode": "explicit-only"}
  }
]
```

Use `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` or `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE`. Secrets stay outside provider JSON through `clientSecretEnv` or `clientSecretFile`.

Supported clouds: `global`, `usgov`, `china`. `custom` exists for controlled testing/private-compatible authorities and requires `allowCustomAuthority=true` plus normal OIDC TLS/SSRF restrictions.

## Account linking and credentials

`explicit-only` is the default. An already authenticated Never user proves control of the Microsoft account through `/api/v1/auth/microsoft/{providerId}/link/begin` and `/link/complete`. Equality of email addresses is never sufficient to link accounts.

Refresh credentials are persisted in `provider_credentials` only as an AES-GCM envelope bound to user, auth identity, provider and subject. Rotation is performed through `/api/v1/auth/providers/{providerId}/credential/refresh`; the refreshed identity must keep the exact same subject.

Provider front-channel logout and Never session logout are separate operations. `/api/v1/auth/microsoft/{providerId}/logout-url` only returns an allowlisted Microsoft logout URL.

## Minecraft boundary

Successful Microsoft authentication is not treated as Minecraft ownership. This connector does not call Xbox/Minecraft entitlement/profile APIs and does not manufacture a Minecraft profile from Microsoft identity. Entitlement/profile verification is a separate compatibility layer.

# NeverLauncher OIDC Connector 0.11.5

Production connector implements OpenID Connect Authorization Code Flow with PKCE S256.

Security invariants:

- issuer is configured out of band and must exactly match Discovery and ID Token `iss`;
- Discovery requires HTTPS `authorization_endpoint`, `token_endpoint` and `jwks_uri`;
- outbound traffic uses an explicit allowlist, DNS/IP validation, TLS 1.2+, no environment proxy and no redirects;
- PKCE always uses `S256`; `plain` is never emitted;
- every login uses high-entropy `state` and `nonce`;
- ID Tokens reject `alg=none` and symmetric `HS*` algorithms and are verified with issuer JWKS;
- `aud`, multi-audience `azp`, `exp`, optional `nbf`/`iat`, signature and login `nonce` are verified before claims are trusted;
- UserInfo, when enabled, must return the same `sub` as the validated ID Token;
- external roles/groups never become a Never global role implicitly; local provisioning policy owns `defaultRole`;
- provider access/refresh tokens are internal connector credentials and never become Never access/refresh tokens.

Configured client authentication methods: `none`, `client_secret_basic`, `client_secret_post`. Public clients still use PKCE S256.

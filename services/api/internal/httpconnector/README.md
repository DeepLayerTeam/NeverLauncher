# NeverLauncher HTTP Auth Connector protocol v1

`0.11.4` использует этот протокол как реальный remote authentication transport. Connector не принимает произвольный URL из login request: все endpoints строятся только относительно заранее проверенного `baseUrl` provider-конфигурации.

## Endpoints

По умолчанию remote auth service реализует:

```text
POST /authenticate
POST /refresh
POST /resolve
POST /logout
GET  /health
```

Все ответы, включая ошибки, имеют `Content-Type: application/json` и подписываются тем же HMAC key, который настроен в NeverLauncher. Redirects запрещены.

Успешная identity response:

```json
{
  "protocolVersion": "neverlauncher-http-auth/1",
  "issuer": "website-auth-prod",
  "subject": "stable-external-user-id",
  "username": "player",
  "email": "player@example.com",
  "displayName": "Player",
  "groups": ["vip"],
  "roles": ["member"],
  "claims": {"region": "eu"},
  "authMethods": ["password"],
  "providerToken": "opaque-provider-token",
  "expiresAt": "2026-09-16T12:00:00Z"
}
```

`subject` обязан быть стабильным и неизменяемым идентификатором. `/resolve` обязан вернуть ровно тот же subject, который был запрошен. Email не является subject и не используется для implicit account linking.

Ошибка:

```json
{
  "protocolVersion": "neverlauncher-http-auth/1",
  "issuer": "website-auth-prod",
  "error": {"code": "invalid_credentials"}
}
```

NeverLauncher распознаёт `invalid_credentials`, `identity_disabled`, `identity_not_found` и `conflict`; `429`, timeout и `5xx` считаются временной недоступностью provider.

## Request envelope

`POST` request содержит:

```json
{
  "protocolVersion": "neverlauncher-http-auth/1",
  "requestId": "cryptographically-random-id",
  "timestamp": "2026-09-16T09:00:00Z",
  "identifier": "player@example.com",
  "password": "..."
}
```

Для `/resolve` используется `subject`, для `/refresh` — `providerToken`, для `/logout` — `subject` + `providerToken`. Provider token никогда не является Never access/refresh token.

## HMAC signing

Каждый request содержит:

```text
X-NeverLauncher-Key-Id
X-NeverLauncher-Timestamp
X-NeverLauncher-Nonce
X-NeverLauncher-Signature
X-NeverLauncher-Connector-Id
```

Request canonical string:

```text
METHOD\n
ESCAPED_PATH\n
UNIX_TIMESTAMP\n
NONCE\n
HEX_SHA256(BODY)
```

`X-NeverLauncher-Signature` равен `v1=` + lowercase hex `HMAC-SHA256(secret, canonical)`.

Remote service должен вернуть тот же `X-NeverLauncher-Nonce`, свой текущий `X-NeverLauncher-Timestamp`, тот же `X-NeverLauncher-Key-Id` и signature над:

```text
RESPONSE\n
HTTP_STATUS\n
UNIX_TIMESTAMP\n
NONCE\n
HEX_SHA256(BODY)
```

NeverLauncher использует constant-time HMAC comparison, проверяет timestamp window и отклоняет уже использованный response nonce.

## Network security

- Только HTTPS; plaintext HTTP не поддерживается.
- Redirects отключены.
- `hostAllowlist` проверяется перед каждым dial.
- DNS разрешается самим Connector’ом, все полученные IP проверяются до соединения, а dial выполняется непосредственно на уже проверенный IP — это закрывает обычный DNS-rebinding SSRF path.
- Loopback/private/link-local/multicast/shared/reserved/test networks заблокированы по умолчанию. Для контролируемого внутреннего auth service конкретная сеть должна быть явно указана в `allowedCidrs`.
- HTTP proxy environment variables намеренно не используются Connector’ом.
- TLS certificate verification включена; дополнительный CA задаётся `mtls.caFile`.
- Client certificate/key (`mtls.certFile` + `mtls.keyFile`) включают mutual TLS.
- Response body имеет жёсткий size limit и strict JSON schema decoding.

## Provider configuration

```json
[
  {
    "id": "website-http",
    "displayName": "Website account",
    "baseUrl": "https://auth.example.com/v1",
    "issuer": "website-auth-prod",
    "hostAllowlist": ["auth.example.com"],
    "hmac": {
      "keyId": "neverlauncher-prod",
      "secretEnv": "WEBSITE_AUTH_HTTP_HMAC_SECRET",
      "maxClockSkew": "2m"
    },
    "requestTimeout": "5s",
    "connectTimeout": "3s",
    "maxResponseBytes": 1048576,
    "provisioning": {"mode": "jit", "defaultRole": "player"}
  }
]
```

HMAC secret задаётся только через environment variable или secret file (`hmac.secretFile`), а не inline в provider JSON.

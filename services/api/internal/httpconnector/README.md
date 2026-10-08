# NeverLauncher HTTP Аутентификация Коннектор протокол v1

`0.11.4` использует этот протокол как реальный удалённый аутентификация транспорт. Коннектор не принимает произвольный URL из вход запрос: все эндпоинты строятся только относительно заранее проверенного `baseUrl` provider-конфигурации.

## Эндпоинты

По умолчанию удалённый аутентификация служба реализует:

```text
POST /authenticate
POST /refresh
POST /resolve
POST /logout
GET  /health
```

Все ответы, включая ошибки, имеют `Content-Type: application/json` и подписываются тем же HMAC ключ, который настроен в NeverLauncher. Перенаправления запрещены.

Успешная идентичность ответ:

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

`subject` обязан быть стабильным и неизменяемым идентификатором. `/resolve` обязан вернуть ровно тот же субъект, который был запрошен. Электронная почта не является субъект и не используется для implicit учётная запись связывание.

Ошибка:

```json
{
  "protocolVersion": "neverlauncher-http-auth/1",
  "issuer": "website-auth-prod",
  "error": {"code": "invalid_credentials"}
}
```

NeverLauncher распознаёт `invalid_credentials`, `identity_disabled`, `identity_not_found` и `conflict`; `429`, тайм-аут и `5xx` считаются временной недоступностью провайдер.

## Запрос конверт

`POST` запрос содержит:

```json
{
  "protocolVersion": "neverlauncher-http-auth/1",
  "requestId": "cryptographically-random-id",
  "timestamp": "2026-09-16T09:00:00Z",
  "identifier": "player@example.com",
  "password": "..."
}
```

Для `/resolve` используется `subject`, для `/refresh` — `providerToken`, для `/logout` — `subject` + `providerToken`. Провайдер токен никогда не является Никогда access/refresh токен.

## HMAC подписание

Каждый запрос содержит:

```text
X-NeverLauncher-Key-Id
X-NeverLauncher-Timestamp
X-NeverLauncher-Nonce
X-NeverLauncher-Signature
X-NeverLauncher-Connector-Id
```

Запрос канонический string:

```text
METHOD\n
ESCAPED_PATH\n
UNIX_TIMESTAMP\n
NONCE\n
HEX_SHA256(BODY)
```

`X-NeverLauncher-Signature` равен `v1=` + lowercase hex `HMAC-SHA256(secret, canonical)`.

Удалённый служба должен вернуть тот же `X-NeverLauncher-Nonce`, свой текущий `X-NeverLauncher-Timestamp`, тот же `X-NeverLauncher-Key-Id` и подпись над:

```text
RESPONSE\n
HTTP_STATUS\n
UNIX_TIMESTAMP\n
NONCE\n
HEX_SHA256(BODY)
```

NeverLauncher использует constant-время HMAC comparison, проверяет метка времени окно и отклоняет уже использованный ответ одноразовое значение.

## Сеть безопасность

- Только HTTPS; открытый текст HTTP не поддерживается.
- Перенаправления отключены.
- `hostAllowlist` проверяется перед каждым dial.
- DNS разрешается самим Коннектор’ом, все полученные IP проверяются до соединения, а dial выполняется непосредственно на уже проверенный IP — это закрывает обычный DNS-rebinding SSRF путь.
- Loopback/private/link-local/multicast/shared/reserved/test сеть заблокированы по умолчанию. Для контролируемого внутреннего аутентификация служба конкретная сеть должна быть явно указана в `allowedCidrs`.
- HTTP прокси переменные окружения намеренно не используются Коннектор’ом.
- TLS сертификат проверка включена; дополнительный CA задаётся `mtls.caFile`.
- Клиент certificate/key (`mtls.certFile` + `mtls.keyFile`) включают mutual TLS.
- Тело ответа имеет жёсткий размер ограничение и строгий JSON схема decoding.

## Провайдер конфигурация

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

HMAC секрет задаётся только через переменная окружения или секрет файл (`hmac.secretFile`), а не inline в провайдер JSON.

# Протокол HTTP-коннектора авторизации Launcher v1

`0.11.4` использует этот протокол для удалённой аутентификации. Коннектор не принимает произвольный URL из запроса на вход: все конечные точки строятся только относительно заранее проверенного `baseUrl` в конфигурации провайдера.

## Конечные точки

По умолчанию удалённый сервис аутентификации реализует:

```text
POST /authenticate
POST /refresh
POST /resolve
POST /logout
GET  /health
```

Все ответы, включая сообщения об ошибках, имеют `Content-Type: application/json` и подписываются тем же ключом HMAC, который настроен в Launcher. Перенаправления запрещены.

Успешный ответ с данными пользователя:

```json
{
  "protocolVersion": "launcher-http-auth/1",
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

`subject` обязан быть стабильным и неизменяемым идентификатором. `/resolve` обязан вернуть ровно тот же subject, который был запрошен. Электронная почта не заменяет `subject` и не используется для неявной привязки учётных записей.

Ошибка:

```json
{
  "protocolVersion": "launcher-http-auth/1",
  "issuer": "website-auth-prod",
  "error": {"code": "invalid_credentials"}
}
```

Launcher распознаёт `invalid_credentials`, `identity_disabled`, `identity_not_found` и `conflict`; `429`, тайм-ауты и `5xx` считаются временной недоступностью провайдера.

## Структура запроса

Запрос `POST` содержит:

```json
{
  "protocolVersion": "launcher-http-auth/1",
  "requestId": "cryptographically-random-id",
  "timestamp": "2026-09-16T09:00:00Z",
  "identifier": "player@example.com",
  "password": "..."
}
```

Для `/resolve` используется `subject`, для `/refresh` — `providerToken`, для `/logout` — `subject` + `providerToken`. Токен провайдера никогда не является токеном доступа или обновления Never.

## Подпись HMAC

Каждый запрос содержит:

```text
X-Launcher-Key-Id
X-Launcher-Timestamp
X-Launcher-Nonce
X-Launcher-Signature
X-Launcher-Connector-Id
```

Каноническая строка запроса:

```text
METHOD\n
ESCAPED_PATH\n
UNIX_TIMESTAMP\n
NONCE\n
HEX_SHA256(BODY)
```

`X-Launcher-Signature` равен `v1=` с последующим `HMAC-SHA256(secret, canonical)` в шестнадцатеричном формате с буквами нижнего регистра.

Удалённый сервис должен вернуть тот же `X-Launcher-Nonce`, текущий `X-Launcher-Timestamp`, тот же `X-Launcher-Key-Id` и подпись над:

```text
RESPONSE\n
HTTP_STATUS\n
UNIX_TIMESTAMP\n
NONCE\n
HEX_SHA256(BODY)
```

Launcher сравнивает HMAC за постоянное время, проверяет допустимое отклонение временной метки и отклоняет повторное использование nonce ответа.

## Сетевая безопасность

- Только HTTPS; незашифрованный HTTP не поддерживается.
- Перенаправления отключены.
- `hostAllowlist` проверяется перед каждым соединением.
- DNS разрешается самим коннектором: все полученные IP-адреса проверяются до соединения, а подключение выполняется непосредственно к проверенному IP-адресу. Это предотвращает обычные SSRF-атаки с подменой DNS-ответа.
- Адреса обратной петли, частные, локальные для канала, многоадресные, общие, зарезервированные и тестовые сети по умолчанию заблокированы. Для доверенного внутреннего сервиса аутентификации соответствующая сеть должна быть явно включена в `allowedCidrs`.
- Коннектор намеренно не использует переменные окружения HTTP-прокси.
- Проверка сертификата TLS включена; дополнительный центр сертификации задаётся параметром `mtls.caFile`.
- Клиентский сертификат и ключ (`mtls.certFile` + `mtls.keyFile`) включают взаимную аутентификацию TLS.
- Размер тела ответа строго ограничен; JSON разбирается с проверкой соответствия схеме.

## Конфигурация провайдера

```json
[
  {
    "id": "website-http",
    "displayName": "Website account",
    "baseUrl": "https://auth.example.com/v1",
    "issuer": "website-auth-prod",
    "hostAllowlist": ["auth.example.com"],
    "hmac": {
      "keyId": "launcher-prod",
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

Секрет HMAC задаётся только через переменную окружения или файл секрета (`hmac.secretFile`), но не непосредственно в JSON-конфигурации провайдера.

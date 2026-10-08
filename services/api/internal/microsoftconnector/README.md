# Microsoft Коннектор (0.11.6)

Рабочий Microsoft идентичность провайдер для NeverLauncher Федерация Ядро. Это delegates standard OpenID Подключение mechanics к `internal/oidcconnector` и добавляет Microsoft-specific tenant, издатель, cloud и стабильный-идентичность правила.

## Доверие модель

- Авторизация Код + PKCE `S256`; нет implicit поток.
- `tid + oid` является внешний идентичность ключ. Электронная почта, `preferred_username` и отображать имя являются профиль attributes только.
- `common` / `organizations` / `consumers` метаданные является проверен с tenant-specific токен издатель и `issuer` подключение к фактический JWKS ключ подписи.
- Необязательный `allowedTenantIds` narrows multitenant authorities.
- Только RS256 ID токены являются принят через Microsoft specialization.
- `offline_access` является всегда запрошенный так обновление учётные данные может быть ротировать на стороне сервера.
- Microsoft обновление учётные данные никогда становиться Никогда access/refresh токены и являются зашифрованный до хранение.
- Внешний groups/roles не может assign Никогда роль except через явный локальный `roleMappings` политика во время JIT создание.

## Конфигурация

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

Использовать `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` или `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE`. Секреты оставаться вне провайдер JSON через `clientSecretEnv` или `clientSecretFile`.

Поддерживаемый clouds: `global`, `usgov`, `china`. `custom` существует для controlled testing/private-compatible authorities и требует `allowCustomAuthority=true` плюс обычный OIDC TLS/SSRF restrictions.

## Учётная запись связывание и учётные данные

`explicit-only` является по умолчанию. уже аутентифицировать Никогда пользователь доказывает управление Microsoft учётная запись через `/api/v1/auth/microsoft/{providerId}/link/begin` и `/link/complete`. Equality электронная почта адрес является никогда sufficient к связь учётные записи.

Обновление учётные данные являются сохранённый в `provider_credentials` только как AES-GCM конверт привязанный к пользователь, аутентификация идентичность, провайдер и субъект. Ротация является performed через `/api/v1/auth/providers/{providerId}/credential/refresh`; обновление идентичность должен сохранять точный одинаковый субъект.

Провайдер front-канал выход и Никогда сессия выход являются отдельный эксплуатация. `/api/v1/auth/microsoft/{providerId}/logout-url` только возвращает список разрешений Microsoft выход URL.

## Minecraft граница

Успешный Microsoft аутентификация является не treated как Minecraft владение. Этот коннектор делает не вызов Xbox/Minecraft entitlement/profile APIs и делает не manufacture Профиль Minecraft из Microsoft идентичность. Entitlement/profile проверка является отдельный совместимость слой.

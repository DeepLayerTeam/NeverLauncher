# Коннектор Microsoft (0.11.6)

Промышленный коннектор Microsoft для ядра федеративной авторизации Launcher. Стандартные механизмы OpenID Connect делегируются компоненту `internal/oidcconnector`; дополнительно применяются правила Microsoft для арендаторов, издателей токенов, облачных сред и устойчивой идентификации.

## Модель доверия

- Используется Authorization Code + PKCE `S256`; неявный поток не поддерживается.
- Ключ внешней учётной записи — сочетание `tid + oid`. Адрес электронной почты, `preferred_username` и отображаемое имя считаются только атрибутами профиля.
- Для метаданных `common` / `organizations` / `consumers` проверяются издатель токена конкретного арендатора и `issuer`, связанный с фактическим ключом подписи JWKS.
- Необязательный параметр `allowedTenantIds` ограничивает разрешённые организации в многопользовательском режиме.
- Специализация Microsoft принимает только ID-токены с алгоритмом RS256.
- Область `offline_access` запрашивается всегда для серверной ротации учётных данных обновления.
- Учётные данные обновления Microsoft не преобразуются в access/refresh-токены Never и перед сохранением шифруются.
- Внешние группы и роли не могут назначить роль Never, кроме явно настроенного локального правила `roleMappings` при создании пользователя по JIT.

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

Используйте `LAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` либо `LAUNCHER_AUTH_MICROSOFT_PROVIDERS_FILE`. Секреты задаются вне JSON-конфигурации провайдера посредством `clientSecretEnv` или `clientSecretFile`.

Поддерживаемые облака: `global`, `usgov`, `china`. Вариант `custom` предназначен для контролируемого тестирования или частных совместимых центров авторизации. Он требует `allowCustomAuthority=true` и соблюдения обычных ограничений OIDC по TLS и SSRF.

## Привязка аккаунтов и учётные данные

По умолчанию действует режим `explicit-only`. Уже авторизованный пользователь Never подтверждает владение учётной записью Microsoft через `/api/v1/auth/microsoft/{providerId}/link/begin` и `/link/complete`. Совпадения адресов электронной почты недостаточно для связывания аккаунтов.

Учётные данные обновления хранятся в `provider_credentials` исключительно в конверте AES-GCM, привязанном к пользователю, идентификации, провайдеру и субъекту. Ротация выполняется через `/api/v1/auth/providers/{providerId}/credential/refresh`; после обновления идентификатор субъекта должен остаться прежним.

Выход на стороне провайдера и завершение сессии Never — отдельные операции. `/api/v1/auth/microsoft/{providerId}/logout-url` только возвращает разрешённый URL выхода Microsoft.

## Границы взаимодействия с Minecraft

Успешная авторизация Microsoft сама по себе не подтверждает право владения Minecraft. Коннектор не вызывает API Xbox/Minecraft для проверки лицензии или профиля и не создаёт Minecraft-профиль на основании учётной записи Microsoft. Проверка лицензии и профиля относится к отдельному слою совместимости.

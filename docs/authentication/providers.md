# Аутентификация и внешние провайдеры

Backend включает внутреннюю auth-систему, поддержку SQL/HTTP/OIDC-провайдеров, федерацию Microsoft identity, MFA/WebAuthn, сессии и device trust. Реальная доступность способа входа зависит от конкретной конфигурации и тестов.

| Вариант | Конфигурация | Особенности |
| --- | --- | --- |
| Встроенные аккаунты | `NEVERLAUNCHER_AUTH_TOKEN_*` | Выдача и отзыв токенов, политика сессий |
| SQL | `NEVERLAUNCHER_AUTH_SQL_PROVIDERS_JSON` или `_FILE` | Изолированные DSN и проверка password hashing |
| HTTP | `NEVERLAUNCHER_AUTH_HTTP_PROVIDERS_JSON` или `_FILE` | HTTPS, host allowlist и подписанные ответы |
| OIDC | `NEVERLAUNCHER_AUTH_OIDC_PROVIDERS_JSON` или `_FILE` | Authorization Code + PKCE, issuer/JWKS validation |
| Microsoft identity | `NEVERLAUNCHER_AUTH_MICROSOFT_PROVIDERS_JSON` или `_FILE` | Федерация учётной записи; **не тождественна** владению Minecraft Java Edition |
| Passkeys/WebAuthn | `NEVERLAUNCHER_WEBAUTHN_RP_*`, `NEVERLAUNCHER_WEBAUTHN_ORIGINS` | HTTPS и RP ID, соответствующий домену |

## Различие между Microsoft login и Minecraft login

Аутентификация Microsoft OAuth/OIDC удостоверяет идентичность пользователя. Получение Minecraft-токена и подтверждение ownership/profile — отдельная цепочка. Не считайте наличие федерации Microsoft готовой официальной Minecraft-аутентификацией без end-to-end проверок Minecraft Services.

## Рекомендации по защите

Секреты провайдеров передавайте через secret manager/окружение. Не смешивайте JSON и FILE-конфиг одного провайдера, если обработчик запрещает это. Ограничивайте redirect URI, origins и host allowlist. Используйте короткие сессии, отзыв, аудит и защиту от replay. Актуальные примеры ключей и названий параметров: [`.env.example`](../../.env.example), [`deploy/production/env.production.example`](../../deploy/production/env.production.example).

## Provider Routing & Account Linking (0.29.3)

`POST /api/v1/auth/login` принимает `identifier`, `password` и необязательный `providerId`. Если `providerId` передан, выбирается **только** он. Если не передан, применяются точные правила `emailDomain`, затем `defaultProvider`. Для несопоставленного identifier настройка `requireExplicitProvider: true` требует `providerId`; по умолчанию сохраняется `local` для обратной совместимости. Ошибки пароля, отказ/недоступность, отсутствие identity и конфликты **никогда** не вызывают попытку входа в другом провайдере.

Настройка передаётся через `NEVERLAUNCHER_AUTH_ROUTING_JSON` **или** `NEVERLAUNCHER_AUTH_ROUTING_FILE`:

```json
{
  "version": 1,
  "defaultProvider": "local",
  "requireExplicitProvider": false,
  "rules": [
    { "emailDomain": "company.example", "providerId": "website", "strict": true }
  ],
  "linkingAllowProviders": ["website"]
}
```

Маршрутизация применяется к **password login**. OIDC/Microsoft browser login уже требует явный `providerId` в URL, привязан к серверной PKCE/state/nonce transaction и не подбирает провайдер по email. Если в конфигурации задан `strict: true`, указание другого провайдера при входе с соответствующим email отклоняется. `strict: false` разрешает явно выбрать другой провайдер, не разрешая fallback. Правила проверяют строку email-идентификатора; они **не** доказывают владение доменом или email.

Для привязки используются только `POST /api/v1/auth/providers/{providerId}/link/password` (с действительной Never-сессией и новым успешным паролем внешнего провайдера) либо `link/begin` + `link/complete` (с действительной Never-сессией, привязанной browser PKCE transaction и подтверждённой external identity). `linkingAllowProviders` задаёт allowlist для обоих потоков; опциональный `disableLinking: true` полностью запрещает новые привязки, не затрагивая вход или безопасное обновление credentials уже связанных identity. Без этих полей существующее явное связывание остаётся разрешённым. Указание произвольного email, username или subject без provider proof **не** связывает аккаунты. Повторная привязка `(provider, issuer, subject)` к чужому Never user и смена subject текущего `(user, provider, issuer)` запрещены. Различные issuer никогда не объединяются по одинаковому email.

Конфигурация валидируется при старте: неизвестные/не password-capable provider, некорректные/дублирующиеся домены, неизвестные версии, конфликт JSON+FILE и превышение 64 KiB останавливают запуск, не активируя частичное правило. При изменении маршрутизации проверяйте реальные login + explicit linking на тестовых учётных записях до доставки на production; конфигурация применяется при перезапуске Backend. Для защиты от обхода через имя пользователя без email задавайте `requireExplicitProvider: true` и полагайтесь на авторизацию уже проверенного identity/issuer.

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

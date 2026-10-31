# Модель угроз и доверия

## Основные активы

Аккаунты, refresh/access tokens, device private keys, JWT signing keys, package signatures, storage objects, ServerBridge identities, ключи обновлений, права и секреты расширений.

## Границы

| Граница | Риск | Обязательная защита |
| --- | --- | --- |
| Пользователь ↔ API | Подмена сессии, CSRF/XSS, brute-force | Auth, TLS, ограничение привилегий, rate limits, безопасные cookies/tokens, audit |
| Device ↔ Backend | Replay и выдача чужого ключа | Challenge freshness, проверка владения private key, привязка device identity, отзыв |
| Сервис ↔ storage | Подмена артефактов, path traversal | Подписанные manifest, SHA-256, безопасные пути, доверенное хранилище |
| Update ↔ filesystem | Частично применённый релиз, rollback bypass | Stage/verify до замены, транзакции, recovery, исключение downgrade |
| ServerBridge ↔ API | Подмена узла, повторы команд | Ключи узлов, одноразовые tickets, replay protection, role separation |
| Extensions ↔ host | Повышение прав и доступ к секретам | Capabilities, grants, процессная изоляция, quotas, quarantine |
| Release CI ↔ users | Подмена бинарников и сертификатов | exact-commit evidence, подписи, прозрачная цепочка поставки |

## Принципы

- **Fail closed:** при отсутствии сертификата, ключа или настоящего evidence операция не должна превращаться в PASS.
- **No secrets in logs:** токены/пароли/DSN необходимо редактировать до загрузки в CI или issue.
- **Vendor provenance != proof of possession:** владение зарегистрированным ключом не означает автоматически подтверждённую аттестацию TPM/Secure Enclave.
- **Auth federation != Minecraft ownership:** Microsoft OAuth/OIDC не заменяет отдельный lifecycle Minecraft Services.
- **Cross-platform evidence:** проверки Guard и system keyring должны учитывать реальные особенности платформ.

Возможные уязвимости сообщаются согласно [SECURITY.md](../../SECURITY.md). Для релизной сертификации см. [release-certification.md](release-certification.md).

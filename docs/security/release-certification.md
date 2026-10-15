# Сертификация и поставка релиза

## Что проверять

1. `VERSION`, lockfiles и схемы согласованы.
2. `schemas/openapi.yaml` проходит контрактную проверку.
3. Offline gates подтверждают security invariants, а не просто присутствие комментариев.
4. Go/Rust/TypeScript/Java тесты успешны; реальный Minecraft Client и loader прошли предусмотренные матрицы.
5. Сформированы и проверены certificate/evidence для **этого commit SHA**, ОС и архитектур.
6. Манифесты, packages, Guard/Bridge/JRE и release-артефакты подписаны согласно политикам поставки.
7. Перед публичной выдачей выполнены production preflight, backup и smoke.

## Локальные контракты

```bash
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
python3 scripts/release/test_fetch_exact_certifications.py
python3 scripts/smoke/offline/repository-policy.py
```

`NEVERLAUNCHER_PREFLIGHT_STRICT=1 bash scripts/release/preflight.sh` — строгий режим проверок, зависящий от платформы и установленного toolchain. `scripts/release/fetch-exact-certifications.py` работает с сертификатами GitHub, не должен пересылать auth bearer на адреса артефактов. Не встраивайте токены в публичные URL.

## Принцип честной сертификации

Отсутствующее, просроченное, подменённое, не относящееся к SHA или неуспешное evidence **запрещает** маркировку как certified. PASS нельзя получать путём исключения обязательного теста или отключения NeverGuard. Особенно внимательно проверяйте `.github/workflows/compatibility.yml`, `.github/workflows/device-trust.yml`, `.github/workflows/neverextensions-ga-0210.yml`, `.github/workflows/production-release-candidate.yml`.

См. [troubleshooting/ci](../troubleshooting/ci.md) и [COMPATIBILITY.md](../../COMPATIBILITY.md).

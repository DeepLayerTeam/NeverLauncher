# Диагностика GitHub Actions

## Источники

Workflows: `.github/workflows/ci.yml`, `compatibility.yml`, `device-trust.yml`, `security.yml`, `extensions-ga-0210.yml`, `production-release-candidate.yml` и delivery workflows. Проверяйте **точный SHA и job log**, а не только общий счётчик checks.

## Порядок расследования

1. Зафиксировать commit SHA, run URL, job name, платформу и первый содержательный error (не финальное `exit code 1`).
2. Определить тип: lint/contract, compilation, unit, integration, real Minecraft, security/adversarial, certificate aggregation.
3. Для контракта воспроизвести соответствующий `scripts/smoke/offline/*.py` и проверить, что тест утверждает *поведение*, а не только точную фразу.
4. Для платформенного отказа прочитать platform evidence и повторить с той же Java/OS/arch. Не помечать непроверенные комбинации PASS.
5. Для release-certificate ошибки проверить наличие всех обязательных evidence, их SHA, hashes и соответствие версии.
6. После исправления дождаться обязательных jobs **на новом коммите**. Результаты предыдущего SHA не доказывают готовность текущего.

## Базовые команды

```bash
python3 scripts/version/manage.py check
python3 scripts/contracts/validate-openapi.py
python3 scripts/smoke/offline/repository-policy.py
python3 scripts/release/test_fetch_exact_certifications.py
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
```

Если тест падает из-за недостающего строкового маркера в комментарии, не отключайте gate: сначала проверьте реальный security invariant, затем исправляйте источник рассинхронизации. Перед публичным релизом используйте [release certification](../security/release-certification.md).

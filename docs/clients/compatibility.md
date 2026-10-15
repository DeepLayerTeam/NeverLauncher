# Матрица Minecraft, загрузчиков и Java

Источник определений — `compatibility/targets.json`; статусы опубликованной сертификации должны выводиться из результатов workflow, а не угадываться по наличию строки.

В репозитории представлены Vanilla, Fabric, Quilt, Forge и NeoForge. Матрица включает разное окружение (ОС/архитектуру/JRE), при этом цель с `required: false` и `unavailableReason` намеренно не объявляется PASS.

## Как проверить определения

```bash
python3 scripts/compatibility/matrix.py validate --targets compatibility/targets.json
python3 scripts/compatibility/test_matrix.py
```

Для запуска настоящей игры используются e2e-сценарии и [compatibility workflow](../../.github/workflows/compatibility.yml). Успешный unit test resolver не является доказательством успешного запуска Minecraft/loader.

## Интерпретация статусов

- **PASS / CERTIFIED** — есть корректное evidence для требуемой платформы и текущего SHA.
- **FAIL** — необходимый сценарий не пройден.
- **NOT CERTIFIED** — прогон отсутствует, upstream недоступен или комбинация помечена необязательной.
- **QUEUED / IN PROGRESS** — окончательное решение ещё невозможно.

Подробное пояснение о недоступных upstream-сборках и Windows OpenGL находится в [COMPATIBILITY.md](../../COMPATIBILITY.md). Для изменения матрицы добавьте обоснование, тест и документированное поведение, а не просто новый номер Minecraft.

# NeverExtensions

NeverExtensions — система расширения возможностей Backend, Desktop и CLI. В проекте присутствуют registry, подписанные пакеты, управление версиями, установка/обновление, lifecycle, host protocol, permissions и event integration.

## Где начинать

- `neverextensions/` — файлы целевых сценариев/сертификации.
- `sdk/` — доступные SDK и типы.
- `examples/extensions/` — примеры backend/CLI расширений.
- `cli/cmd/neverlauncher/main.go` — команды `nl extension ...` и alias `nl plugin ...`.
- `services/api/internal/extension*`, `services/api/internal/httpapi/extension*` — backend implementation.

## Жизненный цикл

Подготовка metadata → упаковка → подпись и проверка → импорт/установка → разрешение capabilities → включение → вызовы host → telemetry/audit → обновление/rollback/disable/remove. Доверенный администратор должен иметь возможность отозвать grant и оперативно отключить расширение.

Полный список CLI включает `extension init|dev|test|build|pack|sign|verify|registry|updates|trust|quarantine|emergency|recovery|installed|install|enable|disable|update|rollback|uninstall|permissions|secrets`; конкретные опции проверяйте командой `nl` и исходниками.

## Ограничения

**Не запускайте недоверенные расширения без оценки sandbox boundary.** Уровень изоляции зависит от ОС; capabilities и подписи не заменяют изоляцию процессов и проверку содержимого. Подробности в [security-and-lifecycle.md](security-and-lifecycle.md).

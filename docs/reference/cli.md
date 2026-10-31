# Справочник CLI `nl`

Исходники: `cli/cmd/neverlauncher/`. Для сборки Go-модуля:

```bash
cd cli
go build -o nl ./cmd/neverlauncher
./nl version
./nl
```

Ниже перечислены основные группы; формат flags зависит от подкоманды (не применяйте несуществующие флаги по аналогии с другой группой).

| Группа | Пример | Назначение |
| --- | --- | --- |
| `version` | `nl version` | Номер CLI |
| `manifest` | `nl manifest validate ...` | Манифесты пакетов |
| `hashes` | `nl hashes check ...` | Контроль SHA-256 |
| `update` | `nl update plan ...` | Планирование и транзакционная замена |
| `diagnostics` | `nl diagnostics collect ...` | Логи, анонимизация, отчёты |
| `runtime` | `nl runtime vanilla-install ...` | Vanilla/loader materializers |
| `server-bridge` | `nl server-bridge status ...` | Регистрация, host и состояние узлов |
| `extension` | `nl extension status ...` | Управление Extensions |
| `install` | `nl install readiness ...` | Первоначальная установка |
| `db` | `nl db status ...` | Миграции и repository |
| `backup` | `nl backup status ...` | Создание/проверка/восстановление |
| `operations` | `nl operations readiness ...` | Эксплуатационные проверки |
| `release` | `nl release doctor ...` | Release readiness |

Backend-команды используют `--backend <url>`, а закрытые запросы могут требовать `--token` или `NEVERLAUNCHER_TOKEN`. Не записывайте токены в shell history, CI log и публичные отчёты. Полный help находится в `cli/cmd/neverlauncher/main.go`.

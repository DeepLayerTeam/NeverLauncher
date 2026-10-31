# NeverLauncher 0.42.0 — финальная приёмка серверной сети

## Что реально проверяется

Путь выполнения остаётся исполняемым: Admin → Backend (PostgreSQL) → TLS RemoteControl → Host Supervisor → JVM → ServerBridge → proxy/game adapter. Никакая положительная запись в manifest, OpenAPI, YAML или `result.json` **сама по себе не является** подтверждением исполнения.

**Исполняемые команды приёмки:**

```bash
# На доверенном Linux CI runner с реальным Docker, Java 21, Go, Gradle,
# PostgreSQL и доступными upstream Minecraft/Proxy образами:
GITHUB_SHA="$(git rev-parse HEAD)" \
  bash scripts/test/serverbridge-network-0420.sh

# После сборки конечного релиза (в build-release.sh выполняется автоматически):
python3 scripts/ga/accept_network_release_0420.py \
  --root . --release "dist/release-0.42.0" \
  --runtime "e2e/runtime" \
  --source-commit "$(git rev-parse HEAD)" \
  --out "dist/release-0.42.0/SERVER_NETWORK_ACCEPTANCE_0420.json"
```

`build-release.sh` проверяет неизменные SHA-256 всех **14** конечных ServerBridge JAR (включая Quilt, Sponge и Vanilla, которые раньше не копировались в release), их соответствие Gradle-сборке и точному списку манифеста. Проверяется исходный commit каждого runtime proof и соответствие JAR, который был проверен в живом процессе, тем байтам, которые окажутся в пакете. Подмена JAR после E2E приводит к блокировке подписи и выпуска.

Реальные Go/JVM `-race` тесты охватывают потерю ACK, журнал RemoteControl, crash, split-brain, конкурентные команды, start/stop/restart, crash-loop, backup/restore и защиту от нового запуска. `network-faults-0420.go-test.jsonl` проверяется построчно: каждый обязательный тест должен завершиться `pass`, пакет тестов также обязан завершиться `pass`; `skip`, `fail`, отсутствие теста и повреждение SHA-256 запрещены. Это отдельная ветка доказательств, которая не подменяет тест на настоящем Minecraft.

Сквозная приёмка дополнительно требует реальные Java/Paper/Minecraft login, проверку отзыва авторизации и handoff, переустановку/откат, сохранение и восстановление реальных `playerdata` и файлов плагинов. Для этих условий используются независимо проверяемые E2E-отчёты `0.29.0`, `0.36.4`, `0.39.8`. При потере любого доказательства статус не может стать `passed`.

## Важный блокирующий фактор

Сценарий `0.41.13` имеет подтверждаемое тестовое покрытие максимум **10 из 14** платформ: Velocity, BungeeCord, Waterfall, Spigot, Paper, Purpur, Folia, Fabric, Forge и NeoForge. **Bukkit, Quilt, Sponge и Vanilla sidecar ещё не имеют равнозначного реального серверного прогона.** Поэтому финальный `--all` пока ожидаемо завершается отказом. Локальные компиляция, тестовый RCON, имитация API или наличие JAR не заменяют live-сертификацию. Выпуск 0.42.0 в production **заблокирован** до предоставления настоящих 14 live-run proof и независимого итогового полного прогона.

При блокировке `SERVER_NETWORK_ACCEPTANCE_0420.json` не записывается; разрешение на подпись/публикацию не выдаётся. Для локальных негативных регрессий без Docker:

```bash
python3 -m unittest discover -s scripts/ga -p 'test_accept_network_release_0420.py' -v
python3 -m unittest discover -s serverbridge/tests -p '*04113.py' -v
python3 -m unittest discover -s e2e/scripts -p 'test_record_serverbridge_runtime_04113.py' -v
python3 scripts/version/manage.py check
```

Никогда не используйте синтетические JSON/JAR из `test_accept_network_release_0420.py` в реальном сертификате. Неверифицированный исход опасного действия должен оставаться `indeterminate` и не запускаться заново.

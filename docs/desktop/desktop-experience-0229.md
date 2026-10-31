# NeverLauncher 0.22.9 — Desktop Experience

## Рабочие функции

- Desktop сохраняет настройки Java, RAM, resolution, fullscreen, auto-enter, ServerBridge server ID, public game host/port и offlineEnabled в native `config.json`, с безопасными default при чтении 0.22.8.
- Изменения RAM/window/server application проходят браузерную и Rust валидацию, после чего преобразуются в аргументы настоящего Java-процесса. Пользовательские параметры не модифицируют и не переподписывают v1/v2 Manifest.
- Native runtime перекрывает `-Xmx` значением из разрешённого signed диапазона, передаёт classpath/modulepath с массивами аргументов без shell-интерпретации и сохраняет environment allowlist.
- Scoped server browser: `GET /api/v1/projects/{projectId}/profiles/{profileId}/servers` отдаёт безопасный срез активных узлов только нужного проекта и профиля; секреты node identity и внутренние routing details не передаются. Это discovery, а не разрешение на join. Фактический ServerBridge join по-прежнему проверяет серверный билет и обязательную аттестацию.
- ServerBridge node ID не равен Minecraft DNS/port. Для auto-enter пользователь указывает реальный публичный игровой адрес. Для Minecraft 1.20+ используется Quick Play, для более старых версий — `--server` и `--port`. ServerBridge one-time ticket запрашивается до auto-enter, чтобы Minecraft не опередил разрешение входа. Если сервер требует post-launch Continuous Guard Attestation v2, предварительный join не может быть подтверждён: auto-enter отклоняется, а обычный запуск и ручное подключение сохраняются. Для loader-специфичных нестандартных идентификаторов версии автоматический выбор Quick Play требует реальной E2E проверки.

## Offline

Offline поддерживается **только** для signed Manifest v2, где `runtime.launch.offlineMode` явно разрешён издателем. Manifest записывается как кеш локально после pinned-Ed25519 verification и повторно проверяется при загрузке и непосредственно перед offline launch. `projectId/profileId/channel/version/signature` должны совпадать с кешем. Runtime повторно проверяет целостность файлов перед запуском. Offline не выдаёт Minecraft session, Guard launch ticket и ServerBridge join. Он не предоставляет доступ к защищённым online-серверам и не обходит Guard process hardening.

## Ограничения сертификации

Запуск E2E на Windows/Linux/macOS, live PostgreSQL-backed ServerBridge, работу Quick Play для всех loader versions и Rust/Desktop production build необходимо подтвердить в полноценно provisioned CI. Текущая реализация не считается production-certified без этих проверок.

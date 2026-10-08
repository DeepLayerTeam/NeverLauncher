# NeverExtensions SDK 0.21.0

Этот каталог является исходник--truth SDK поставляемый с NeverLauncher 0.21.0.

- `backend/go` — аутентифицировать Хост расширений Протокол клиент, возможности, журналы, сигнал состояния и event/hook обратный вызов.
- `admin/typescript` — типизированный песочница Администратор `postMessage` мост.
- `desktop/typescript` — типизированный песочница Desktop/Tauri-broker мост.
- `desktop/rust` — сгенерированный Настольное приложение протокол types для нативный companion код, без привилегированный Tauri доступ.
- `cli/go` — аутентифицировать CLI цель application/command SDK.
- `api/extension-host-protocol.json` — канонический протокол type исходник используется через `scripts/sdk/generate-types.py`.

Разработчик жизненный цикл:

```sh
nl extension init --target backend,admin,desktop,cli --out my-extension
nl extension build my-extension
nl extension test my-extension
nl extension dev my-extension --target backend --grant telemetry:write
```

`NEVERLAUNCHER_SDK_ROOT` или `--sdk-root` может точка собирает в локальный SDK checkout. Без это, standard Go модуль разрешение является используется.

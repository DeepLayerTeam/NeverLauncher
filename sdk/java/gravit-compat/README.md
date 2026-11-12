# Адаптер совместимости Gravit 0.31.0 (ограниченный API)

Это **рабочий, намеренно ограниченный адаптер для переноса исходного кода** Java-модулей в стиле GravitLauncher, а не универсальный загрузчик JAR-файлов Gravit. Он работает в существующем хосте Java-расширений лаунчера (`java -jar`) под контролем супервизора Go с ограничениями времени и проверкой подписи Ed25519 пакетов `.nlext`. Внутренние API Gravit LaunchServer, LauncherRuntime и JavaFX отсутствуют и не имитируются. Реализация независимая и не копирует исходный код Gravit.

## Поддерживаемый API (фиксированный перечень)

| Тип / API | Фактическое поведение расширения |
|---|---|
| `pro.gravit.utils.Version` | Целочисленная версия из четырёх компонентов, сравнение, `Type`, `getVersionString` |
| `pro.gravit.launcher.base.modules.LauncherModule`, `LauncherInitContext` | `preInitAction` и `init` в рамках жизненного цикла хоста Java-расширений. Контекст `GravitInitContext` предоставляет настоящий `ExtensionContext` |
| `LauncherModuleInfo`, `LauncherModuleInfoBuilder` | Локальные метаданные модуля; неподдерживаемые внутренние зависимости Gravit отклоняются, а не помечаются как удовлетворённые |
| `LauncherModule.EventHandler`, `registerEvent()` | Типизированный адаптер поверх **настоящего** EventBus Go. Принимаются только разрешённые типы `@HostEvent`, имеющие соответствующие типы EventBus |
| `ReleasePublishedEvent`, `ProjectSavedEvent` | Соответствуют `release.published` и `project.saved`; сохраняются идентификатор события, проект, ключ идемпотентности и исходный JSON |
| `pro.gravit.utils.command.Command`, `CommandHandler.registerCommand()` | `invoke(String... args)` выполняется через реестр команд CLI/RPC с аутентификацией Extensions. Имена команд должны быть объявлены в подписанном манифесте `.nlext`; `CommandHandler.respond(Object)` возвращает ограниченный по размеру JSON |
| Модуль `AutoCloseable` | При остановке расширения вызывается `close`; локальные обработчики удаляются при выходе, а постоянные подписки бэкенда сохраняются |

**Не поддерживаются:** бинарная совместимость с неизменёнными исходными модулями, внутренние компоненты `LaunchServer`, `LaunchServerInitContext`, `LaunchServerPostInitPhase`, `PreConfigPhase`, поставщики и реестры, `ModulesConfigManager`, интерфейс JavaFX, `Event.cancel()` и семантика отмены событий, произвольные внутренние механизмы `CommandHandler` Gravit и непроверенные зависимости classpath. Вызовы неподдерживаемых методов отмены или типов событий отклоняются явно, а не принимаются молча. Переносите исходный код только на опубликованное подмножество API, используйте `ExtensionContext.runtime()` из Extensions для конфигурации, хранилища и секретов, объявляйте разрешения и зависимости в подписанном пакете. Имена пакетов Gravit используются исключительно для задокументированных классов; они не гарантируют ABI-совместимость между версиями Gravit.

## Сборка, запуск и упаковка

```sh
sh sdk/java/gravit-compat/build.sh test
sh examples/extensions/gravit-compat/build.sh
python3 examples/extensions/gravit-compat/test-runner.py
# Универсальная сборка действительно перенесённых исходников и создание подписанного пакета:
python3 tools/gravit-port/port.py --help
# Команда производственного подписания описана в docs/releases/0.42.11-gravit-source-port.md.
# Требуются Launcher CLI и заранее созданный защищённый закрытый ключ Ed25519.
nl extension pack examples/extensions/gravit-compat/build/package --output /tmp/gravit-port.nlext --private-key /secure/extension-private.pem
nl extension verify /tmp/gravit-port.nlext --public-key /secure/extension-public.pem
```

Для каждого переносимого модуля соберите самостоятельный JAR со следующими записями в манифесте:

```
Main-Class: ru.launcher.sdk.host.JavaExtensionHost
Launcher-Extension-Class: ru.launcher.sdk.gravit.GravitCompatExtension
Launcher-Gravit-Module-Class: your.package.YourPortedModule
```

SDK Java, адаптер и перенесённый класс должны находиться внутри этого JAR. Метод `extensionjava.Inspect()` на стороне Go **до запуска** процесса Java проверяет наличие классов адаптера и модуля; проверка подписи и доверия к издателю остаётся частью существующего жизненного цикла пакетов Extensions. Автоматическая загрузка произвольных JAR Gravit или внешних зависимостей через `Class-Path` не допускается. Для компиляции требуется Java 17 или новее; Java 21 также проверяется в CI.

В примере `PortedModule` наследуется от `LauncherModule`, получает настоящее событие `release.published`, сохраняет запись через брокер хранилища Go и предоставляет декларативно разрешённую CLI-команду `status`. Сквозной тест дочернего процесса запускает действительный JVM-хост из JAR, проверяет цикл hello/ready/heartbeat, вызывает обработчик события через аутентифицированный RPC, читает состояние во втором JVM-вызове CLI, отвергает неправильные токены и необъявленные команды. Имитация хоста в E2E проверяет только транспорт; перед сертификацией промышленного развёртывания проверяйте расширение с настоящим бэкендом Go. Команды исполняются в **доверенном системном процессе Java**, а не в песочнице.

Сигнатуры исходного API сверены с классами `LauncherModule`, `LauncherModuleInfoBuilder` и `Command` репозитория `GravitLauncher/Launcher` (ветка master на 25 октября 2026 года). Фактический набор API намеренно меньше; бинарные модули, связанные с полными исходными библиотеками, не считаются совместимыми. Проверенные границы описаны в `docs/releases/0.30.7-gravit-compat.md`.

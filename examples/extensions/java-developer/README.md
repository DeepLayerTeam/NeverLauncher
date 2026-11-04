# NeverLauncher 0.48.12 — пример Java-разработчика

Этот проект — настоящий **внешний** потребитель Java SDK. Собирайте его после публикации трёх артефактов SDK в `dist/java-sdk/maven` (см. `scripts/java/developer_e2e_04812.py`).

```sh
mvn --batch-mode --no-transfer-progress -f examples/extensions/java-developer-04812/pom.xml package
gradle -p examples/extensions/java-developer-04812 classes
python3 scripts/java/developer_e2e_04812.py --sdk-repo dist/java-sdk/maven
```

Задачи Maven и Gradle компилируются относительно опубликованного репозитория Maven, а не `sdk/java/core/build/classes`. Интеграционный исполнитель отдельно собирает запускаемый JAR JVM Host из опубликованного бинарного SDK и класса этого расширения, запускает настоящий дочерний процесс и проверяет аутентифицированные обратные вызовы Host, действия Admin/Desktop, настройки, CLI, отклонения по политике и корректное завершение. Ключ подписи в тесте не используется. Для установки пакета требуются действующий процесс `nl extension pack/verify`, доверие к издателю и явно выданные разрешения. Пример никогда не обходит эти проверки.

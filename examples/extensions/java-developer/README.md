# NeverLauncher Java Developer sample — 0.48.12

This source is a real **external** Java SDK consumer. Build after publishing the three SDK artifacts into `dist/java-sdk/maven` (see `scripts/java/developer_e2e_04812.py`).

```sh
mvn --batch-mode --no-transfer-progress -f examples/extensions/java-developer-04812/pom.xml package
gradle -p examples/extensions/java-developer-04812 classes
python3 scripts/java/developer_e2e_04812.py --sdk-repo dist/java-sdk/maven
```

The Maven and Gradle tasks compile against the published Maven repository (not `sdk/java/core/build/classes`). The integration runner separately assembles a runnable JVM Host JAR from the published binary SDK and this extension class, then starts a real subprocess and checks authenticated Host callbacks, Admin/Desktop actions, settings, CLI, policy rejections and clean shutdown. No signing key is used in this test; packaging for installation requires the existing `nl extension pack/verify` workflow, publisher trust and explicit permission grants. The sample never bypasses those checks.

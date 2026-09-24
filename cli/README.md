# NeverLauncher CLI

`nl` — операционный CLI для канонического NeverLauncher API `/api/v1`. Исторические RC/stable/platform/product/extension/beta status-only семейства команд удалены.

Все общие отчёты CLI, ранее помеченные историческими `schemaVersion` 4.x–8.x, используют единую версию схемы `1.0`. Специализированные форматы, например manifest/runtime schema, сохраняют собственные версии формата.

## Основные команды

```bash
nl version
nl manifest ...
nl update ...
nl runtime ...
nl loader ...
nl project ...
nl diagnostics ...
```

## Minecraft runtime materialization

Рабочие materializer-команды:

```bash
nl runtime vanilla-package --minecraft 1.21.1 --client-dir .neverlauncher/vanilla/1.21.1 --output client-package.json
nl runtime fabric-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/fabric/1.21.1 --output client-package.json
nl runtime quilt-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/quilt/1.21.1 --output client-package.json
nl runtime forge-package --minecraft 1.20.1 --loader-version latest-stable --client-dir .neverlauncher/forge/1.20.1 --output client-package.json
nl runtime neoforge-package --minecraft 1.21.1 --loader-version latest-stable --client-dir .neverlauncher/neoforge/1.21.1 --output client-package.json
```

Fabric использует официальный Meta API v2, Quilt — Meta API v3. Forge и NeoForge загружают проверенный official Maven installer JAR, выполняют client processors из `install_profile.json`, проверяют outputs и нормализуют дочерний `version.json`. До упаковки mutable alias `latest-stable` разрешается в конкретную loader version, а все runtime artifacts фиксируются обычным SHA-256 + signed manifest lifecycle NeverLauncher.

## Операции Backend

```bash
nl auth login --backend https://launcher.example
nl auth sessions --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl admin overview --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl install readiness --backend https://launcher.example
nl operations diagnostics --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl backup status --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
```

Первичная инициализация администратора использует одноразовый bootstrap-заголовок:

```bash
nl install bootstrap-admin \
  --backend https://launcher.example \
  --bootstrap-token "$NEVERLAUNCHER_BOOTSTRAP_TOKEN" \
  --email admin@example.test \
  --password '...'
```

## Релизы и пакеты

```bash
nl release doctor
VERSION="$(cat VERSION)"
nl release build --out "dist/release-${VERSION}" \
  --compatibility-matrix /path/to/matrix.json \
  --compatibility-targets compatibility/targets.json \
  --guard-ci-matrix /path/to/guard-matrix.json \
  --guard-ci-targets guard-ci/targets.json \
  --source-commit "$(git rev-parse HEAD)"
nl release sign dist/release-${VERSION} --private-key /secure/release-private.pem
nl release verify dist/release-${VERSION} --public-key /etc/neverlauncher/release-public.pem
nl release publish-check dist/release-${VERSION} --public-key /etc/neverlauncher/release-public.pem
nl packaging prepare
nl packaging verify
```

Для `0.13.9+` publishable bundle требует exact-commit Guard CI evidence для Linux/Windows/macOS. `scripts/release/build-release.sh` получает пути через `NEVERLAUNCHER_GUARD_CI_MATRIX_FILE`, `NEVERLAUNCHER_GUARD_CI_TARGETS_FILE` и `NEVERLAUNCHER_GUARD_PLATFORM_ARTIFACTS_DIR`; CLI повторно проверяет exact platform artifact hashes при `release build` и `release publish-check`.

Для обращений к Backend используйте `--backend`, а для защищённых маршрутов `/api/v1` — `--token` или `NEVERLAUNCHER_TOKEN`.

## Production-операции без status-only заглушек

```bash
nl pipeline stage --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN" --package-id <id>
nl pipeline smoke-test --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN" --package-id <id>
nl pipeline publish --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN" --package-id <id>
nl storage consistency --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl storage audit --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl migrate apply --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl migrate rollback --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN" --backup-id <id> --confirm <id>
nl install storage-check --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
nl install verify --backend https://launcher.example --token "$NEVERLAUNCHER_TOKEN"
```

`release verify` и `security verify-signature` требуют внешний доверенный Ed25519 public key. Ключ, лежащий внутри проверяемого bundle, никогда не используется как trust anchor.

## P3.2v4: реальный client/desktop/key lifecycle

Client lifecycle использует уже собранный `client-package.json` и storage с тем же layout:

```bash
nl client install --package dist/client-package.json --storage-dir ./storage --client-dir ./minecraft
nl client verify --package dist/client-package.json --client-dir ./minecraft
nl client repair --package dist/client-package.json --storage-dir ./storage --client-dir ./minecraft
nl client cleanup --package dist/client-package.json --client-dir ./minecraft
nl client rollback --client-dir ./minecraft --target previous
```

`cleanup` не удаляет неизвестные файлы безвозвратно: управляемые orphan-файлы перемещаются в `.neverlauncher/quarantine`. Перед install/update/repair создаётся rollback snapshot.

Standalone first-run не зависит от исходного checkout и требует immutable image references:

```bash
nl install first-run --output-dir ./neverlauncher-production \
  --api-image registry.example/neverlauncher-api@sha256:<digest> \
  --admin-image registry.example/neverlauncher-admin@sha256:<digest>
```

Desktop package/verify работает только с реально собранными artifacts:

```bash
nl desktop package --artifact-dir dist/release-${VERSION} --out dist/desktop-package --platform linux
nl desktop verify dist/desktop-package
```

Key lifecycle и supply-chain:

```bash
nl security rotate-key --registry-dir /secure/neverlauncher-keys --key release-signing
nl security keys --registry-dir /secure/neverlauncher-keys
nl security revocation-list --registry-dir /secure/neverlauncher-keys --revoke <keyId>
nl security attest --path PROVENANCE.json --private-key /secure/.../private.pem
nl security sbom --source-root . --output SBOM.spdx.json
nl security provenance --source-root . --artifact-dir dist/release-${VERSION} --output PROVENANCE.json
```

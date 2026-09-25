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

## Unified Transactional Updater Core

```bash
nl update plan --from old.json --to new.json
nl update apply --from old.json --to new.json --source-root ./payload --root ./install
nl update status --root ./install
nl update recover --root ./install
nl update self-test
```

Для `0.15.7+` Desktop self-update использует внешний `nl update components` helper: production package обязан иметь pinned SHA-256 и platform component manifest, NeverGuard останавливается до switch, а Desktop/Guard/Runtime применяются одной rollback-boundary; macOS обновляет целый notarized `.app`.

Для `0.15.6+` `client install/update/repair/rollback/package-apply` используют один transactional engine: verified staging на том же filesystem, durable journal, backup только touched paths, atomic replace, post-verify и automatic crash rollback. Control state находится в `.neverlauncher/updater`; payload не может изменять этот каталог, проходить через symlink или выходить за install root.

## Релизы и пакеты

```bash
nl release doctor
VERSION="$(cat VERSION)"
nl release build --out "dist/release-${VERSION}" \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --compatibility-matrix /path/to/matrix.json \
  --compatibility-targets compatibility/targets.json \
  --guard-ci-matrix /path/to/guard-matrix.json \
  --guard-ci-targets guard-ci/targets.json \
  --source-commit "$(git rev-parse HEAD)"
nl release sign dist/release-${VERSION} --private-key /secure/release-private.pem
nl release verify dist/release-${VERSION} --public-key /etc/neverlauncher/root-public.pem \
  --trust-state /var/lib/neverlauncher/release-trust-state.json \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json
nl release publish-check dist/release-${VERSION} --public-key /etc/neverlauncher/root-public.pem \
  --trust-state /var/lib/neverlauncher/release-trust-state.json \
  --trust-policy /secure/RELEASE_TRUST_POLICY.json
nl delivery verify-windows --bundle dist/release-${VERSION} --version "${VERSION}" --production
nl delivery verify-public-matrix --bundle dist/release-${VERSION} --version "${VERSION}"
nl delivery public-e2e --matrix-url "https://github.com/DeepLayerTeam/NeverLauncher/releases/download/v${VERSION}/PUBLIC_PRODUCTION_DELIVERY_MATRIX.json" \
  --public-key /etc/neverlauncher/root-public.pem --trust-policy /secure/RELEASE_TRUST_POLICY.json \
  --trust-state /var/lib/neverlauncher/public-e2e-trust-state.json
nl packaging prepare
nl packaging verify
```


Для `0.15.2+` Windows publication дополнительно требует две канонические архитектуры (`windows-x64`, `windows-arm64`) и production `WINDOWS_SIGNING_EVIDENCE.json`. `release publish-check` повторно связывает подписанные PE/ZIP/package manifests с `DELIVERY_MANIFEST.json`; unsigned CI candidate публикацией не считается.

Для `0.13.9+` publishable bundle требует exact-commit Guard CI evidence для Linux/Windows/macOS. `scripts/release/build-release.sh` получает пути через `NEVERLAUNCHER_GUARD_CI_MATRIX_FILE`, `NEVERLAUNCHER_GUARD_CI_TARGETS_FILE` и `NEVERLAUNCHER_GUARD_PLATFORM_ARTIFACTS_DIR`; CLI повторно проверяет exact platform artifact hashes при `release build` и `release publish-check`.

В `0.13.10` каждый Guard target result также обязан совпадать по `repository`; evidence из другого fork отклоняется даже при совпавших commit/run. Перед production rollout с 0.13.9 выполните `nl db migrate apply` и `nl db migrate verify`: latest migration должна быть `0020_guard_migration_compatibility_stabilization_01310`. Для 0.14.2 latest migration — `0022_serverbridge_crypto_node_identities_0142`: shared ServerBridge bearer credentials удалены, public Ed25519 node identities и replay nonces стали PostgreSQL state; существующие 0.14.1 nodes требуют `rotate-identity` enrollment. Для 0.14.3 latest migration — `0023_one_time_join_tickets_0143`: активные legacy join authorizations сбрасываются на security boundary, новые ServerBridge tickets привязываются к exact node identity epoch/fingerprint и атомарно consume-ятся с redemption proof; Yggdrasil `/hasJoined` также consume-once.

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

`0.15.8+` `release verify` и `security verify-signature` требуют внешний offline-root Ed25519 public key и persistent trust state. Root key из bundle не принимается; release-signing key принимается только через root-signed `RELEASE_TRUST_POLICY.json`.

`0.15.9+` `PUBLIC_PRODUCTION_DELIVERY_MATRIX.json` обязан покрывать Windows/Linux/macOS x64+ARM64 и exact package/JRE/component bytes. `delivery public-e2e` предназначен для post-publish проверки реальных публичных URL и повторно запускает Release Verification v2 над скачанным bundle.

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

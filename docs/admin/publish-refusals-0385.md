# Публикация: причины отказов в Admin (0.38.5)

В Release Workspace на этапах «Проверка» и «Публикация» выполняется GET `/api/v1/packages/{packageId}/validations`. Поле `publishReadiness` формируется Backend из реальных проверок файлов, подписи, текущего integrity check и обязательного runtime evidence. Для stable используется независимая проверка ValidationEvidence v4 и матрицы required targets.

Каждая блокировка содержит `reasonCode`, `resource` (файл, пакет или целевой runtime), `message`, `action`. В частности: `package-files-empty`, `file-unavailable`, `file-integrity-mismatch`, `manifest-signature-invalid`, `signed-file-set-mismatch`, `manifest-compatibility-invalid`, `integrity-pass-missing`, `stable-runtime-target-blocked`, `runtime-policy-unsatisfied`. Прямой запрос публикации и durable operation preview возвращают структурированную ошибку `publish-blocked` при отказе.

Порядок восстановления: загрузить недостающие файлы / исправить профиль и создать новую сборку при необходимости; Validate → Sign → Stage → Integrity check → предоставить доверенное runtime evidence для установленных целей → повторить preview. Для stable загрузка старого v1 evidence не заменяет полную независимую сертификацию. Отправка ошибки или HTTP 200 с `status: invalid` не означает допуск.

`publishReadiness.eligible` обозначает только предварительный результат на момент чтения. Перед исполнением Backend повторно проверяет точные байты, подписи, доверие и актуальность разрешений; сама диагностика не выдаёт пропуск и не меняет состояние канала. Окончательный успех определяется состоянием durable job и channel head.

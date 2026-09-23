package ru.neverlauncher.bridge.common;

public final class JoinValidationResult {
    public final boolean allowed;
    public final String reason;
    public final String raw;

    public JoinValidationResult(boolean allowed, String reason, String raw) {
        this.allowed = allowed;
        this.reason = reason == null || reason.isBlank() ? (allowed ? "session_valid" : "session_denied") : reason;
        this.raw = raw;
    }

    public String userMessage() {
        return switch (reason) {
            case "backend_unavailable", "backend_interrupted" -> "Сервис авторизации NeverLauncher временно недоступен.";
            case "server_token_missing", "server_token_invalid" -> "ServerBridge не настроен или его server token недействителен.";
            case "trusted_device_required", "trusted_device_unverified", "trusted_device_missing", "trusted_device_revoked" -> "Для входа требуется активное доверенное устройство NeverLauncher.";
            case "credential_trust_snapshot_missing", "session_binding_changed", "session_device_changed" -> "Сессия устройства устарела. Перезапустите игру из NeverLauncher.";
            case "device_reattest_required" -> "Требуется повторная проверка устройства в NeverLauncher.";
            case "session_step_up_required" -> "Требуется дополнительная проверка входа в NeverLauncher.";
            case "session_risk_revoked", "parent_session_inactive" -> "Сессия NeverLauncher отозвана. Выполните вход заново.";
            case "project_mismatch", "profile_mismatch" -> "Эта сессия NeverLauncher не предназначена для данного сервера.";
            case "channel_mismatch" -> "Канал launcher session не совпадает с каналом сервера.";
            case "bridge_integrity_unavailable", "bridge_integrity_measurement_missing", "bridge_integrity_heartbeat_required", "bridge_integrity_policy_unavailable", "bridge_integrity_release_revoked", "bridge_integrity_hash_rejected", "bridge_integrity_server_type_mismatch", "bridge_integrity_request_measurement_mismatch" -> "Целостность ServerBridge не подтверждена. Обновите или перезапустите серверный bridge.";
            case "minecraft_integrity_session_required", "minecraft_integrity_binding_mismatch", "minecraft_integrity_repository_unavailable", "minecraft_integrity_session_inactive", "integrity_snapshot_missing", "integrity_release_revoked", "integrity_release_policy_unavailable", "integrity_attestation_not_fresh_at_issue", "integrity_attestation_hash_invalid", "integrity_evidence_hash_invalid", "integrity_guard_hash_invalid", "integrity_launcher_hash_invalid" -> "Целостность игровой сессии не подтверждена. Перезапустите Minecraft из NeverLauncher.";
            default -> "Вход разрешён только через действительную доверенную сессию NeverLauncher.";
        };
    }
}

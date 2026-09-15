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
}

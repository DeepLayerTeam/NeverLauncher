package ru.launcher.sdk.core;

/** Sanitized, stable error class for authentication flows; no credentials in messages. */
public final class IdentityFailure extends Exception {
    public enum Code { INVALID_CREDENTIALS, IDENTITY_DISABLED, IDENTITY_NOT_FOUND, CONFLICT, UNSUPPORTED, UNAVAILABLE, MISCONFIGURED }
    private final Code code;
    public IdentityFailure(Code code) {super(code.name());this.code=java.util.Objects.requireNonNull(code);}
    public Code code(){return code;}
}

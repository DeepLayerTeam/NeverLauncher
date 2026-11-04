package ru.launcher.sdk.core;

/** Очищенный стабильный класс ошибки для потоков аутентификации; сообщения не содержат учётных данных. */
public final class IdentityFailure extends Exception {
    public enum Code { INVALID_CREDENTIALS, IDENTITY_DISABLED, IDENTITY_NOT_FOUND, CONFLICT, UNSUPPORTED, UNAVAILABLE, MISCONFIGURED }
    private final Code code;
    public IdentityFailure(Code code) {super(code.name());this.code=java.util.Objects.requireNonNull(code);}
    public Code code(){return code;}
}

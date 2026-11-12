package ru.launcher.sdk.core;

/** Аутентифицированный внешний провайдер идентификации. Сеансы Launcher и учётные данные Minecraft
 * находятся исключительно в ведении Go-федерации и официального механизма Minecraft. */
public interface IdentityProvider extends JavaProvider {
    IdentityProof authenticatePassword(String identifier, String secret) throws IdentityFailure;
    VerifiedIdentity resolveIdentity(String subject) throws IdentityFailure;
    IdentityProof verifyProviderSession(String providerToken) throws IdentityFailure;
    void revokeProviderSession(String subject, String providerToken) throws IdentityFailure;
}

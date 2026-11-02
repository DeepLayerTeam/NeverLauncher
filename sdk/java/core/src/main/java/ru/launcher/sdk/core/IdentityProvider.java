package ru.launcher.sdk.core;

/** Authenticated external identity provider. Never sessions and Minecraft credentials
 * are exclusively owned by the Go federation and official Minecraft flow. */
public interface IdentityProvider extends JavaProvider {
    IdentityProof authenticatePassword(String identifier, String secret) throws IdentityFailure;
    VerifiedIdentity resolveIdentity(String subject) throws IdentityFailure;
    IdentityProof verifyProviderSession(String providerToken) throws IdentityFailure;
    void revokeProviderSession(String subject, String providerToken) throws IdentityFailure;
}

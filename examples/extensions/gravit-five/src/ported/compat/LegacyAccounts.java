package ported.compat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import ru.launcher.sdk.core.*;

/** Explicit PBKDF2-SHA256 source-port adapter. Unsupported Gravit hashes fail closed.
 * Secrets are never copied into a new NeverLauncher session: the Go federation owns sessions. */
public final class LegacyAccounts implements IdentityProvider {
    private RuntimeDocuments config;
    @Override public void start(ProviderContext ctx) { config = ctx.runtime().config(); }
    @Override public void stop(ProviderContext ctx) { config = null; }
    private Map<String,Object> accounts() throws IdentityFailure {
        try { return Json.object(config.get("legacy-identities", null).orElseThrow()); }
        catch(Exception e) { throw new IdentityFailure(IdentityFailure.Code.UNAVAILABLE); }
    }
    private Map<String,Object> account(String subject) throws IdentityFailure {
        Object entry=accounts().get(subject);
        if (!(entry instanceof Map<?,?>)) throw new IdentityFailure(IdentityFailure.Code.IDENTITY_NOT_FOUND);
        return Json.object(entry);
    }
    @Override public IdentityProof authenticatePassword(String identifier, String secret) throws IdentityFailure {
        if (identifier == null || secret == null || identifier.length()>128 || secret.length()>4096)
            throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
        try {
            var a = account(identifier);
            if (!"pbkdf2-sha256".equals(a.get("scheme"))) throw new IdentityFailure(IdentityFailure.Code.UNSUPPORTED);
            int rounds = ((Number)a.get("iterations")).intValue();
            if (rounds < 210_000 || rounds > 2_000_000) throw new IdentityFailure(IdentityFailure.Code.MISCONFIGURED);
            byte[] salt = HexFormat.of().parseHex(Json.string(a,"saltHex",true));
            byte[] expected = HexFormat.of().parseHex(Json.string(a,"hashHex",true));
            if (salt.length < 16 || salt.length > 64 || expected.length != 32) throw new IdentityFailure(IdentityFailure.Code.MISCONFIGURED);
            char[] chars = secret.toCharArray();
            PBEKeySpec spec = new PBEKeySpec(chars,salt,rounds,256);
            byte[] actual;
            try { actual = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
            finally { spec.clearPassword(); Arrays.fill(chars,'\0'); }
            boolean valid = MessageDigest.isEqual(actual,expected);
            Arrays.fill(actual,(byte)0);
            if (!valid) throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
            return new IdentityProof(verified(identifier,a),List.of("password"),null,0);
        } catch(IdentityFailure e) { throw e; }
          catch(Exception e) { throw new IdentityFailure(IdentityFailure.Code.MISCONFIGURED); }
    }
    @Override public VerifiedIdentity resolveIdentity(String subject) throws IdentityFailure {
        try {
            UUID uuid = UUID.fromString(subject);
            for (var entry:accounts().entrySet()) {
                if (Json.string(Json.object(entry.getValue()),"uuid",true).equals(uuid.toString()))
                    return verified(entry.getKey(),Json.object(entry.getValue()));
            }
            throw new IdentityFailure(IdentityFailure.Code.IDENTITY_NOT_FOUND);
        } catch(IllegalArgumentException e) { throw new IdentityFailure(IdentityFailure.Code.IDENTITY_NOT_FOUND); }
    }
    private VerifiedIdentity verified(String username,Map<String,Object> a) throws IdentityFailure {
        if (Boolean.TRUE.equals(a.get("disabled"))) throw new IdentityFailure(IdentityFailure.Code.IDENTITY_DISABLED);
        try {
            UUID uuid = UUID.fromString(Json.string(a,"uuid",true));
            return new VerifiedIdentity("neverlauncher-gravit-port", uuid.toString(), null, username,
                    Json.string(a,"name",true));
        } catch(Exception e) { throw new IdentityFailure(IdentityFailure.Code.MISCONFIGURED); }
    }
    @Override public IdentityProof verifyProviderSession(String token) throws IdentityFailure {
        throw new IdentityFailure(IdentityFailure.Code.UNSUPPORTED);
    }
    @Override public void revokeProviderSession(String subject, String token) throws IdentityFailure {
        throw new IdentityFailure(IdentityFailure.Code.UNSUPPORTED);
    }
}

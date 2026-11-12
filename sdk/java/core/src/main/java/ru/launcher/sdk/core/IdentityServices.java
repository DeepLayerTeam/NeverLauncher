package ru.launcher.sdk.core;

import java.util.*;

/** Выбранный Java SPI-провайдер вызывается только через аутентифицированный Host RPC с ограничениями.
 * Авторизация Backend, MFA, каноническая привязка аккаунтов и выдача токенов НЕ делегируются. */
public final class IdentityServices {
    public static final ProviderService<IdentityProvider> CONTRACT =
        new ProviderService<>("launcher.identity",IdentityProvider.class,SemVer.parse("1.0.0"));
    private volatile ProviderRegistry registry;
    void bind(ProviderRegistry value) {registry=Objects.requireNonNull(value);}
    private ProviderRegistry registry() {
        ProviderRegistry value=registry;
        if(value==null)throw new IllegalStateException("Служба идентификации SPI не инициализирована");
        return value;
    }
    public IdentityProof authenticatePassword(String identifier,String secret) throws IdentityFailure {
        if(identifier==null||identifier.isBlank()||identifier.length()>512||secret==null||secret.isEmpty()||secret.length()>4096)
            throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
        return call(p->p.authenticatePassword(identifier,secret));
    }
    public VerifiedIdentity resolveIdentity(String subject) throws IdentityFailure {
        if(subject==null||subject.isBlank()||subject.length()>512)throw new IdentityFailure(IdentityFailure.Code.IDENTITY_NOT_FOUND);
        VerifiedIdentity id=call(p->p.resolveIdentity(subject));
        if(!subject.equals(id.subject()))throw new IdentityFailure(IdentityFailure.Code.MISCONFIGURED);
        return id;
    }
    public IdentityProof verifyProviderSession(String token) throws IdentityFailure {
        if(token==null||token.isBlank()||token.length()>16384)throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
        IdentityProof result=call(p->p.verifyProviderSession(token));
        if(result.expiresAtEpochSeconds()!=0 && result.expiresAtEpochSeconds()<=java.time.Instant.now().getEpochSecond())
            throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
        return result;
    }
    public void revokeProviderSession(String subject,String token) throws IdentityFailure {
        if(subject==null||subject.isBlank()||subject.length()>512||token==null||token.isBlank()||token.length()>16384)
            throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
        call(p->{p.revokeProviderSession(subject,token);return null;});
    }
    private <T> T call(CheckedCall<T> action) throws IdentityFailure {
        if(registry().selected(CONTRACT.id()).isEmpty())throw new IdentityFailure(IdentityFailure.Code.UNAVAILABLE);
        try {
            return registry().call(CONTRACT, provider->{
                try{return action.run(provider);}catch(IdentityFailure e){throw new Wrapped(e);}
            });
        }catch(Wrapped e){throw e.failure;}
        catch(IllegalStateException | ProviderRegistry.CompatibilityException e){throw new IdentityFailure(IdentityFailure.Code.UNAVAILABLE);}
    }
    @FunctionalInterface private interface CheckedCall<T>{T run(IdentityProvider p)throws IdentityFailure;}
    private static final class Wrapped extends RuntimeException {
        final IdentityFailure failure;
        Wrapped(IdentityFailure failure){super(failure);this.failure=failure;}
    }
    Map<String,Object> dispatch(String method,Map<String,Object> params) {
        try {
            switch(method) {
                case "auth.health": {
                    return Map.of("available",registry().selected(CONTRACT.id()).isPresent());
                }
                case "auth.password": {
                    return Map.of("authentication",authenticatePassword(Json.string(params,"identifier",true),Json.string(params,"secret",true)).wire());
                }
                case "auth.resolve": {
                    return Map.of("identity",resolveIdentity(Json.string(params,"subject",true)).wire());
                }
                case "auth.session.verify": {
                    return Map.of("authentication",verifyProviderSession(Json.string(params,"providerToken",true)).wire());
                }
                case "auth.session.revoke": {
                    revokeProviderSession(Json.string(params,"subject",true),Json.string(params,"providerToken",true));
                    return Map.of("revoked",true);
                }
                default: throw new IllegalArgumentException("Неизвестная операция авторизации");
            }
        }catch(IdentityFailure e){return Map.of("errorCode",e.code().name().toLowerCase(java.util.Locale.ROOT));}
        catch(IllegalArgumentException e){return Map.of("errorCode","invalid_credentials");}
    }
}

package ru.launcher.sdk.core;

import java.util.*;

/** Доказательство, возвращаемое после проверки секрета или принадлежащего провайдеру сеанса. */
public record IdentityProof(VerifiedIdentity identity, List<String> authMethods, String providerToken, long expiresAtEpochSeconds) {
    public IdentityProof {
        Objects.requireNonNull(identity,"проверенная учётная запись");
        authMethods = List.copyOf(Objects.requireNonNull(authMethods,"методы аутентификации"));
        if (authMethods.isEmpty() || authMethods.size() > 16 || authMethods.stream().anyMatch(v -> v==null || !v.matches("[a-zA-Z0-9._:-]{1,48}")))
            throw new IllegalArgumentException("Недопустимые методы аутентификации");
        if (providerToken != null && providerToken.length()>16384)throw new IllegalArgumentException("Токен провайдера превышает допустимый размер");
        if (expiresAtEpochSeconds < 0)throw new IllegalArgumentException("Срок действия не может быть отрицательным");
    }
    Map<String,Object> wire() {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("identity",identity.wire());result.put("authMethods",authMethods);
        result.put("providerToken",Objects.toString(providerToken,""));result.put("expiresAt",expiresAtEpochSeconds);
        return result;
    }
}

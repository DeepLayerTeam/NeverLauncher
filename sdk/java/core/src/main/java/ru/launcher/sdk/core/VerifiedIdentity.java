package ru.launcher.sdk.core;

import java.util.*;

/** Субъект — неизменяемый ключ пользователя у провайдера, а не email или отображаемое имя. */
public record VerifiedIdentity(String issuer, String subject, String email, String username, String displayName) {
    public VerifiedIdentity {
        if (subject == null || subject.isBlank() || subject.length() > 512 || issuer == null || issuer.isBlank() || issuer.length() > 2048)
            throw new IllegalArgumentException("invalid verified identity issuer/subject");
        if (email != null && email.length() > 512 || username != null && username.length() > 512 || displayName != null && displayName.length() > 1024)
            throw new IllegalArgumentException("invalid identity display fields");
    }
    Map<String,Object> wire() {
        Map<String,Object> value = new LinkedHashMap<>();
        value.put("issuer",issuer); value.put("subject",subject);
        value.put("email",Objects.toString(email,"")); value.put("username",Objects.toString(username,""));
        value.put("displayName",Objects.toString(displayName,"")); return value;
    }
}

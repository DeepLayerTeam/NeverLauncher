package ru.neverlauncher.bridge.common;

import java.time.Instant;
import java.util.List;

public record BridgeProtocolNegotiation(
    int protocolVersion,
    List<String> features,
    boolean legacyV2Fallback,
    Instant negotiatedAt,
    String securityProfile,
    String capabilityDigest
) {
    public BridgeProtocolNegotiation {
        features = List.copyOf(features == null ? List.of() : features);
        negotiatedAt = negotiatedAt == null ? Instant.now() : negotiatedAt;
        securityProfile = securityProfile == null ? "" : securityProfile.trim();
        capabilityDigest = capabilityDigest == null ? "" : capabilityDigest.trim().toLowerCase();
    }

    public BridgeProtocolNegotiation(int protocolVersion, List<String> features, boolean legacyV2Fallback, Instant negotiatedAt) {
        this(protocolVersion, features, legacyV2Fallback, negotiatedAt, "", "");
    }

    public boolean expired(Instant now) {
        return negotiatedAt.plusSeconds(300).isBefore(now);
    }
}

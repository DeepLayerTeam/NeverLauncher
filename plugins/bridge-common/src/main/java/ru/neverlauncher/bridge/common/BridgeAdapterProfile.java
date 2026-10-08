package ru.neverlauncher.bridge.common;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Immutable, executable capability profile for a concrete ServerBridge adapter. */
public record BridgeAdapterProfile(
    String platformId,
    String family,
    String role,
    Set<BridgeAdapterCapability> capabilities
) {
    public BridgeAdapterProfile {
        platformId = clean(platformId);
        family = clean(family);
        role = clean(role);
        capabilities = capabilities == null ? Set.of() : Set.copyOf(capabilities);
        if (platformId.isEmpty() || family.isEmpty() || role.isEmpty()) {
            throw new IllegalArgumentException("adapter platform/family/role are required");
        }
        if (!role.equals("backend") && !role.equals("proxy")) {
            throw new IllegalArgumentException("adapter role must be backend or proxy");
        }
    }

    public boolean supports(BridgeAdapterCapability capability) {
        return capability != null && capabilities.contains(capability);
    }

    /**
     * Merge platform-neutral protocol capabilities with the stable adapter
     * capability vocabulary exposed in runtime discovery.
     */
    public List<String> runtimeCapabilities(Collection<String> protocolCapabilities) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (protocolCapabilities != null) {
            for (String value : protocolCapabilities) {
                if (value != null && !value.isBlank()) out.add(value.trim().toLowerCase(Locale.ROOT));
            }
        }
        out.add("adapter.universal-v1");
        out.add("adapter.family." + family);
        out.add("adapter.role." + role);
        for (BridgeAdapterCapability capability : capabilities) out.add(capability.runtimeCapability());
        return List.copyOf(out);
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}

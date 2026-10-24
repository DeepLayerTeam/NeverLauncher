package ru.neverlauncher.bridge.common;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

/** Неизменяемые сведения о платформе, предоставленные конкретным адаптером ServerBridge. */
public record BridgeRuntimeDescriptor(
    String minecraftVersion,
    String platform,
    String loaderName,
    String loaderVersion,
    String serverBrand,
    List<String> capabilities
) {
    public BridgeRuntimeDescriptor {
        minecraftVersion = clean(minecraftVersion, 128);
        platform = clean(platform, 64).toLowerCase(Locale.ROOT);
        loaderName = clean(loaderName, 128);
        loaderVersion = clean(loaderVersion, 128);
        serverBrand = clean(serverBrand, 512);
        TreeSet<String> normalized = new TreeSet<>();
        if (capabilities != null) {
            for (String capability : capabilities) {
                capability = clean(capability, 128).toLowerCase(Locale.ROOT);
                if (!capability.isEmpty()) normalized.add(capability);
            }
        }
        BridgeAdapterProfile adapterProfile = BridgeAdapterProfiles.find(platform);
        if (adapterProfile != null) {
            // Plugin-provided free-form features may describe telemetry, but cannot
            // add an unsupported adapter.* claim to its signed runtime identity.
            java.util.Set<String> allowed = java.util.Set.copyOf(adapterProfile.runtimeCapabilities(List.of()));
            for (String claimed : normalized) {
                if (claimed.startsWith("adapter.") && !allowed.contains(claimed)) {
                    throw new IllegalArgumentException("unsupported adapter capability claim: " + claimed);
                }
            }
            normalized.addAll(allowed);
        }
        capabilities = List.copyOf(normalized);
    }

    public static BridgeRuntimeDescriptor of(
        String minecraftVersion,
        String platform,
        String loaderName,
        String loaderVersion,
        String serverBrand,
        Collection<String> capabilities
    ) {
        List<String> values = capabilities == null ? List.of() : new ArrayList<>(capabilities);
        return new BridgeRuntimeDescriptor(minecraftVersion, platform, loaderName, loaderVersion, serverBrand, values);
    }

    private static String clean(String value, int maxLength) {
        if (value == null) return "";
        String normalized = value.replace('\r', ' ').replace('\n', ' ').replace("\0", "").trim();
        if (normalized.length() > maxLength) return normalized.substring(0, maxLength);
        return normalized;
    }
}

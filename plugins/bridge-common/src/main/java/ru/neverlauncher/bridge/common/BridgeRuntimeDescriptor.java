package ru.neverlauncher.bridge.common;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;

/** Immutable platform facts contributed by the concrete ServerBridge adapter. */
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
            normalized.addAll(adapterProfile.runtimeCapabilities(List.of()));
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

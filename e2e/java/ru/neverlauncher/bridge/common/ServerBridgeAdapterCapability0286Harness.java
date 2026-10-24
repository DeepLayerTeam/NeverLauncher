package ru.neverlauncher.bridge.common;

import java.util.List;
import java.util.Set;

/** Executable Java capability policy tests. This is not a live Minecraft runtime E2E. */
public final class ServerBridgeAdapterCapability0286Harness {
    public static void main(String[] args) {
        Set<String> expected = Set.of("velocity", "bungeecord", "waterfall", "bukkit", "spigot", "paper",
            "purpur", "folia", "fabric", "quilt", "forge", "neoforge", "sponge", "vanilla");
        require(BridgeAdapterProfiles.supportedPlatforms().equals(expected), "missing or unexpected adapter");
        for (String id : expected) {
            BridgeAdapterProfile profile = BridgeAdapterProfiles.require(id);
            BridgeRuntimeDescriptor descriptor = BridgeRuntimeDescriptor.of("1.21.1", id, id, "1", id, List.of("runtime.discovery"));
            require(descriptor.capabilities().contains("adapter.universal-v1"), "universal missing: " + id);
            require(descriptor.capabilities().contains("adapter.role." + profile.role()), "role missing: " + id);
            require(descriptor.capabilities().contains("adapter.family." + profile.family()), "family missing: " + id);
            for (BridgeAdapterCapability cap : BridgeAdapterCapability.values()) {
                require(descriptor.capabilities().contains(cap.runtimeCapability()) == profile.supports(cap), id + " cap mismatch: " + cap);
            }
            for (String kind : List.of("player.kick", "message.broadcast", "whitelist.add", "whitelist.remove",
                "whitelist.enable", "whitelist.disable", "ban.add", "ban.remove", "server.save", "server.maintenance",
                "server.drain", "server.shutdown", "server.console")) {
                require(BridgeAdapterCapability.forControl(kind) != null, "unmapped operation " + kind);
            }
            require(BridgeAdapterCapability.forControl("server.shell") == null, "host shell became a game capability");
            try {
                BridgeRuntimeDescriptor.of("1.21.1", id, id, "1", id, List.of("adapter.control.root"));
                throw new AssertionError("accepted forged adapter capability for " + id);
            } catch (IllegalArgumentException expectedError) { /* fail closed */ }
            System.out.println("CAPABILITY_POLICY_OK platform=" + id + " caps=" + profile.capabilities().size());
        }
        BridgeAdapterProfile vanilla = BridgeAdapterProfiles.require("vanilla");
        require(!vanilla.supports(BridgeAdapterCapability.LOGIN_GATE), "Vanilla RCON is not a pre-login gate");
        require(vanilla.supports(BridgeAdapterCapability.SIDECAR_RCON), "Vanilla sidecar needs RCON");
        BridgeAdapterProfile sponge = BridgeAdapterProfiles.require("sponge");
        for (BridgeAdapterCapability cap : List.of(BridgeAdapterCapability.CONTROL_WHITELIST,
                BridgeAdapterCapability.CONTROL_BAN, BridgeAdapterCapability.CONTROL_SAVE, BridgeAdapterCapability.CONTROL_CONSOLE)) {
            require(!sponge.supports(cap), "Sponge reflection-only/unsupported control advertised: " + cap);
        }
        for (String id : List.of("velocity", "bungeecord", "waterfall")) {
            BridgeAdapterProfile profile = BridgeAdapterProfiles.require(id);
            require(profile.supports(BridgeAdapterCapability.LOGIN_GATE), "proxy login gate absent: " + id);
            require(!profile.supports(BridgeAdapterCapability.CONTROL_SAVE), "proxy cannot save a world: " + id);
        }
        try {
            BridgeAdapterProfiles.rejectUncertifiedHybrid("paper", "Mohist build");
            throw new AssertionError("accepted uncertified hybrid");
        } catch (IllegalStateException expectedError) { /* blocked */ }
        System.out.println("CAPABILITY_POLICY_OK total=" + expected.size() + " runtime_certified=false");
    }
    private static void require(boolean condition, String failure) {
        if (!condition) throw new AssertionError(failure);
    }
}

package ru.neverlauncher.bridge.common;

public final class BridgeDefaults {
    public static final String VERSION = BridgeVersion.VERSION;
    public static final int PROTOCOL_VERSION = 3;
    public static final int LEGACY_PROTOCOL_VERSION = 2;
    public static final String FEATURE_CAPABILITY_NEGOTIATION = "protocol.capability-negotiation";
    public static final String FEATURE_PROTOCOL_FLAGS = "protocol.feature-flags";
    public static final String FEATURE_ROLLING_UPGRADE = "protocol.rolling-upgrade-v2";
    public static final String FEATURE_NODE_SIGNATURES = "security.ed25519-node-requests";
    public static final String FEATURE_NONCE_REPLAY = "security.single-use-node-nonce";
    public static final String FEATURE_ARTIFACT_INTEGRITY = "integrity.sha256";
    public static final String FEATURE_ONE_TIME_JOIN = "join.one-time";
    public static final String FEATURE_ONE_TIME_HANDOFF = "handoff.one-time";
    public static final String FEATURE_RUNTIME_TOPOLOGY = "topology.runtime-learned";
    public static final String FEATURE_RUNTIME_DISCOVERY = "runtime.node-discovery-v1";
    public static final String FEATURE_RUNTIME_IDENTITY = "security.runtime-identity-ed25519";
    public static final String VELOCITY_ID = "neverlauncher-velocity-bridge";
    public static final String BUNGEECORD_ID = "neverlauncher-bungeecord-bridge";
    public static final String WATERFALL_ID = "neverlauncher-waterfall-bridge";
    public static final String BUKKIT_ID = "neverlauncher-bukkit-bridge";
    public static final String SPIGOT_ID = "neverlauncher-spigot-bridge";
    public static final String PAPER_ID = "neverlauncher-paper-bridge";
    public static final String PURPUR_ID = "neverlauncher-purpur-bridge";
    public static final String FOLIA_ID = "neverlauncher-folia-bridge";
    private BridgeDefaults() {}
}

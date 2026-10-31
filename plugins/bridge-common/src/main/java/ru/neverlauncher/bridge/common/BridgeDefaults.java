package ru.launcher.bridge.common;

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
    public static final String FEATURE_SERVER_TELEMETRY = "telemetry.server-v1";
    public static final String FEATURE_EVENT_STREAM = "events.ordered-stream-v1";
    public static final String FEATURE_CONTROL_API = "control.secure-channel-v1";
    public static final String FEATURE_HA_CONTROL_PLANE = "control.ha-channel-v2";
    public static final String FEATURE_ROUTING_V2 = "topology.routing-v2";
    public static final String FEATURE_PLAYER_SESSION_V3 = "session.player-lifecycle-v3";
    public static final String FEATURE_SECURITY_V3_SIGNING_DOMAIN = "security.protocol-v3-signing-domain";
    public static final String FEATURE_CAPABILITY_DOWNGRADE_PROTECTION = "security.capability-downgrade-protection";
    public static final String FEATURE_COMMAND_SIGNATURES_V3 = "security.command-signatures-v3";
    public static final String FEATURE_EVENT_SIGNATURES_V3 = "security.event-signatures-v3";
    public static final String FEATURE_RUNTIME_BINDING_V3 = "security.runtime-instance-binding-v3";
    public static final String FEATURE_ONLINE_KEY_ROTATION = "security.online-key-rotation-v1";
    public static final String SECURITY_PROFILE = "serverbridge3-security-01912";
    public static final String VELOCITY_ID = "launcher-velocity-bridge";
    public static final String BUNGEECORD_ID = "launcher-bungeecord-bridge";
    public static final String WATERFALL_ID = "launcher-waterfall-bridge";
    public static final String BUKKIT_ID = "launcher-bukkit-bridge";
    public static final String SPIGOT_ID = "launcher-spigot-bridge";
    public static final String PAPER_ID = "launcher-paper-bridge";
    public static final String PURPUR_ID = "launcher-purpur-bridge";
    public static final String FOLIA_ID = "launcher-folia-bridge";
    public static final String QUILT_ID = "launcher-quilt-bridge";
    public static final String SPONGE_ID = "launcher-sponge-bridge";
    public static final String VANILLA_ID = "launcher-vanilla-bridge";
    private BridgeDefaults() {}
}

package ru.neverlauncher.bridge.common;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Process-scoped runtime identity attested by the long-lived Ed25519 node key.
 * The runtime id is deterministic for a node identity + JVM process, so plugin
 * reloads in the same JVM do not look like server restarts while a JVM/process
 * replacement necessarily yields a different id.
 */
public final class BridgeRuntimeIdentity {
    public static final String SIGNATURE_SCHEME = "NeverLauncher-ServerBridge-RuntimeIdentity-v1";
    private static final String RUNTIME_ID_SCHEME = "NeverLauncher-ServerBridge-RuntimeId-v1";

    private final String serverId;
    private final String nodeKeyFingerprint;
    private final String runtimeId;
    private final long startedAtUnixMillis;
    private final long processId;
    private final String hostname;
    private final String nodeName;
    private final String minecraftVersion;
    private final String javaVersion;
    private final String javaVendor;
    private final String javaVmName;
    private final String platform;
    private final String loaderName;
    private final String loaderVersion;
    private final String serverBrand;
    private final List<String> capabilities;
    private final String identitySignature;

    private BridgeRuntimeIdentity(
        String serverId,
        String nodeKeyFingerprint,
        String runtimeId,
        long startedAtUnixMillis,
        long processId,
        String hostname,
        String nodeName,
        BridgeRuntimeDescriptor descriptor,
        String javaVersion,
        String javaVendor,
        String javaVmName,
        String identitySignature
    ) {
        this.serverId = serverId;
        this.nodeKeyFingerprint = nodeKeyFingerprint;
        this.runtimeId = runtimeId;
        this.startedAtUnixMillis = startedAtUnixMillis;
        this.processId = processId;
        this.hostname = hostname;
        this.nodeName = nodeName;
        this.minecraftVersion = descriptor.minecraftVersion();
        this.javaVersion = javaVersion;
        this.javaVendor = javaVendor;
        this.javaVmName = javaVmName;
        this.platform = descriptor.platform();
        this.loaderName = descriptor.loaderName();
        this.loaderVersion = descriptor.loaderVersion();
        this.serverBrand = descriptor.serverBrand();
        this.capabilities = descriptor.capabilities();
        this.identitySignature = identitySignature;
    }

    public static BridgeRuntimeIdentity capture(BridgeConfig config, NodeIdentity identity, BridgeRuntimeDescriptor descriptor)
        throws GeneralSecurityException {
        if (config == null || identity == null || descriptor == null) {
            throw new GeneralSecurityException("runtime identity requires config, node identity and platform descriptor");
        }
        String serverId = clean(config.serverId);
        String fingerprint = identity.fingerprint();
        long startedAt = BridgeRuntimeProbe.jvmStartMillis();
        long pid = BridgeRuntimeProbe.processId();
        String hostname = clean(detectHostname(), 255);
        String nodeName = clean(detectNodeName(hostname), 255);
        String javaVersion = clean(System.getProperty("java.version", ""), 128);
        String javaVendor = clean(System.getProperty("java.vendor", ""), 128);
        String javaVmName = clean(System.getProperty("java.vm.name", ""), 128);
        String runtimeId = deriveRuntimeId(serverId, fingerprint, startedAt, pid, hostname);
        String canonical = canonical(
            serverId, fingerprint, runtimeId, startedAt, pid, hostname, nodeName,
            descriptor.minecraftVersion(), javaVersion, javaVendor, javaVmName,
            descriptor.platform(), descriptor.loaderName(), descriptor.loaderVersion(), descriptor.serverBrand(), descriptor.capabilities()
        );
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(identity.sign(canonical));
        return new BridgeRuntimeIdentity(
            serverId, fingerprint, runtimeId, startedAt, pid, hostname, nodeName, descriptor,
            javaVersion, javaVendor, javaVmName, signature
        );
    }

    public String toJson() {
        return "{" +
            "\"runtimeId\":" + quote(runtimeId) + "," +
            "\"startedAt\":" + quote(Instant.ofEpochMilli(startedAtUnixMillis).toString()) + "," +
            "\"startedAtUnixMillis\":" + startedAtUnixMillis + "," +
            "\"uptimeSeconds\":" + BridgeRuntimeProbe.uptimeSeconds() + "," +
            "\"processId\":" + processId + "," +
            "\"hostname\":" + quote(hostname) + "," +
            "\"nodeName\":" + quote(nodeName) + "," +
            "\"minecraftVersion\":" + quote(minecraftVersion) + "," +
            "\"javaVersion\":" + quote(javaVersion) + "," +
            "\"javaVendor\":" + quote(javaVendor) + "," +
            "\"javaVmName\":" + quote(javaVmName) + "," +
            "\"platform\":" + quote(platform) + "," +
            "\"loaderName\":" + quote(loaderName) + "," +
            "\"loaderVersion\":" + quote(loaderVersion) + "," +
            "\"serverBrand\":" + quote(serverBrand) + "," +
            "\"capabilities\":" + jsonArray(capabilities) + "," +
            "\"nodeKeyFingerprint\":" + quote(nodeKeyFingerprint) + "," +
            "\"identitySignature\":" + quote(identitySignature) +
            "}";
    }

    public String runtimeId() { return runtimeId; }
    public long startedAtUnixMillis() { return startedAtUnixMillis; }
    public long processId() { return processId; }
    public String hostname() { return hostname; }
    public String nodeName() { return nodeName; }
    public String nodeKeyFingerprint() { return nodeKeyFingerprint; }
    public String identitySignature() { return identitySignature; }
    public BridgeRuntimeDescriptor descriptor() {
        return new BridgeRuntimeDescriptor(minecraftVersion, platform, loaderName, loaderVersion, serverBrand, capabilities);
    }

    public static String canonical(
        String serverId,
        String nodeKeyFingerprint,
        String runtimeId,
        long startedAtUnixMillis,
        long processId,
        String hostname,
        String nodeName,
        String minecraftVersion,
        String javaVersion,
        String javaVendor,
        String javaVmName,
        String platform,
        String loaderName,
        String loaderVersion,
        String serverBrand,
        List<String> capabilities
    ) {
        return String.join("\n",
            SIGNATURE_SCHEME,
            b64(clean(serverId)),
            clean(nodeKeyFingerprint).toLowerCase(),
            clean(runtimeId).toLowerCase(),
            Long.toString(startedAtUnixMillis),
            Long.toString(processId),
            b64(clean(hostname)),
            b64(clean(nodeName)),
            b64(clean(minecraftVersion)),
            b64(clean(javaVersion)),
            b64(clean(javaVendor)),
            b64(clean(javaVmName)),
            b64(clean(platform).toLowerCase()),
            b64(clean(loaderName)),
            b64(clean(loaderVersion)),
            b64(clean(serverBrand)),
            b64(String.join("\n", capabilities == null ? List.of() : capabilities))
        );
    }

    private static String deriveRuntimeId(String serverId, String fingerprint, long startedAt, long pid, String hostname)
        throws GeneralSecurityException {
        String source = String.join("\n", RUNTIME_ID_SCHEME, b64(serverId), fingerprint, Long.toString(startedAt), Long.toString(pid), b64(hostname));
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(source.getBytes(StandardCharsets.UTF_8)));
    }

    private static String detectHostname() {
        try {
            String hostname = clean(InetAddress.getLocalHost().getHostName());
            if (!hostname.isBlank()) return hostname;
        } catch (Exception ignored) {}
        String env = clean(System.getenv("HOSTNAME"));
        if (!env.isBlank()) return env;
        env = clean(System.getenv("COMPUTERNAME"));
        return env.isBlank() ? "unknown" : env;
    }

    private static String detectNodeName(String hostname) {
        String value = clean(System.getProperty("neverlauncher.nodeName", ""));
        if (!value.isBlank()) return value;
        value = clean(System.getenv("NEVERLAUNCHER_NODE_NAME"));
        if (!value.isBlank()) return value;
        return hostname;
    }

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String quote(String value) {
        if (value == null) value = "";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String jsonArray(List<String> values) {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) out.append(',');
            out.append(quote(values.get(i)));
        }
        return out.append(']').toString();
    }

    private static String clean(String value) {
        if (value == null) return "";
        return value.replace('\r', ' ').replace('\n', ' ').replace("\0", "").trim();
    }

    private static String clean(String value, int maxLength) {
        String normalized = clean(value);
        return normalized.length() > maxLength ? normalized.substring(0, maxLength) : normalized;
    }
}

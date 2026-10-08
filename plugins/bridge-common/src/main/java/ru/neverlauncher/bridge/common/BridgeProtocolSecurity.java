package ru.neverlauncher.bridge.common;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/** Протокол v3 security/certification канонический общий через каждый ServerBridge адаптер. */
final class BridgeProtocolSecurity {
    static final String DOMAIN = "NeverLauncher-ServerBridge-Protocol-v3";
    static final String PROFILE = "serverbridge3-security-01912";
    static final List<String> REQUIRED_FEATURES = List.of(
        BridgeDefaults.FEATURE_SECURITY_V3_SIGNING_DOMAIN,
        BridgeDefaults.FEATURE_CAPABILITY_DOWNGRADE_PROTECTION,
        BridgeDefaults.FEATURE_COMMAND_SIGNATURES_V3,
        BridgeDefaults.FEATURE_EVENT_SIGNATURES_V3,
        BridgeDefaults.FEATURE_RUNTIME_BINDING_V3,
        BridgeDefaults.FEATURE_ONLINE_KEY_ROTATION
    );

    private BridgeProtocolSecurity() {}

    static String expectedCapabilityDigest() {
        try {
            ArrayList<String> sorted = new ArrayList<>(REQUIRED_FEATURES);
            sorted.sort(String::compareTo);
            String canonical = String.join("\n", DOMAIN, "capabilities", Integer.toString(BridgeDefaults.PROTOCOL_VERSION), PROFILE, String.join("\n", sorted));
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String capabilityCanonical(String digest, String activeFingerprint, String previousFingerprint) {
        return String.join("\n", DOMAIN, "capabilities", Integer.toString(BridgeDefaults.PROTOCOL_VERSION), PROFILE,
            normalize(digest).toLowerCase(), normalize(activeFingerprint).toLowerCase(), normalize(previousFingerprint).toLowerCase());
    }

    static String nodeRequestCanonical(String serverId, String fingerprint, String method, String target, String timestamp, String nonce,
                                       String runtimeId, String capabilityDigest, String bodySha256) {
        return String.join("\n", DOMAIN, "node-request", Integer.toString(BridgeDefaults.PROTOCOL_VERSION), PROFILE,
            b64(serverId), normalize(fingerprint).toLowerCase(), normalize(method).toUpperCase(), target,
            timestamp, nonce, normalize(runtimeId).toLowerCase(), normalize(capabilityDigest).toLowerCase(), normalize(bodySha256).toLowerCase());
    }

    static String eventCanonical(String serverId, String eventId, String runtimeId, String keyFingerprint, String capabilityDigest,
                                 long sequence, String type, long occurredAt, String payloadSha256) {
        return String.join("\n", DOMAIN, "event", Integer.toString(BridgeDefaults.PROTOCOL_VERSION), PROFILE,
            b64(serverId), normalize(eventId), normalize(runtimeId).toLowerCase(), normalize(keyFingerprint).toLowerCase(),
            normalize(capabilityDigest).toLowerCase(), Long.toString(sequence), Long.toString(occurredAt), b64(type), normalize(payloadSha256).toLowerCase());
    }

    static String commandCanonical(String serverId, String commandId, long identityEpoch, long runtimeEpoch, String runtimeId,
                                   String capabilityDigest, String type, String payloadSha256, long deliverySequence,
                                   String channelId, String leaseToken, int attempt, long issuedAt, long expiresAt, String signerFingerprint) {
        return String.join("\n", DOMAIN, "command", Integer.toString(BridgeDefaults.PROTOCOL_VERSION), PROFILE,
            b64(serverId), b64(commandId), Long.toString(identityEpoch), Long.toString(runtimeEpoch), normalize(runtimeId).toLowerCase(),
            normalize(capabilityDigest).toLowerCase(), b64(type), normalize(payloadSha256).toLowerCase(), Long.toString(deliverySequence),
            b64(channelId), b64(leaseToken), Integer.toString(attempt), Long.toString(issuedAt), Long.toString(expiresAt), normalize(signerFingerprint).toLowerCase());
    }

    static boolean verify(String publicKeyB64, String canonical, String signatureB64) {
        try {
            byte[] raw = Base64.getUrlDecoder().decode(normalize(publicKeyB64));
            byte[] signature = Base64.getUrlDecoder().decode(normalize(signatureB64));
            if (raw.length != 32 || signature.length != 64) return false;
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(rawEd25519PublicKey(raw));
            verifier.update(canonical.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    static String fingerprint(String publicKeyB64) {
        try {
            byte[] raw = Base64.getUrlDecoder().decode(normalize(publicKeyB64));
            if (raw.length != 32) return "";
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
        } catch (Exception e) {
            return "";
        }
    }

    private static PublicKey rawEd25519PublicKey(byte[] raw) throws Exception {
        byte[] prefix = HexFormat.of().parseHex("302a300506032b6570032100");
        byte[] x509 = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, x509, 0, prefix.length);
        System.arraycopy(raw, 0, x509, prefix.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(x509));
    }

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(normalize(value).getBytes(StandardCharsets.UTF_8));
    }
    private static String normalize(String value) { return value == null ? "" : value.trim(); }
}

package ru.neverlauncher.bridge.common;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

/** Сеть-free атакующий harness для Протокол v3 подписание, повторное воспроизведение и ротация ключей. */
public final class ServerBridgeSecurityCertification01912Harness {
    private record SigningKey(java.security.PrivateKey privateKey, String publicKey, String fingerprint) {}

    public static void main(String[] args) throws Exception {
        String target = args.length == 0 ? "paper" : args[0].trim().toLowerCase();
        require(!target.isBlank(), "target required");
        String serverId = target + "-security-01912";
        Path root = Files.createTempDirectory("nl-sb-security-01912-" + target + "-");
        Path cfgPath = root.resolve("serverbridge.yml");
        Files.writeString(cfgPath, "backend:\n  url: http://127.0.0.1:8080\nserver:\n  id: " + serverId + "\nidentity:\n  file: node-identity.properties\n", StandardCharsets.UTF_8);
        BridgeConfig config = BridgeConfig.load(cfgPath, serverId);
        BridgeControlTrust trust = new BridgeControlTrust(config);

        SigningKey keyA = signingKey();
        SigningKey keyB = signingKey();
        SigningKey attacker = signingKey();
        String digest = BridgeProtocolSecurity.expectedCapabilityDigest();

        String firstCanonical = BridgeProtocolSecurity.capabilityCanonical(digest, keyA.fingerprint, "");
        require(trust.verifyCapabilities(BridgeProtocolSecurity.PROFILE, digest, keyA.publicKey, keyA.fingerprint, "", "", sign(keyA, firstCanonical), ""), "initial capability trust");

        String rotateCanonical = BridgeProtocolSecurity.capabilityCanonical(digest, keyB.fingerprint, keyA.fingerprint);
        require(trust.verifyCapabilities(BridgeProtocolSecurity.PROFILE, digest, keyB.publicKey, keyB.fingerprint, keyA.publicKey, keyA.fingerprint,
            sign(keyB, rotateCanonical), sign(keyA, rotateCanonical)), "overlap key rotation");

        String finalizedCanonical = BridgeProtocolSecurity.capabilityCanonical(digest, keyB.fingerprint, "");
        require(trust.verifyCapabilities(BridgeProtocolSecurity.PROFILE, digest, keyB.publicKey, keyB.fingerprint, "", "", sign(keyB, finalizedCanonical), ""), "rotation finalize");

        String attackerCanonical = BridgeProtocolSecurity.capabilityCanonical(digest, attacker.fingerprint, "");
        require(!trust.verifyCapabilities(BridgeProtocolSecurity.PROFILE, digest, attacker.publicKey, attacker.fingerprint, "", "", sign(attacker, attackerCanonical), ""), "untrusted capability key rejected");
        String revokedRotationCanonical = BridgeProtocolSecurity.capabilityCanonical(digest, attacker.fingerprint, keyA.fingerprint);
        require(!trust.verifyCapabilities(BridgeProtocolSecurity.PROFILE, digest, attacker.publicKey, attacker.fingerprint, keyA.publicKey, keyA.fingerprint,
            sign(attacker, revokedRotationCanonical), sign(keyA, revokedRotationCanonical)), "retired previous key cannot authorize rotation after finalize");
        require(!trust.verifyCapabilities(BridgeProtocolSecurity.PROFILE, "0".repeat(64), keyB.publicKey, keyB.fingerprint, "", "", sign(keyB, finalizedCanonical), ""), "capability downgrade rejected");

        Path bridgeArtifact = root.resolve("neverlauncher-" + target + "-bridge-0.19.12.jar");
        Files.writeString(bridgeArtifact, "certified-" + target, StandardCharsets.UTF_8);
        String certifiedArtifactHash = BridgeIntegrity.sha256(bridgeArtifact);
        Files.writeString(bridgeArtifact, "tamper", StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
        require(!certifiedArtifactHash.equals(BridgeIntegrity.sha256(bridgeArtifact)), "tampered bridge artifact rejected by certified hash");

        String runtime = "a".repeat(64);
        String payloadHash = "1".repeat(64);
        BridgeControlCommand unsigned = new BridgeControlCommand(serverId, "cmd-01912", runtime, 7, 3, "server.save", Map.of(), payloadHash,
            11, "0123456789abcdef0123456789abcdef", "lease-token-01912", 1, 1000, 2000, BridgeProtocolSecurity.PROFILE, digest,
            keyB.publicKey, keyB.fingerprint, "", "", "", "");
        String commandSignature = sign(keyB, unsigned.canonicalForSigner(keyB.fingerprint));
        BridgeControlCommand command = new BridgeControlCommand(unsigned.serverId(), unsigned.commandId(), unsigned.runtimeId(), unsigned.runtimeEpoch(), unsigned.identityEpoch(), unsigned.type(), unsigned.payload(), unsigned.payloadSha256(),
            unsigned.deliverySequence(), unsigned.channelId(), unsigned.leaseToken(), unsigned.attempt(), unsigned.issuedAtUnixMillis(), unsigned.expiresAtUnixMillis(), unsigned.securityProfile(), unsigned.capabilityDigest(),
            keyB.publicKey, keyB.fingerprint, commandSignature, "", "", "");
        require(trust.verify(command), "valid v3 command signature");
        BridgeControlCommand tamperedCommand = new BridgeControlCommand(command.serverId(), command.commandId(), "b".repeat(64), 8, command.identityEpoch(), command.type(), command.payload(), command.payloadSha256(),
            command.deliverySequence(), command.channelId(), command.leaseToken(), command.attempt(), command.issuedAtUnixMillis(), command.expiresAtUnixMillis(), command.securityProfile(), command.capabilityDigest(),
            command.v3SigningPublicKey(), command.v3SigningKeyFingerprint(), command.v3Signature(), "", "", "");
        require(!trust.verify(tamperedCommand), "tampered/runtime-replayed command rejected");

        BridgeControlJournal journal = new BridgeControlJournal(root.resolve("control.journal"));
        journal.begin(command);
        journal.complete(command, BridgeControlResult.ok(Map.of("saved", "true")));
        require(journal.state(command) != null && "done".equals(journal.state(command).phase()), "command replay returns durable result");
        boolean digestConflict = false;
        try { journal.state(tamperedCommand); } catch (IllegalStateException expected) { digestConflict = true; }
        require(digestConflict, "command id replay with changed runtime rejected");

        NodeIdentity node = NodeIdentity.loadOrCreate(root.resolve("node-v3.properties"));
        BridgeEventJournal eventJournal = new BridgeEventJournal(root.resolve("events.journal"), serverId, runtime, node);
        BridgeEventRecord journalEvent = eventJournal.append("server.ready", Map.of("platform", target));
        BridgeEventRecord replayEvent = eventJournal.nextBatch(1).get(0);
        BridgeEventRecord replayEventAgain = eventJournal.nextBatch(1).get(0);
        require(journalEvent.sequence() == replayEvent.sequence() && replayEvent.sequence() == replayEventAgain.sequence()
            && journalEvent.signature().equals(replayEvent.signature()) && replayEvent.signature().equals(replayEventAgain.signature()),
            "replayed event preserves original signed sequence");

        BridgeEventRecord event = BridgeEventRecord.signed(1, serverId, runtime, "server.ready", System.currentTimeMillis(), Map.of("platform", target), node);
        String eventCanonical = BridgeProtocolSecurity.eventCanonical(serverId, event.eventId(), event.runtimeId(), event.nodeKeyFingerprint(), event.capabilityDigest(), event.sequence(), event.type(), event.occurredAtUnixMillis(), event.payloadSha256());
        require(BridgeProtocolSecurity.verify(node.publicKeyBase64Url(), eventCanonical, event.signature()), "valid event signature");
        String tamperedEvent = BridgeProtocolSecurity.eventCanonical(serverId, event.eventId(), "c".repeat(64), event.nodeKeyFingerprint(), event.capabilityDigest(), event.sequence(), event.type(), event.occurredAtUnixMillis(), event.payloadSha256());
        require(!BridgeProtocolSecurity.verify(node.publicKeyBase64Url(), tamperedEvent, event.signature()), "tampered/runtime-replayed event rejected");

        String bodyHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest("{}".getBytes(StandardCharsets.UTF_8)));
        String nodeCanonical = BridgeProtocolSecurity.nodeRequestCanonical(serverId, node.fingerprint(), "POST", "/api/v1/server-bridge/servers/" + serverId + "/heartbeat", "1770000000", "nonce-01912", runtime, digest, bodyHash);
        String nodeSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(node.sign(nodeCanonical));
        require(BridgeProtocolSecurity.verify(node.publicKeyBase64Url(), nodeCanonical, nodeSignature), "valid node request signature");
        String tamperedNode = BridgeProtocolSecurity.nodeRequestCanonical(serverId, node.fingerprint(), "POST", "/api/v1/server-bridge/servers/" + serverId + "/heartbeat", "1770000000", "nonce-01912", "d".repeat(64), digest, bodyHash);
        require(!BridgeProtocolSecurity.verify(node.publicKeyBase64Url(), tamperedNode, nodeSignature), "tampered node runtime rejected");

        System.out.println("ServerBridge Security & Certification 0.19.12 adversarial harness [" + target + "]: OK");
    }

    private static SigningKey signingKey() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] encoded = pair.getPublic().getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        String pub = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        String fp = BridgeProtocolSecurity.fingerprint(pub);
        return new SigningKey(pair.getPrivate(), pub, fp);
    }
    private static String sign(SigningKey key, String canonical) throws Exception {
        Signature signer = Signature.getInstance("Ed25519"); signer.initSign(key.privateKey); signer.update(canonical.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }
    private static void require(boolean condition, String label) { if (!condition) throw new IllegalStateException("FAILED: " + label); }
}

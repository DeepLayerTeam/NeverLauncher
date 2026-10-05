package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/** Durable trust store with overlap-key rotation authenticated by the already trusted key. */
final class BridgeControlTrust {
    private final Path trustFile;
    private final String configuredPublicKey;
    private final List<URI> backends;
    private volatile Set<String> pinnedPublicKeys;

    BridgeControlTrust(BridgeConfig config) throws IOException {
        this.trustFile = config.identityFile.resolveSibling("control-backend-key.properties").toAbsolutePath().normalize();
        this.configuredPublicKey = normalize(config.controlBackendPublicKey);
        if (!configuredPublicKey.isBlank() && !validPublicKey(configuredPublicKey)) {
            throw new IOException("control.backendPublicKey must be an unpadded base64url 32-byte Ed25519 public key");
        }
        this.backends = config.backendUrls.stream().map(URI::create).toList();
        this.pinnedPublicKeys = loadPinned();
    }

    synchronized boolean verifyCapabilities(String securityProfile, String capabilityDigest,
                                            String activePublicKey, String activeFingerprint,
                                            String previousPublicKey, String previousFingerprint,
                                            String activeSignature, String previousSignature) throws IOException {
        if (!BridgeProtocolSecurity.PROFILE.equals(normalize(securityProfile))) return false;
        String expectedDigest = BridgeProtocolSecurity.expectedCapabilityDigest();
        if (!constantEquals(expectedDigest, normalize(capabilityDigest).toLowerCase())) return false;

        activePublicKey = normalize(activePublicKey);
        previousPublicKey = normalize(previousPublicKey);
        activeFingerprint = normalize(activeFingerprint).toLowerCase();
        previousFingerprint = normalize(previousFingerprint).toLowerCase();
        if (!validBinding(activePublicKey, activeFingerprint)) return false;
        if (!previousPublicKey.isBlank() && !validBinding(previousPublicKey, previousFingerprint)) return false;
        if (previousPublicKey.isBlank() != previousFingerprint.isBlank()) return false;
        if (!previousPublicKey.isBlank() && activePublicKey.equals(previousPublicKey)) return false;

        String canonical = BridgeProtocolSecurity.capabilityCanonical(capabilityDigest, activeFingerprint, previousFingerprint);
        boolean activeValid = BridgeProtocolSecurity.verify(activePublicKey, canonical, activeSignature);
        boolean previousValid = !previousPublicKey.isBlank() && BridgeProtocolSecurity.verify(previousPublicKey, canonical, previousSignature);
        if (!activeValid) return false; // every document must prove possession of the announced active key

        LinkedHashSet<String> anchors = new LinkedHashSet<>(pinnedPublicKeys);
        // The configured key is a bootstrap anchor only. Once a signed capability
        // document has established durable pins, removed overlap keys must stop
        // authorizing future rotations or commands.
        if (anchors.isEmpty() && !configuredPublicKey.isBlank()) anchors.add(configuredPublicKey);
        boolean anchored = false;
        if (anchors.isEmpty()) {
            if (!secureFirstUseAllowed()) return false;
            anchored = activeValid;
        } else {
            for (String anchor : anchors) {
                if (anchor.equals(activePublicKey) && activeValid) { anchored = true; break; }
                if (anchor.equals(previousPublicKey) && previousValid) { anchored = true; break; }
            }
        }
        if (!anchored) return false;

        LinkedHashSet<String> next = new LinkedHashSet<>();
        next.add(activePublicKey);
        if (!previousPublicKey.isBlank()) next.add(previousPublicKey);
        persistPins(next);
        return true;
    }

    boolean verify(BridgeControlCommand command) {
        if (!BridgeProtocolSecurity.PROFILE.equals(normalize(command.securityProfile()))) return false;
        if (!constantEquals(BridgeProtocolSecurity.expectedCapabilityDigest(), normalize(command.capabilityDigest()).toLowerCase())) return false;
        Set<String> trusted = pinnedPublicKeys;
        if (trusted.isEmpty()) return false; // command endpoint can never bootstrap trust
        if (verifyCommandWithKey(command, command.v3SigningPublicKey(), command.v3SigningKeyFingerprint(), command.v3Signature(), trusted)) return true;
        return verifyCommandWithKey(command, command.previousV3SigningPublicKey(), command.previousV3SigningKeyFingerprint(), command.previousV3Signature(), trusted);
    }

    private boolean verifyCommandWithKey(BridgeControlCommand command, String publicKey, String fingerprint, String signature, Set<String> trusted) {
        publicKey = normalize(publicKey);
        fingerprint = normalize(fingerprint).toLowerCase();
        if (publicKey.isBlank() || !trusted.contains(publicKey) || !validBinding(publicKey, fingerprint)) return false;
        String canonical = command.canonicalForSigner(fingerprint);
        return BridgeProtocolSecurity.verify(publicKey, canonical, signature);
    }

    private boolean secureFirstUseAllowed() {
        if (backends.isEmpty()) return false;
        for (URI backend : backends) {
            String scheme = backend.getScheme() == null ? "" : backend.getScheme().toLowerCase();
            if (scheme.equals("https")) continue;
            String host = backend.getHost() == null ? "" : backend.getHost().toLowerCase();
            if (!(scheme.equals("http") && (host.equals("127.0.0.1") || host.equals("localhost") || host.equals("::1")))) return false;
        }
        return true;
    }

    private Set<String> loadPinned() {
        try {
            if (!Files.exists(trustFile)) return Set.of();
            Properties p = new Properties();
            try (var in = Files.newInputStream(trustFile)) { p.load(in); }
            LinkedHashSet<String> result = new LinkedHashSet<>();
            String keys = normalize(p.getProperty("publicKeys"));
            if (!keys.isBlank()) {
                for (String key : keys.split(",")) if (validPublicKey(normalize(key))) result.add(normalize(key));
            }
            String legacy = normalize(p.getProperty("publicKey"));
            if (validPublicKey(legacy)) result.add(legacy);
            return Set.copyOf(result);
        } catch (Exception ignored) { return Set.of(); }
    }

    private synchronized void persistPins(Set<String> publicKeys) throws IOException {
        LinkedHashSet<String> clean = new LinkedHashSet<>();
        for (String key : publicKeys) if (validPublicKey(normalize(key))) clean.add(normalize(key));
        if (clean.isEmpty() || clean.size() > 2) throw new IOException("invalid ServerBridge control trust set");
        Path parent = trustFile.getParent(); if (parent != null) Files.createDirectories(parent);
        Path tmp = trustFile.resolveSibling(trustFile.getFileName() + ".tmp");
        ArrayList<String> fingerprints = new ArrayList<>();
        for (String key : clean) fingerprints.add(BridgeProtocolSecurity.fingerprint(key));
        String content = "algorithm=ed25519\npublicKeys=" + String.join(",", clean) + "\nfingerprints=" + String.join(",", fingerprints) + "\n";
        Files.writeString(tmp, content, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        setOwnerOnly(tmp);
        try { Files.move(tmp, trustFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
        catch (AtomicMoveNotSupportedException e) { Files.move(tmp, trustFile, StandardCopyOption.REPLACE_EXISTING); }
        setOwnerOnly(trustFile);
        pinnedPublicKeys = Set.copyOf(clean);
    }

    private static boolean validBinding(String publicKey, String fingerprint) {
        return validPublicKey(publicKey) && fingerprint.length() == 64 && constantEquals(BridgeProtocolSecurity.fingerprint(publicKey), fingerprint);
    }
    private static boolean validPublicKey(String key) {
        if (key == null || key.isBlank()) return false;
        try { return Base64.getUrlDecoder().decode(key).length == 32; } catch (IllegalArgumentException e) { return false; }
    }
    private static boolean constantEquals(String a, String b) {
        return MessageDigest.isEqual(normalize(a).getBytes(StandardCharsets.US_ASCII), normalize(b).getBytes(StandardCharsets.US_ASCII));
    }
    private static void setOwnerOnly(Path p) { try { Files.setPosixFilePermissions(p, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")); } catch (Exception ignored) {} }
    private static String normalize(String v) { return v == null ? "" : v.trim(); }
}

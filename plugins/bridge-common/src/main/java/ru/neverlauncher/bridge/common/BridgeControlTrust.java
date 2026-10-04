package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Properties;

final class BridgeControlTrust {
    private final Path trustFile;
    private final String configuredPublicKey;
    private final java.util.List<URI> backends;
    private volatile String pinnedPublicKey;

    BridgeControlTrust(BridgeConfig config) throws IOException {
        this.trustFile = config.identityFile.resolveSibling("control-backend-key.properties").toAbsolutePath().normalize();
        this.configuredPublicKey = normalize(config.controlBackendPublicKey);
        if (!this.configuredPublicKey.isBlank()) {
            try {
                byte[] configured = Base64.getUrlDecoder().decode(this.configuredPublicKey);
                if (configured.length != 32) throw new IllegalArgumentException("wrong Ed25519 public key length");
            } catch (IllegalArgumentException e) {
                throw new IOException("control.backendPublicKey must be an unpadded base64url 32-byte Ed25519 public key", e);
            }
        }
        this.backends = config.backendUrls.stream().map(URI::create).toList();
        this.pinnedPublicKey = loadPinned();
    }

    boolean verify(BridgeControlCommand command) throws Exception {
        String presented = normalize(command.signingPublicKey());
        byte[] raw = Base64.getUrlDecoder().decode(presented);
        if (raw.length != 32) return false;
        String trusted = configuredPublicKey.isBlank() ? pinnedPublicKey : configuredPublicKey;
        if (trusted.isBlank()) {
            if (!secureFirstUseAllowed()) return false;
            persistPin(presented);
            trusted = presented;
        }
        if (!MessageDigest.isEqual(trusted.getBytes(StandardCharsets.US_ASCII), presented.getBytes(StandardCharsets.US_ASCII))) return false;
        byte[] signature = Base64.getUrlDecoder().decode(command.signature());
        if (signature.length != 64) return false;
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(rawEd25519PublicKey(raw));
        verifier.update(command.canonical().getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signature);
    }

    private PublicKey rawEd25519PublicKey(byte[] raw) throws Exception {
        // SubjectPublicKeyInfo prefix for Ed25519 (OID 1.3.101.112), followed by 32 raw bytes.
        byte[] prefix = HexFormat.of().parseHex("302a300506032b6570032100");
        byte[] x509 = new byte[prefix.length + raw.length];
        System.arraycopy(prefix,0,x509,0,prefix.length); System.arraycopy(raw,0,x509,prefix.length,raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(x509));
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

    private String loadPinned() {
        try {
            if (!Files.exists(trustFile)) return "";
            Properties p = new Properties();
            try (var in = Files.newInputStream(trustFile)) { p.load(in); }
            return normalize(p.getProperty("publicKey"));
        } catch (Exception ignored) { return ""; }
    }

    private synchronized void persistPin(String publicKey) throws IOException {
        if (!pinnedPublicKey.isBlank()) return;
        Path parent = trustFile.getParent(); if (parent != null) Files.createDirectories(parent);
        Path tmp = trustFile.resolveSibling(trustFile.getFileName()+".tmp");
        String fingerprint;
        try { fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Base64.getUrlDecoder().decode(publicKey))); }
        catch (Exception e) { throw new IOException(e); }
        Files.writeString(tmp,"algorithm=ed25519\npublicKey="+publicKey+"\nfingerprint="+fingerprint+"\n",StandardCharsets.UTF_8,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,StandardOpenOption.WRITE);
        setOwnerOnly(tmp); try { Files.move(tmp,trustFile,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE); } catch (java.nio.file.AtomicMoveNotSupportedException e) { Files.move(tmp,trustFile,StandardCopyOption.REPLACE_EXISTING); } setOwnerOnly(trustFile); pinnedPublicKey=publicKey;
    }
    private static void setOwnerOnly(Path p){ try{Files.setPosixFilePermissions(p,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}catch(Exception ignored){} }
    private static String normalize(String v){return v==null?"":v.trim();}
}

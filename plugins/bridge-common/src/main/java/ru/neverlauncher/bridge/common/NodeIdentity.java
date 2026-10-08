package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Properties;
import java.util.Set;

public final class NodeIdentity {
    private static final byte[] ED25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Set<PosixFilePermission> PRIVATE_FILE_PERMISSIONS = PosixFilePermissions.fromString("rw-------");

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final byte[] rawPublicKey;
    private final String fingerprint;

    private NodeIdentity(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.rawPublicKey = rawEd25519PublicKey(publicKey.getEncoded());
        this.fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(rawPublicKey));
        byte[] proof = sign("NeverLauncher-ServerBridge-NodeIdentity-self-test-v1");
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update("NeverLauncher-ServerBridge-NodeIdentity-self-test-v1".getBytes(StandardCharsets.UTF_8));
        if (!verifier.verify(proof)) throw new GeneralSecurityException("node identity keypair self-test failed");
    }

    public static NodeIdentity loadOrCreate(Path path) throws IOException, GeneralSecurityException {
        Path absolute = path.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if (parent != null) Files.createDirectories(parent);
        if (Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(absolute) || !Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("node identity must be a regular non-symlink file: " + absolute);
            }
            return load(absolute);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair pair = generator.generateKeyPair();
        NodeIdentity identity = new NodeIdentity(pair.getPrivate(), pair.getPublic());
        identity.persist(absolute);
        return load(absolute);
    }

    private static NodeIdentity load(Path path) throws IOException, GeneralSecurityException {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("node identity must be a regular non-symlink file: " + path);
        }
        enforcePrivatePermissions(path);
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(path)) {
            properties.load(in);
        }
        if (!"1".equals(properties.getProperty("formatVersion")) || !"ed25519".equals(properties.getProperty("keyAlgorithm"))) {
            throw new GeneralSecurityException("unsupported node identity format");
        }
        byte[] privateEncoded = decodeRequired(properties, "privateKeyPkcs8");
        byte[] publicEncoded = decodeRequired(properties, "publicKeyX509");
        KeyFactory factory = KeyFactory.getInstance("Ed25519");
        NodeIdentity identity = new NodeIdentity(
            factory.generatePrivate(new PKCS8EncodedKeySpec(privateEncoded)),
            factory.generatePublic(new X509EncodedKeySpec(publicEncoded))
        );
        byte[] expectedRawPublicKey = decodeRequired(properties, "publicKey");
        if (!MessageDigest.isEqual(expectedRawPublicKey, identity.rawPublicKey)) {
            throw new GeneralSecurityException("node identity raw public key mismatch");
        }
        String expected = properties.getProperty("keyFingerprint", "").trim().toLowerCase();
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), identity.fingerprint.getBytes(StandardCharsets.US_ASCII))) {
            throw new GeneralSecurityException("node identity fingerprint mismatch");
        }
        return identity;
    }

    private void persist(Path path) throws IOException {
        Properties properties = new Properties();
        properties.setProperty("formatVersion", "1");
        properties.setProperty("keyAlgorithm", "ed25519");
        properties.setProperty("publicKey", publicKeyBase64Url());
        properties.setProperty("keyFingerprint", fingerprint);
        properties.setProperty("publicKeyX509", Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getEncoded()));
        properties.setProperty("privateKeyPkcs8", Base64.getUrlEncoder().withoutPadding().encodeToString(privateKey.getEncoded()));

        Path parent = path.getParent() == null ? Path.of(".").toAbsolutePath() : path.getParent();
        Path temp = Files.createTempFile(parent, ".neverlauncher-node-identity-", ".tmp");
        try {
            setPrivatePermissions(temp);
            try (OutputStream out = Files.newOutputStream(temp)) {
                properties.store(out, "NeverLauncher ServerBridge node identity - PRIVATE KEY, do not share");
            }
            try {
                Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, path);
            }
            setPrivatePermissions(path);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    public byte[] sign(String canonical) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(canonical.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }

    public String newNonce() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String publicKeyBase64Url() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(rawPublicKey);
    }

    public String fingerprint() { return fingerprint; }
    public String algorithm() { return "ed25519"; }

    private static byte[] decodeRequired(Properties properties, String key) throws GeneralSecurityException {
        String value = properties.getProperty(key, "").trim();
        if (value.isEmpty()) throw new GeneralSecurityException("node identity is missing " + key);
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("node identity has invalid " + key, e);
        }
    }

    private static byte[] rawEd25519PublicKey(byte[] encoded) throws GeneralSecurityException {
        if (encoded.length != ED25519_SPKI_PREFIX.length + 32) throw new GeneralSecurityException("unexpected Ed25519 public key encoding");
        byte[] prefix = Arrays.copyOf(encoded, ED25519_SPKI_PREFIX.length);
        if (!MessageDigest.isEqual(prefix, ED25519_SPKI_PREFIX)) throw new GeneralSecurityException("unexpected Ed25519 SubjectPublicKeyInfo prefix");
        return Arrays.copyOfRange(encoded, ED25519_SPKI_PREFIX.length, encoded.length);
    }

    private static void enforcePrivatePermissions(Path path) throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            for (PosixFilePermission permission : permissions) {
                if (permission != PosixFilePermission.OWNER_READ && permission != PosixFilePermission.OWNER_WRITE) {
                    throw new IOException("node identity file permissions must be 0600: " + path);
                }
            }
        } catch (UnsupportedOperationException ignored) {
            // Windows/non-POSIX filesystems are governed by their native ACLs.
        }
    }

    private static void setPrivatePermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, PRIVATE_FILE_PERMISSIONS);
        } catch (UnsupportedOperationException ignored) {
            // Windows/non-POSIX filesystems are governed by their native ACLs.
        }
    }
}

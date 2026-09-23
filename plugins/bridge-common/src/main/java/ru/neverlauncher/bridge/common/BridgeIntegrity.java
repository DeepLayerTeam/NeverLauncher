package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class BridgeIntegrity {
    private BridgeIntegrity() {}

    public static String artifactSha256(Class<?> anchor) {
        if (anchor == null) return "";
        try {
            CodeSource source = anchor.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null) return "";
            URI uri = source.getLocation().toURI();
            if (!"file".equalsIgnoreCase(uri.getScheme())) return "";
            Path path = Path.of(uri).toAbsolutePath().normalize();
            if (!Files.isRegularFile(path)) return "";
            return sha256(path);
        } catch (Exception ignored) {
            return "";
        }
    }

    public static String sha256(Path path) throws IOException {
        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
        try (InputStream in = Files.newInputStream(path)) {
            byte[] buffer = new byte[128 * 1024];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                if (read > 0) digest.update(buffer, 0, read);
            }
        }
        return hex(digest.digest());
    }

    public static boolean isSha256(String value) {
        if (value == null || value.length() != 64) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    private static String hex(byte[] value) {
        char[] out = new char[value.length * 2];
        char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < value.length; i++) {
            int b = value[i] & 0xff;
            out[i * 2] = alphabet[b >>> 4];
            out[i * 2 + 1] = alphabet[b & 0x0f];
        }
        return new String(out);
    }
}

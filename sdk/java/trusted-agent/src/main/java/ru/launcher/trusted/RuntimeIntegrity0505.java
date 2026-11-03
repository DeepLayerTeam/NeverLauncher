package ru.launcher.trusted;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.net.URL;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/** Live integrity enforcement for the verified Minecraft process, not a diagnostic-only report.
 * A trusted launch supplies exact digest pins from the verified release/Guard policy.
 * In-process checks cannot protect against fully trusted malicious native/JVM code.
 */
final class RuntimeIntegrity0505 implements ClassFileTransformer {
    private static final int LIMIT = 8192;
    private final Path root;
    private final Map<Path, String> digests;
    private final Map<Path, String> kinds;
    private final boolean strictCode;
    private final boolean linuxProcessRequired;
    private final Set<Path> verifiedOrigins = new HashSet<Path>();
    private volatile long lastVerifiedNanos = System.nanoTime();

    private RuntimeIntegrity0505(Path root, Map<Path, String> digests, Map<Path, String> kinds,
                                 boolean strictCode, boolean linuxProcessRequired) {
        this.root = root;
        this.digests = digests;
        this.kinds = kinds;
        this.strictCode = strictCode;
        this.linuxProcessRequired = linuxProcessRequired;
    }

    static RuntimeIntegrity0505 from(Properties props) throws Exception {
        if (!"true".equals(props.getProperty("integrity.required")))
            throw new SecurityException("Guard Runtime Integrity configuration missing");
        String encodedRoot = props.getProperty("integrity.root");
        if (encodedRoot == null) throw new SecurityException("Guard Runtime Integrity root missing");
        Path root = new File(new String(Base64.getDecoder().decode(encodedRoot), "UTF-8")).getCanonicalFile().toPath();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))
            throw new SecurityException("Guard Runtime Integrity root unavailable");
        int count;
        try { count = Integer.parseInt(props.getProperty("integrity.count", "-1")); }
        catch (NumberFormatException ex) { throw new SecurityException("Guard Runtime Integrity count invalid", ex); }
        if (count < 1 || count > LIMIT) throw new SecurityException("Guard Runtime Integrity empty/oversized inventory");
        Map<Path,String> digests = new HashMap<Path,String>();
        Map<Path,String> kinds = new HashMap<Path,String>();
        for (int i = 0; i < count; i++) {
            String raw = props.getProperty("integrity."+i+".path");
            String hash = props.getProperty("integrity."+i+".sha256");
            String kind = props.getProperty("integrity."+i+".kind");
            if (raw == null || hash == null || !hash.matches("[0-9a-f]{64}") ||
                    !("code".equals(kind) || "native".equals(kind)))
                throw new SecurityException("Guard Runtime Integrity malformed inventory item " + i);
            Path path = new File(new String(Base64.getDecoder().decode(raw), "UTF-8")).toPath().toAbsolutePath().normalize();
            if (!path.startsWith(root) || path.equals(root) || digests.put(path, hash) != null)
                throw new SecurityException("Guard Runtime Integrity outside/duplicate file " + i);
            kinds.put(path, kind);
        }
        RuntimeIntegrity0505 guard = new RuntimeIntegrity0505(root,digests,kinds,
            "true".equals(props.getProperty("integrity.code.strict")),
            "true".equals(props.getProperty("integrity.linux.process.required")));
        guard.scan();
        if (guard.strictCode) guard.verifyClasspath();
        return guard;
    }

    private void verifyClasspath() throws Exception {
        String cp = System.getProperty("java.class.path", "");
        if (cp.isEmpty()) throw new SecurityException("Guard JVM classpath unavailable");
        for (String item : cp.split(java.util.regex.Pattern.quote(File.pathSeparator), -1)) {
            if (item.isEmpty() || item.endsWith("*") )
                throw new SecurityException("Guard rejects wildcard/empty JVM classpath");
            Path path = new File(item).toPath().toAbsolutePath().normalize();
            if (!path.startsWith(root) || !"code".equals(kinds.get(path)))
                throw new SecurityException("Guard JVM classpath is not signed: " + path);
            check(path);
        }
    }

    void start() {
        Thread watcher = new Thread(new Runnable() {
            @Override public void run() {
                for (;;) {
                    try {
                        Thread.sleep(4000);
                        scan();
                        lastVerifiedNanos = System.nanoTime();
                    } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                    catch (Throwable e) { reject("continuous scan: " + e); }
                }
            }
        }, "launcher-runtime-integrity-0505");
        watcher.setDaemon(true);
        watcher.start();
        // A second observer detects a crashed/interrupted integrity watcher.
        // Guard must not silently continue a running game without scans.
        Thread watchdog = new Thread(new Runnable() {
            @Override public void run() {
                for (;;) {
                    try { Thread.sleep(1000); }
                    catch (InterruptedException e) { reject("integrity watchdog interrupted"); }
                    if (!watcher.isAlive()) reject("integrity watcher stopped while JVM running");
                    // Permit slow disks and large mod packs, but fail closed on
                    // a permanently stalled scan (monotonic clock; not wall time).
                    if (System.nanoTime() - lastVerifiedNanos > 90_000_000_000L)
                        reject("integrity watcher deadline exceeded");
                }
            }
        }, "launcher-integrity-watchdog-0506");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    private void check(Path path) throws Exception {
        Path absolute = path.toAbsolutePath().normalize();
        if (!absolute.startsWith(root) || absolute.equals(root)) throw new SecurityException("path escaped game root");
        Path cursor = root;
        Path relative = root.relativize(absolute);
        for (Path component : relative) {
            cursor = cursor.resolve(component);
            if (Files.isSymbolicLink(cursor)) throw new SecurityException("symbolic link: " + cursor);
        }
        if (!Files.isRegularFile(absolute,LinkOption.NOFOLLOW_LINKS))
            throw new SecurityException("executable is not regular: " + absolute);
        String expected=digests.get(absolute);
        if (expected==null || !expected.equals(digest(absolute)))
            throw new SecurityException("missing/replaced signed runtime file: " + absolute);
    }

    private void scan() throws Exception {
        for (Path path : digests.keySet()) check(path);
        checkTree(root.resolve("mods"),true);
        checkTree(root.resolve("natives"),false);
        // Linux: verify actual native modules mapped by this JVM, not only files on disk.
        // Windows uses the separate continuously armed native Module Guard; macOS
        // has no portable equivalent at this stage and does not claim coverage.
        if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux")) {
            if (linuxProcessRequired) LinuxProcessGuard0508.verify();
            scanLinuxMaps();
        } else if (linuxProcessRequired) {
            throw new SecurityException("Linux process requirements on non-Linux JVM");
        }
    }

    private void checkTree(Path dir, boolean jars) throws Exception {
        if (!Files.exists(dir,LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.isSymbolicLink(dir) || !Files.isDirectory(dir,LinkOption.NOFOLLOW_LINKS))
            throw new SecurityException("Guard executable directory replaced: " + dir);
        int[] remaining = new int[]{LIMIT};
        walk(dir,jars,remaining);
    }
    private void walk(Path dir, boolean jars, int[] remaining) throws Exception {
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir)) {
            for (Path path : files) {
                if (--remaining[0] < 0) throw new SecurityException("Guard executable tree scan limit");
                if (Files.isSymbolicLink(path)) throw new SecurityException("symlink in executable tree: "+path);
                if (Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS)) { walk(path,jars,remaining); continue; }
                String name=path.getFileName().toString().toLowerCase(Locale.ROOT);
                boolean executable = jars ? name.endsWith(".jar") :
                    (name.endsWith(".so") || name.contains(".so.") || name.endsWith(".dll") ||
                     name.endsWith(".dylib") || name.endsWith(".jnilib"));
                if (executable) {
                    Path normalized=path.toAbsolutePath().normalize();
                    if (!digests.containsKey(normalized)) throw new SecurityException("unapproved runtime file: "+path);
                }
            }
        }
    }
    private void scanLinuxMaps() throws Exception {
        Path maps = new File("/proc/self/maps").toPath();
        if (!Files.isReadable(maps)) throw new SecurityException("Guard cannot read process mappings");
        try (java.io.BufferedReader reader=Files.newBufferedReader(maps)) {
            for (String line; (line=reader.readLine())!=null;) {
                String[] parts=line.trim().split("\\s+",6);
                if (parts.length<6 || !parts[1].contains("x")) continue;
                String pathname=parts[5];
                if (!pathname.startsWith("/")) continue;
                if (pathname.endsWith(" (deleted)")) {
                    String name=pathname.substring(0,pathname.length()-10);
                    if (new File(name).toPath().normalize().startsWith(root))
                        throw new SecurityException("mapped game library deleted: "+name);
                    continue;
                }
                Path p = new File(pathname).toPath().normalize();
                // The selected Java distribution is independently revalidated
                // by Managed Java before spawning. Do not confuse JVM-owned
                // system images with Minecraft's own native executable tree.
                Path javaHome=new File(System.getProperty("java.home", "/__invalid_java_home__")).toPath().toAbsolutePath().normalize();
                if (p.startsWith(javaHome) && !p.startsWith(root.resolve("mods")) && !p.startsWith(root.resolve("natives"))) continue;
                if (p.startsWith(root) && isNative(p)) {
                    if (!"native".equals(kinds.get(p)))
                        throw new SecurityException("unapproved mapped native module: "+p);
                    check(p);
                }
            }
        }
    }
    private static boolean isNative(Path file) {
        String s=file.getFileName().toString().toLowerCase(Locale.ROOT);
        return s.endsWith(".so") || s.contains(".so.") || s.endsWith(".dll") || s.endsWith(".dylib") || s.endsWith(".jnilib");
    }
    @Override
    public byte[] transform(ClassLoader loader,String name,Class<?> redefined,ProtectionDomain pd,byte[] original) {
        if (!strictCode || pd==null || pd.getCodeSource()==null) return null;
        try {
            URL url=pd.getCodeSource().getLocation();
            if (url==null || !"file".equalsIgnoreCase(url.getProtocol())) return null;
            Path path=new File(url.toURI()).toPath().toAbsolutePath().normalize();
            if (!path.startsWith(root)) return null;
            if (!"code".equals(kinds.get(path))) reject("unapproved class origin: "+name+" from "+path);
            // Verify at definition, not just once at premain: detect a replaced mod/JAR
            // even if it is changed between periodic filesystem scans.
            synchronized (verifiedOrigins) {
                if (!verifiedOrigins.contains(path)) {check(path);verifiedOrigins.add(path);}
            }
        } catch (Throwable e) { reject("class source verification: "+e); }
        return null;
    }
    private static String digest(Path path) throws Exception {
        MessageDigest sha=MessageDigest.getInstance("SHA-256");
        try (BufferedInputStream in=new BufferedInputStream(new FileInputStream(path.toFile()))) {
            byte[] buf=new byte[65536]; int n;
            while ((n=in.read(buf))!=-1) sha.update(buf,0,n);
        }
        StringBuilder out=new StringBuilder(64);
        for (byte b:sha.digest()) {out.append(Character.forDigit((b>>4)&15,16));out.append(Character.forDigit(b&15,16));}
        return out.toString();
    }
    static void reject(String message) {
        System.err.println("[Launcher Guard 0.50.6] "+message);
        Runtime.getRuntime().halt(79);
        throw new SecurityException(message); // unreachable in production, enables static analysis
    }
}

package ru.launcher.trusted;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;

/** Trusted premain: loads only digest-pinned plugin JARs from a signed package.
 *  All plugins have the FULL privilege level of this JVM. */
public final class Agent {
    private static final CopyOnWriteArrayList<MinecraftHook> HOOKS = new CopyOnWriteArrayList<MinecraftHook>();
    private static final ThreadLocal<Boolean> IN_CALLBACK = new ThreadLocal<Boolean>();
    private static volatile String originalMain;
    private static volatile URLClassLoader pluginLoader;
    private static volatile boolean ready;
    private Agent() { }

    public static void premain(String argument, Instrumentation instrumentation) throws Exception {
        if (argument == null || argument.isEmpty()) throw new IllegalArgumentException("signed agent configuration required");
        Properties config = new Properties();
        try (FileInputStream in = new FileInputStream(argument)) { config.load(in); }
        String encodedMain = config.getProperty("main");
        if (encodedMain == null) throw new IllegalArgumentException("Minecraft original main missing");
        originalMain = new String(Base64.getDecoder().decode(encodedMain), java.nio.charset.StandardCharsets.UTF_8);
        if (!originalMain.matches("[A-Za-z_$][\\w$]*(\\.[A-Za-z_$][\\w$]*)+")) throw new IllegalArgumentException("invalid Minecraft main");
        int count = Integer.parseInt(config.getProperty("count", "-1"));
        if (count < 0 || count > 32) throw new IllegalArgumentException("invalid plugin count");
        List<URL> urls = new ArrayList<URL>();
        for (int i = 0; i < count; i++) {
            String path = new String(Base64.getDecoder().decode(config.getProperty("plugin."+i)), java.nio.charset.StandardCharsets.UTF_8);
            String sha = config.getProperty("plugin."+i+".sha256");
            if (sha == null || !sha.matches("[0-9a-f]{64}") || !sha.equals(digest(path)))
                throw new SecurityException("trusted JVM plugin digest mismatch: " + i);
            urls.add(new java.io.File(path).toURI().toURL());
        }
        pluginLoader = new URLClassLoader(urls.toArray(new URL[0]), Agent.class.getClassLoader());
        for (MinecraftHook hook : ServiceLoader.load(MinecraftHook.class, pluginLoader)) {
            HOOKS.add(hook);
        }
        instrumentation.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String name, Class<?> redef, ProtectionDomain domain, byte[] original) {
                if (name == null || !isMinecraftClass(name) || Boolean.TRUE.equals(IN_CALLBACK.get())) return null;
                IN_CALLBACK.set(Boolean.TRUE);
                try {
                    String binary = name.replace('/', '.');
                    byte[] current = original;
                    boolean modified = false;
                    for (MinecraftHook hook : HOOKS) {
                        byte[] result = hook.transformMinecraftClass(binary,loader,current);
                        if (result != null) {
                            if (result.length == 0 || result.length > 64*1024*1024) throw new IllegalStateException("invalid class transform result");
                            current = result;
                            modified = true;
                        }
                    }
                    return modified ? current : null;
                } catch (Exception ex) {
                    System.err.println("[Launcher trusted JVM] transform rejected for " + name + ": " + ex);
                    // JVM may ignore transformer exceptions: do not pretend it is a sandbox.
                    return null;
                } finally { IN_CALLBACK.remove(); }
            }
        }, false);
        for (MinecraftHook hook : HOOKS) hook.onAgentReady(instrumentation);
        ready = true;
    }
    private static boolean isMinecraftClass(String n) {
        return n.startsWith("net/minecraft/") || n.startsWith("com/mojang/") ||
               n.startsWith("net/minecraftforge/") || n.startsWith("net/fabricmc/") ||
               n.startsWith("org/quiltmc/");
    }
    private static String digest(String file) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buf = new byte[65536]; int n;
            while ((n = in.read(buf)) >= 0) { if (n > 0) sha.update(buf,0,n); }
        }
        StringBuilder out = new StringBuilder(64);
        for (byte b : sha.digest()) out.append(String.format("%02x",b & 0xff));
        return out.toString();
    }
    static String mainClass() { ensureReady(); return originalMain; }
    static void beforeMain(String[] args) throws Exception {
        ensureReady();
        for (MinecraftHook hook : HOOKS) hook.beforeMinecraftMain(originalMain,args,Thread.currentThread().getContextClassLoader());
    }
    static void afterMain(Throwable failure) throws Exception {
        for (MinecraftHook hook : HOOKS) hook.afterMinecraftMain(originalMain,failure);
    }
    private static void ensureReady() { if (!ready) throw new IllegalStateException("trusted JVM premain did not complete"); }
}

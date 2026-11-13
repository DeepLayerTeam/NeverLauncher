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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;

/** Доверенный premain: загружает только JAR плагинов с закреплённым дайджестом из подписанного пакета.
 *  Все плагины имеют ПОЛНЫЕ привилегии этой JVM. */
public final class Agent {
    private static final CopyOnWriteArrayList<MinecraftHook> HOOKS = new CopyOnWriteArrayList<MinecraftHook>();
    private static final ThreadLocal<Boolean> IN_CALLBACK = new ThreadLocal<Boolean>();
    private static volatile String originalMain;
    private static volatile URLClassLoader pluginLoader;
    private static volatile boolean ready;
    private static volatile boolean guardPolicyActive;
    private static final Map<String, Set<String>> ALLOWED_TRANSFORMS = new HashMap<String, Set<String>>();
    private static final Map<String, String> PLUGIN_DIGESTS = new HashMap<String, String>();
    private Agent() { }

    public static void premain(String argument, Instrumentation instrumentation) throws Exception {
        if (argument == null || argument.isEmpty()) throw new IllegalArgumentException("Требуется конфигурация подписанного агента");
        Properties config = new Properties();
        try (FileInputStream in = new FileInputStream(argument)) { config.load(in); }
        String encodedMain = config.getProperty("main");
        if (encodedMain == null) throw new IllegalArgumentException("Отсутствует исходный главный класс Minecraft");
        originalMain = new String(Base64.getDecoder().decode(encodedMain), java.nio.charset.StandardCharsets.UTF_8);
        if (!originalMain.matches("[A-Za-z_$][\\w$]*(\\.[A-Za-z_$][\\w$]*)+")) throw new IllegalArgumentException("Некорректный главный класс Minecraft");
        int count = Integer.parseInt(config.getProperty("count", "-1"));
        if (count < 0 || count > 32) throw new IllegalArgumentException("Некорректное число плагинов");
        guardPolicyActive = "true".equals(config.getProperty("guard.policy.active"));
        if (guardPolicyActive) {
            int transforms = Integer.parseInt(config.getProperty("transform.count", "-1"));
            if (transforms < 0 || transforms > 4096) throw new SecurityException("Guard: некорректное число преобразований");
            for (int i = 0; i < transforms; i++) {
                String sha = config.getProperty("transform." + i + ".owner");
                String clazz = new String(Base64.getDecoder().decode(config.getProperty("transform." + i + ".class")), java.nio.charset.StandardCharsets.UTF_8);
                if (sha == null || !sha.matches("[0-9a-f]{64}") || !clazz.matches("[A-Za-z_$][\\w$]*(\\.[A-Za-z_$][\\w$]*)+"))
                    throw new SecurityException("Guard: некорректная привязка преобразования");
                Set<String> classes = ALLOWED_TRANSFORMS.get(sha);
                if (classes == null) { classes = new HashSet<String>(); ALLOWED_TRANSFORMS.put(sha, classes); }
                if (!classes.add(clazz)) throw new SecurityException("Guard: повторяющаяся привязка преобразования");
            }
        }
        if (guardPolicyActive) {
            // Устанавливайте наблюдатель до инициализации собственного загрузчика
            // Minecraft. Разрешённые классы загрузчика должны происходить из закреплённых
            // JAR-файл Runtime.
            instrumentation.addTransformer(LoaderGuard0504.from(config), false);
            if ("true".equals(config.getProperty("integrity.required"))) {
                RuntimeIntegrity0505 integrity = RuntimeIntegrity0505.from(config);
                instrumentation.addTransformer(integrity, false);
                integrity.start();
            }
        }
        List<URL> urls = new ArrayList<URL>();
        for (int i = 0; i < count; i++) {
            String path = new String(Base64.getDecoder().decode(config.getProperty("plugin."+i)), java.nio.charset.StandardCharsets.UTF_8);
            String sha = config.getProperty("plugin."+i+".sha256");
            if (sha == null || !sha.matches("[0-9a-f]{64}") || !sha.equals(digest(path)))
                throw new SecurityException("Не совпадает контрольная сумма плагина доверенной JVM: " + i);
            URL url = new java.io.File(path).toURI().toURL();
            urls.add(url);
            PLUGIN_DIGESTS.put(url.toExternalForm(), sha);
        }
        pluginLoader = new URLClassLoader(urls.toArray(new URL[0]), Agent.class.getClassLoader());
        for (MinecraftHook hook : ServiceLoader.load(MinecraftHook.class, pluginLoader)) {
            if (guardPolicyActive) pluginDigest(hook); // отклонять хуки вне закреплённых JAR до вызова обработчиков
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
                            if (guardPolicyActive) {
                                String owner = pluginDigest(hook);
                                Set<String> allowed = ALLOWED_TRANSFORMS.get(owner);
                                if (allowed == null || !allowed.contains(binary)) {
                                    System.err.println("[Launcher Guard] unauthorized_class_transformation: неразрешённое преобразование класса: " + binary);
                                    Runtime.getRuntime().halt(79); // JVM может скрывать исключения трансформатора
                                }
                            }
                            if (result.length == 0 || result.length > 64*1024*1024) throw new IllegalStateException("Некорректный результат преобразования класса");
                            current = result;
                            modified = true;
                        }
                    }
                    return modified ? current : null;
                } catch (Throwable ex) {
                    System.err.println("[Launcher trusted JVM] преобразование отклонено для " + name + ": " + ex);
                    if (guardPolicyActive) Runtime.getRuntime().halt(79);
                    return null; // устаревшее поведение обратных вызовов без Guard
                } finally { IN_CALLBACK.remove(); }
            }
        }, false);
        for (MinecraftHook hook : HOOKS) hook.onAgentReady(instrumentation);
        ready = true;
    }
    private static String pluginDigest(MinecraftHook hook) {
        try {
            URL jar = hook.getClass().getProtectionDomain().getCodeSource().getLocation();
            String digest = PLUGIN_DIGESTS.get(jar.toExternalForm());
            if (digest == null) throw new SecurityException("Guard: источником перехвата не является закреплённый JAR плагина");
            return digest;
        } catch (NullPointerException e) { throw new SecurityException("Guard: у перехвата отсутствует доверенный источник", e); }
    }
    private static boolean isMinecraftClass(String n) {
        return n.startsWith("net/minecraft/") || n.startsWith("com/mojang/") ||
               n.startsWith("net/minecraftforge/") || n.startsWith("net/neoforged/") ||
               n.startsWith("net/fabricmc/") || n.startsWith("org/quiltmc/") ||
               n.startsWith("cpw/mods/modlauncher/") || n.startsWith("org/spongepowered/asm/mixin/");
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
    private static void ensureReady() { if (!ready) throw new IllegalStateException("Инициализация premain доверенной JVM не завершилась"); }
}

package ru.neverlauncher.bridge.common;

import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.util.Locale;

/** Reflection-только probes тот сохранять мост-common независимый из Minecraft/loader APIs. */
public final class BridgeRuntimeProbe {
    private BridgeRuntimeProbe() {}

    public static String minecraftVersion() {
        for (String currentVersionMethod : new String[]{"getCurrentVersion", "getGameVersion"}) {
            Object version = invokeStatic("net.minecraft.SharedConstants", currentVersionMethod);
            if (version == null) continue;
            for (String valueMethod : new String[]{"getName", "name", "getId", "id"}) {
                String value = invokeString(version, valueMethod);
                if (!value.isBlank()) return value;
            }
            String text = clean(version.toString());
            if (!text.isBlank()) return text;
        }
        String property = clean(System.getProperty("minecraft.version", ""));
        return property;
    }

    public static String packageVersion(String className) {
        try {
            Class<?> type = Class.forName(className, false, BridgeRuntimeProbe.class.getClassLoader());
            Package pkg = type.getPackage();
            if (pkg == null) return "";
            String version = clean(pkg.getImplementationVersion());
            if (!version.isBlank()) return version;
            return clean(pkg.getSpecificationVersion());
        } catch (ClassNotFoundException | LinkageError ignored) {
            return "";
        }
    }

    public static String nestedStaticString(String className, String factoryMethod, String valueMethod) {
        Object value = invokeStatic(className, factoryMethod);
        return value == null ? "" : invokeString(value, valueMethod);
    }

    public static long processId() {
        try {
            return ProcessHandle.current().pid();
        } catch (UnsupportedOperationException | SecurityException ignored) {
            return -1L;
        }
    }

    public static long jvmStartMillis() {
        try {
            return ManagementFactory.getRuntimeMXBean().getStartTime();
        } catch (RuntimeException ignored) {
            return System.currentTimeMillis();
        }
    }

    public static long uptimeSeconds() {
        try {
            return Math.max(0L, ManagementFactory.getRuntimeMXBean().getUptime() / 1000L);
        } catch (RuntimeException ignored) {
            return Math.max(0L, (System.currentTimeMillis() - jvmStartMillis()) / 1000L);
        }
    }

    private static Object invokeStatic(String className, String methodName) {
        try {
            Class<?> type = Class.forName(className, false, Thread.currentThread().getContextClassLoader());
            Method method = type.getMethod(methodName);
            return method.invoke(null);
        } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {
            return null;
        }
    }

    private static String invokeString(Object target, String methodName) {
        try {
            Method method = target.getClass().getMethod(methodName);
            Object value = method.invoke(target);
            return value == null ? "" : clean(String.valueOf(value));
        } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {
            return "";
        }
    }

    private static String clean(String value) {
        if (value == null) return "";
        return value.replace('\r', ' ').replace('\n', ' ').trim();
    }
}

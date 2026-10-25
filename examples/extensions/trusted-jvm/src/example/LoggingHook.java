package example;

import ru.neverlauncher.trusted.MinecraftHook;
import java.lang.instrument.Instrumentation;

public final class LoggingHook implements MinecraftHook {
    private static void write(String value) {
        String marker=System.getProperty("neverlauncher.trusted.test.log");
        if (marker != null) {
            try {
                java.nio.file.Files.write(java.nio.file.Paths.get(marker), (value+"\n").getBytes("UTF-8"),
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
            } catch (Exception e) { throw new IllegalStateException(e); }
        }
    }
    @Override public void onAgentReady(Instrumentation inst) { write("agent-ready:"+inst.isRetransformClassesSupported()); }
    @Override public void beforeMinecraftMain(String main, String[] args, ClassLoader loader) { write("before:"+main+":"+args.length); }
    @Override public byte[] transformMinecraftClass(String name, ClassLoader loader, byte[] original) {
        write("transform:"+name);
        return null;
    }
    @Override public void afterMinecraftMain(String main, Throwable error) { write("after:"+(error==null?"ok":"failed")); }
}

package ported.compat;

import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import ru.launcher.trusted.MinecraftHook;

/** A real bytecode transformation and lifecycle callback executed by premain. */
public final class LegacyGameHook implements MinecraftHook {
    @Override public void onAgentReady(Instrumentation instrumentation) {
        if (!instrumentation.isRetransformClassesSupported()) {
            // Startup-time instrumentation is sufficient: no retransform requested.
        }
        System.setProperty("never.ported.agent.ready", "true");
    }
    @Override public void beforeMinecraftMain(String main,String[] args,ClassLoader loader) {
        if(!Boolean.parseBoolean(System.getProperty("never.ported.agent.ready","false")))
            throw new SecurityException("trusted agent has not initialized");
    }
    @Override public byte[] transformMinecraftClass(String name,ClassLoader loader,byte[] original) {
        if(!name.equals("net.minecraft.client.main.Main"))return null;
        // This port deliberately alters a constant-pool string with the same length.
        // No transformation is performed on any other Minecraft class.
        byte[] before="ORIGINAL".getBytes(StandardCharsets.UTF_8);
        byte[] after="MIGRATED".getBytes(StandardCharsets.UTF_8);
        byte[] result=original.clone();int found=0;
        for(int i=0;i<=result.length-before.length;i++) {
            boolean equal=true;for(int j=0;j<before.length;j++)if(result[i+j]!=before[j]){equal=false;break;}
            if(equal){System.arraycopy(after,0,result,i,after.length);found++;i+=before.length-1;}
        }
        if(found!=1)throw new SecurityException("expected JVM hook target was not found exactly once");
        return result;
    }
    @Override public void afterMinecraftMain(String main,Throwable failed) {
        System.setProperty("never.ported.agent.completed",failed==null?"ok":"failed");
    }
}

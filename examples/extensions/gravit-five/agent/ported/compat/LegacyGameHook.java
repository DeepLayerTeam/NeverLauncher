package ported.compat;

import java.lang.instrument.Instrumentation;
import java.nio.charset.StandardCharsets;
import ru.launcher.trusted.MinecraftHook;

/** Настоящее преобразование байткода и обработчик жизненного цикла, выполненные premain. */
public final class LegacyGameHook implements MinecraftHook {
    @Override public void onAgentReady(Instrumentation instrumentation) {
        if (!instrumentation.isRetransformClassesSupported()) {
            // Инструментирования при запуске достаточно: повторная трансформация не запрашивается.
        }
        System.setProperty("never.ported.agent.ready", "true");
    }
    @Override public void beforeMinecraftMain(String main,String[] args,ClassLoader loader) {
        if(!Boolean.parseBoolean(System.getProperty("never.ported.agent.ready","false")))
            throw new SecurityException("Доверенный агент не инициализирован");
    }
    @Override public byte[] transformMinecraftClass(String name,ClassLoader loader,byte[] original) {
        if(!name.equals("net.minecraft.client.main.Main"))return null;
        // Этот порт намеренно изменяет строку пула констант на значение той же
        // длины. Другие классы Minecraft не трансформируются.
        byte[] before="ORIGINAL".getBytes(StandardCharsets.UTF_8);
        byte[] after="MIGRATED".getBytes(StandardCharsets.UTF_8);
        byte[] result=original.clone();int found=0;
        for(int i=0;i<=result.length-before.length;i++) {
            boolean equal=true;for(int j=0;j<before.length;j++)if(result[i+j]!=before[j]){equal=false;break;}
            if(equal){System.arraycopy(after,0,result,i,after.length);found++;i+=before.length-1;}
        }
        if(found!=1)throw new SecurityException("Целевой перехват JVM не найден ровно один раз");
        return result;
    }
    @Override public void afterMinecraftMain(String main,Throwable failed) {
        System.setProperty("never.ported.agent.completed",failed==null?"ok":"failed");
    }
}

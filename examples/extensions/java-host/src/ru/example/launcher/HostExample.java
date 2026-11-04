package ru.example.launcher;

import java.util.Map;
import ru.launcher.sdk.core.Extension;
import ru.launcher.sdk.core.ExtensionContext;

/** Исполняемая интеграционная фикстура JVM-хоста; выполняет типизированные команды по настоящим RPC-запросам. */
public final class HostExample implements Extension {
    private volatile boolean started;
    @Override public void start(ExtensionContext context) {
        context.runtime().commands().register("status",null,input->input,request->Map.of("running",started,"extensionId",context.manifest().id()));
        context.runtime().commands().register("echo",null,input->input,request->Map.of("echo",request));
        context.runtime().commands().register("hang",null,input->input,request->{
            // Проверяет супервизор процессов: намеренно игнорирует прерывание потока.
            long until=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(60);
            while(System.nanoTime()<until){try{Thread.sleep(100);}catch(InterruptedException ignored){}}
            return Map.of("finished",true);
        });
        started=true;
    }
    @Override public void stop(ExtensionContext context) {started=false;}
}

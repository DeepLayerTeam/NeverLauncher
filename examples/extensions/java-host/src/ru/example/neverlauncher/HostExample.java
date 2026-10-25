package ru.example.neverlauncher;

import java.util.Map;
import ru.neverlauncher.sdk.core.Extension;
import ru.neverlauncher.sdk.core.ExtensionContext;

/** Runnable JVM-host integration fixture; executes typed commands on live RPC requests. */
public final class HostExample implements Extension {
    private volatile boolean started;
    @Override public void start(ExtensionContext context) {
        context.runtime().commands().register("status",null,input->input,request->Map.of("running",started,"extensionId",context.manifest().id()));
        context.runtime().commands().register("echo",null,input->input,request->Map.of("echo",request));
        context.runtime().commands().register("hang",null,input->input,request->{
            // Exercises the process supervisor: deliberately ignores thread interruption.
            long until=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(60);
            while(System.nanoTime()<until){try{Thread.sleep(100);}catch(InterruptedException ignored){}}
            return Map.of("finished",true);
        });
        started=true;
    }
    @Override public void stop(ExtensionContext context) {started=false;}
}

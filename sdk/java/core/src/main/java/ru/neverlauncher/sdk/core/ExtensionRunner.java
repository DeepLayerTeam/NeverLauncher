package ru.neverlauncher.sdk.core;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Run a Java 17+ extension via the existing NeverLauncher backend executable target. */
public final class ExtensionRunner {
    private ExtensionRunner() {}
    public static void main(String[] args) throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("usage: ExtensionRunner <manifest.json> <extension-class>");
        run(args[0],args[1],System.getenv());
    }
    public static void run(String manifestPath,String className,Map<String,String> env) throws Exception {
        ExtensionManifest manifest=ExtensionManifest.load(Path.of(manifestPath));
        if(manifest.targets().stream().noneMatch(t->t.kind().equals("backend")))throw new IllegalArgumentException("Java backend requires backend target");
        if(!manifest.hooks().isEmpty())throw new IllegalArgumentException("manifest hooks require event callbacks (Java SDK Runtime APIs 0.30.3)");
        Class<?> type=Class.forName(className);
        if(!Extension.class.isAssignableFrom(type))throw new IllegalArgumentException("class does not implement Extension: "+className);
        Extension extension=(Extension)type.getDeclaredConstructor().newInstance();
        try(HostSession host=HostSession.fromEnvironment(env,manifest);ExtensionLifecycle lifecycle=new ExtensionLifecycle(extension,manifest)) {
            CountDownLatch stopping=new CountDownLatch(1);
            AtomicBoolean shuttingDown=new AtomicBoolean();
            // A JVM shutdown hook must perform cleanup itself: merely waking the main thread
            // would allow JVM termination before Extension.stop() completes.
            Thread shutdown=new Thread(()->{
                try{shuttingDown.set(true);lifecycle.stop(Duration.ofSeconds(3));}catch(Exception ignored){/* supervisor can kill */}
                finally{host.close();stopping.countDown();}
            },"neverext-shutdown-hook");
            Runtime.getRuntime().addShutdownHook(shutdown);
            try{
                host.connect();
                lifecycle.start(Duration.ofSeconds(8));
                while(host.healthy()&&!stopping.await(1,TimeUnit.SECONDS)){}
                if(!host.healthy()&&!shuttingDown.get())throw new IllegalStateException("extension host heartbeat failed");
                lifecycle.stop(Duration.ofSeconds(3));
            } finally {
                try{Runtime.getRuntime().removeShutdownHook(shutdown);}catch(IllegalStateException ignored){/* JVM shutting down */}
            }
        }
    }
}

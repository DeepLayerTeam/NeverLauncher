package ru.neverlauncher.sdk.core;

import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Production entrypoint for NeverExtensions backend or short-lived CLI Java targets. */
public final class ExtensionRunner {
    private ExtensionRunner() {}
    public static void main(String[] args) throws Exception {
        if(args.length==2){run(args[0],args[1],System.getenv());return;}
        if(args.length>=4&&args[0].equals("--cli")){runCli(args[1],args[2],System.getenv(),Arrays.copyOfRange(args,3,args.length));return;}
        throw new IllegalArgumentException("usage: ExtensionRunner <manifest.json> <extension-class> OR --cli <manifest.json> <extension-class> <command> [args...]");
    }
    public static void run(String manifestPath,String className,Map<String,String> env) throws Exception {
        launch(manifestPath,className,env,null);
    }
    public static Object runCli(String manifestPath,String className,Map<String,String> env,String[] argv)throws Exception {
        if(argv.length==0||argv.length>128)throw new IllegalArgumentException("CLI command required");
        return launch(manifestPath,className,env,argv);
    }
    private static Object launch(String manifestPath,String className,Map<String,String> env,String[] argv)throws Exception {
        ExtensionManifest manifest=ExtensionManifest.load(Path.of(manifestPath));
        String kind=argv==null?"backend":"cli";
        if(manifest.targets().stream().noneMatch(t->t.kind().equals(kind)))throw new IllegalArgumentException("Java extension requires "+kind+" target");
        if(!kind.equals(env.getOrDefault("NEVERLAUNCHER_EXTENSION_TARGET","backend")))throw new IllegalArgumentException("host target mismatch");
        Class<?> type=Class.forName(className);
        if(!Extension.class.isAssignableFrom(type))throw new IllegalArgumentException("class does not implement Extension: "+className);
        Extension extension=(Extension)type.getDeclaredConstructor().newInstance();
        Set<String> declared=declaredCommands(manifestPath);
        if(argv!=null&&!declared.contains(argv[0]))throw new SecurityException("undeclared CLI command");
        try(HostSession host=HostSession.fromEnvironment(env,manifest);
            RuntimeServices services=new RuntimeServices(host,declared);
            RuntimeCallbackServer callback=new RuntimeCallbackServer(required(env,"NEVERLAUNCHER_EXTENSION_CALLBACK_TOKEN"),services);
            ExtensionLifecycle lifecycle=new ExtensionLifecycle(extension,manifest,services)) {
            CountDownLatch stopping=new CountDownLatch(1);
            AtomicBoolean shuttingDown=new AtomicBoolean();
            Thread shutdown=new Thread(()->{
                try{shuttingDown.set(true);lifecycle.stop(Duration.ofSeconds(3));}catch(Exception ignored){/* host supervisor can kill */}
                finally{host.close();stopping.countDown();}
            },"neverext-shutdown-hook");
            Runtime.getRuntime().addShutdownHook(shutdown);
            try {
                host.connect(callback.url());
                lifecycle.start(Duration.ofSeconds(8));
                if(argv!=null){
                    Object response=services.commands().invoke(argv[0],Map.of("args",Arrays.asList(Arrays.copyOfRange(argv,1,argv.length))));
                    System.out.println(Json.encode(response));
                    lifecycle.stop(Duration.ofSeconds(3));
                    return response;
                }
                while(host.healthy()&&!stopping.await(1,TimeUnit.SECONDS)){}
                if(!host.healthy()&&!shuttingDown.get())throw new IllegalStateException("extension host heartbeat failed");
                lifecycle.stop(Duration.ofSeconds(3));
                return null;
            } finally {
                try{Runtime.getRuntime().removeShutdownHook(shutdown);}catch(IllegalStateException ignored){/* JVM shutting down */}
            }
        }
    }
    private static String required(Map<String,String> env,String key){String v=env.get(key);if(v==null||v.isBlank())throw new IllegalArgumentException("missing "+key);return v;}
    private static Set<String> declaredCommands(String path)throws IOException {
        Map<String,Object> raw=Json.object(Json.parse(Files.readString(Path.of(path))));
        Object cli=raw.get("cli");if(cli==null)return Set.of();
        Map<String,Object> obj=Json.object(cli);Object commands=obj.get("commands");
        if(!(commands instanceof List<?> list))return Set.of();
        Set<String> names=new HashSet<>();for(Object item:list){String name=Json.string(Json.object(item),"name",true);if(!names.add(name))throw new IllegalArgumentException("duplicate CLI command");}
        return names;
    }
}

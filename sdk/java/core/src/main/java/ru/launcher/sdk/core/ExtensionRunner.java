package ru.launcher.sdk.core;

import java.io.IOException;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Точка входа в production для Backend Extensions или краткоживущих Java CLI-целей. */
public final class ExtensionRunner {
    private ExtensionRunner() {}
    public static void main(String[] args) throws Exception {
        if(args.length==2){run(args[0],args[1],System.getenv());return;}
        if(args.length>=4&&args[0].equals("--cli")){runCli(args[1],args[2],System.getenv(),Arrays.copyOfRange(args,3,args.length));return;}
        throw new IllegalArgumentException("usage: ExtensionRunner <manifest.json> <extension-class> OR --cli <manifest.json> <extension-class> <command> [args...]");
    }
    public static void run(String manifestPath,String className,Map<String,String> env) throws Exception {
        launch(manifestPath,className,env,null,false,null);
    }
    public static void runManaged(String manifestPath,String className,Map<String,String> env)throws Exception {
        launch(manifestPath,className,env,null,true,null);
    }
    public static Object runManagedCli(String manifestPath,String className,Map<String,String> env,String[] argv)throws Exception {
        return launch(manifestPath,className,env,argv,true,null);
    }
    public static Object runCli(String manifestPath,String className,Map<String,String> env,String[] argv)throws Exception {
        if(argv.length==0||argv.length>128)throw new IllegalArgumentException("CLI command required");
        return launch(manifestPath,className,env,argv,false,null);
    }
    public static void runManagedFromHost(String className,Map<String,String> env)throws Exception {
        launch(null,className,env,null,true,HostSession.fetchManifestFromEnvironment(env));
    }
    public static Object runManagedCliFromHost(String className,Map<String,String> env,String[] argv)throws Exception {
        return launch(null,className,env,argv,true,HostSession.fetchManifestFromEnvironment(env));
    }
    private static Object launch(String manifestPath,String className,Map<String,String> env,String[] argv,boolean managed,String suppliedManifest)throws Exception {
        String source=suppliedManifest==null?Files.readString(Path.of(manifestPath)):suppliedManifest;
        ExtensionManifest manifest=ExtensionManifest.parse(source);
        String kind=argv==null?"backend":"cli";
        if(manifest.targets().stream().noneMatch(t->t.kind().equals(kind)))throw new IllegalArgumentException("Java extension requires "+kind+" target");
        if(!kind.equals(env.getOrDefault("LAUNCHER_EXTENSION_TARGET","backend")))throw new IllegalArgumentException("host target mismatch");
        // Загрузка без инициализации не допускает выполнения статических
        // инициализаторов расширения, пока аутентифицированный хост не согласует API.
        try(BundledLibraries libraries=BundledLibraries.open(manifest.api())) {
        Class<?> type=Class.forName(className,false,libraries.classLoader());
        if(!Extension.class.isAssignableFrom(type))throw new IllegalArgumentException("class does not implement Extension: "+className);
        Set<String> declared=declaredCommands(source);
        if(argv!=null&&!declared.contains(argv[0]))throw new SecurityException("undeclared CLI command");
        java.util.concurrent.atomic.AtomicReference<ExtensionLifecycle> lifecycleRef=new java.util.concurrent.atomic.AtomicReference<>();
        try(HostSession host=HostSession.fromEnvironment(env,manifest);
            RuntimeServices services=new RuntimeServices(host,declared,declaredUIActions(source));
            RuntimeCallbackServer callback=new RuntimeCallbackServer(required(env,"LAUNCHER_EXTENSION_CALLBACK_TOKEN"),services,
                ()->{ExtensionLifecycle current=lifecycleRef.get();return current==null?"STARTING":current.state().name();})) {
            // Если хост отклоняет версию, идентичность или объявленные возможности, не
            // вызываются ни конструктор расширения, ни статический инициализатор, ни
            // start().
            host.connect(callback.url());
            Thread currentThread=Thread.currentThread();
            ClassLoader previousLoader=currentThread.getContextClassLoader();
            currentThread.setContextClassLoader(libraries.classLoader());
            try {
            Extension extension=(Extension)type.getDeclaredConstructor().newInstance();
            try(ExtensionLifecycle lifecycle=new ExtensionLifecycle(extension,manifest,services)) {
                lifecycleRef.set(lifecycle);
                CountDownLatch stopping=new CountDownLatch(1);
                AtomicBoolean shuttingDown=new AtomicBoolean();
                Thread shutdown=new Thread(()->{
                    try{shuttingDown.set(true);lifecycle.stop(Duration.ofSeconds(3));}catch(Exception ignored){/* host supervisor can kill */}
                    finally{host.close();stopping.countDown();}
                },"neverext-shutdown-hook");
                Runtime.getRuntime().addShutdownHook(shutdown);
                try {
                    lifecycle.start(Duration.ofSeconds(8));
                    if(managed&&argv==null)host.ready();
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
            } finally {currentThread.setContextClassLoader(previousLoader);}
        }
        }
    }
    private static String required(Map<String,String> env,String key){String v=env.get(key);if(v==null||v.isBlank())throw new IllegalArgumentException("missing "+key);return v;}
    private static Map<String,Set<String>> declaredUIActions(String source){
        Map<String,Object> manifest=Json.object(Json.parse(source));
        Map<String,Set<String>> surfaces=new HashMap<>();
        for(String kind:List.of("admin","desktop")){
            Object value=manifest.get(kind);
            if(value==null)continue;
            Object actions=Json.object(value).get("actions");
            if(actions==null)continue;
            if(!(actions instanceof List<?> items))throw new IllegalArgumentException("UI actions must be an array");
            Set<String> names=new HashSet<>();
            for(Object item:items){
                String id=Json.string(Json.object(item),"id",true);
                if(!names.add(id))throw new IllegalArgumentException("duplicate signed UI action");
            }
            surfaces.put(kind,Set.copyOf(names));
        }
        return surfaces;
    }
    private static Set<String> declaredCommands(String source) {
        Map<String,Object> raw=Json.object(Json.parse(source));
        Object cli=raw.get("cli");if(cli==null)return Set.of();
        Map<String,Object> obj=Json.object(cli);Object commands=obj.get("commands");
        if(!(commands instanceof List<?> list))return Set.of();
        Set<String> names=new HashSet<>();for(Object item:list){String name=Json.string(Json.object(item),"name",true);if(!names.add(name))throw new IllegalArgumentException("duplicate CLI command");}
        return names;
    }
}

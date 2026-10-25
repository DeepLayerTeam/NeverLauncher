package ru.neverlauncher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public final class CoreTests {
    private static int assertions;
    private static void ok(boolean b,String message){assertions++;if(!b)throw new AssertionError(message);}
    private static void throwsType(Class<? extends Throwable> type,Checked action){assertions++;try{action.run();throw new AssertionError("expected "+type.getSimpleName());}catch(Throwable e){if(!type.isInstance(e))throw new AssertionError("expected "+type.getSimpleName()+", got "+e,e);}}
    @FunctionalInterface interface Checked{void run() throws Exception;}
    private static String sample(String id,String version,String deps,String conflicts){return "{\"schemaVersion\":\"2.0\",\"id\":\""+id+"\",\"name\":\"Test\",\"version\":\""+version+"\",\"publisher\":\"team\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/bin/app\"}],\"dependencies\":"+deps+",\"conflicts\":"+conflicts+"}";}
    static ExtensionManifest dep(String id,String version,String deps){return ExtensionManifest.parse(sample(id,version,deps,"[]"));}
    static void jsonAndManifest(){
        var m=dep("org.test","1.2.3","[]");ok(m.id().equals("org.test"),"manifest");
        throwsType(IllegalArgumentException.class,()->Json.parse("{\"x\":1,\"x\":2}"));
        throwsType(IllegalArgumentException.class,()->Json.parse("{\"x\":null,\"x\":2}"));
        throwsType(IllegalArgumentException.class,()->Json.parse("{\"x\": [0,]}"));
        throwsType(IllegalArgumentException.class,()->Json.parse("[true] trailing"));
        throwsType(IllegalArgumentException.class,()->ExtensionManifest.parse(sample("org.test","1.0.0","[]","[]").replace("backend/bin/app","../../etc/shadow")));
        throwsType(IllegalArgumentException.class,()->ExtensionManifest.parse(sample("org.test","1.0.0","[{\"id\":\"org.test\",\"version\":\"*\"}]","[]")));
        throwsType(IllegalArgumentException.class,()->ExtensionManifest.parse(sample("org.test","1.0.0","[{\"id\":\"org.other\",\"version\":\"invalid\"}]","[]")));
        ok(Json.object(Json.parse(Json.encode(Map.of("x",List.of("hello\\world",true,13))))).containsKey("x"),"JSON roundtrip");
    }
    static void semver(){
        ok(SemVer.parse("2.0.0-beta.2").compareTo(SemVer.parse("2.0.0-beta.11"))<0,"numeric prerelease order");
        ok(SemVer.parse("1.5.0").matches(">=1.2.0 <2.0.0"),"compound range");
        ok(!SemVer.parse("2.0.0").matches("^1.2.0"),"caret bound");
        ok(SemVer.parse("0.2.7").matches("^0.2.0"),"zero major caret");
        ok(!SemVer.parse("0.3.0").matches("^0.2.0"),"zero major upper");
        ok(SemVer.parse("1.8.0").matches("1.x"),"wildcard");
        ok(SemVer.parse("1.2.5").matches("~1.2.1"),"tilde");
        ok(SemVer.parse("1.8.0").matches("1.7.0 || 1.8.0"),"OR");
        throwsType(IllegalArgumentException.class,()->SemVer.parse("1.2.-3"));
        throwsType(IllegalArgumentException.class,()->SemVer.parse("01.2.3"));
        throwsType(IllegalArgumentException.class,()->SemVer.parse("1.2.3-01"));
        throwsType(IllegalArgumentException.class,()->SemVer.parse("1.2.3").matches("1.2.3 || nonsense"));
    }
    static void graph(){
        var lib15=dep("org.lib","1.5.0","[]");var lib2=dep("org.lib","2.0.0","[]");
        var app=dep("org.app","1.0.0","[{\"id\":\"org.lib\",\"version\":\"^1.0.0\"},{\"id\":\"org.absent\",\"version\":\"*\",\"optional\":true}]");
        var resolved=DependencyResolver.resolve(List.of(lib15,lib2,app),List.of(new ExtensionManifest.Dependency("org.app","*",false)));
        ok(resolved.size()==2&&resolved.get(0).id().equals("org.lib")&&resolved.get(1).id().equals("org.app"),"transitive selection and order");
        var cycA=dep("org.aaa","1.0.0","[{\"id\":\"org.bbb\",\"version\":\"*\"}]");
        var cycB=dep("org.bbb","1.0.0","[{\"id\":\"org.aaa\",\"version\":\"*\"}]");
        throwsType(IllegalArgumentException.class,()->DependencyResolver.resolve(List.of(cycA,cycB),List.of(new ExtensionManifest.Dependency("org.aaa","*",false))));
        throwsType(IllegalArgumentException.class,()->DependencyResolver.resolve(List.of(lib15),List.of(new ExtensionManifest.Dependency("org.missing","^1.0.0",false))));
        var conflicts=ExtensionManifest.parse(sample("org.bad","1.0.0","[]","[{\"id\":\"org.lib\",\"version\":\"^1.0.0\"}]"));
        throwsType(IllegalArgumentException.class,()->DependencyResolver.resolve(List.of(conflicts,lib15),List.of(new ExtensionManifest.Dependency("org.bad","*",false),new ExtensionManifest.Dependency("org.lib","*",false))));
        var optional=DependencyResolver.resolve(List.of(lib15),List.of(new ExtensionManifest.Dependency("org.lib","^1.0.0",false),new ExtensionManifest.Dependency("org.lib","^2.0.0",true)));
        ok(optional.size()==1&&optional.get(0).version().equals(lib15.version()),"optional version conflict skipped");
    }
    static void cancellationAndDeadline() throws Exception {
        var token=new Cancellation();AtomicInteger count=new AtomicInteger();token.onCancel(count::incrementAndGet);var child=token.child();
        ok(token.cancel()&&!token.cancel(),"cancel idempotent");ok(child.isCancelled()&&count.get()==1,"propagation");
        token.onCancel(count::incrementAndGet);ok(count.get()==2,"late listeners");
        var deadline=Deadline.after(Duration.ofMillis(10));Thread.sleep(25);ok(deadline.expired(),"monotonic expiry");throwsType(TimeoutException.class,deadline::check);
    }
    static void lifecycle() throws Exception {
        var m=dep("org.test","1.0.0","[]");AtomicInteger start=new AtomicInteger(),stop=new AtomicInteger();
        Extension ext=new Extension(){public void start(ExtensionContext c){start.incrementAndGet();}public void stop(ExtensionContext c){stop.incrementAndGet();}};
        try(var managed=new ExtensionLifecycle(ext,m)){
            managed.start(Duration.ofSeconds(1));ok(managed.state()==ExtensionLifecycle.State.RUNNING,"started");
            throwsType(IllegalStateException.class,()->managed.start(Duration.ofSeconds(1)));
            managed.stop(Duration.ofSeconds(1));ok(managed.state()==ExtensionLifecycle.State.STOPPED,"stopped");
        }ok(start.get()==1&&stop.get()==1,"callbacks once");
        Extension hangs=new Extension(){public void start(ExtensionContext c)throws Exception{Thread.sleep(60_000);}public void stop(ExtensionContext c){}};
        try(var managed=new ExtensionLifecycle(hangs,m)){
            throwsType(TimeoutException.class,()->managed.start(Duration.ofMillis(50)));ok(managed.state()==ExtensionLifecycle.State.FAILED,"deadline fails closed");
        }
    }
    static void host() throws Exception {
        AtomicInteger hello=new AtomicInteger(),heartbeats=new AtomicInteger();
        HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        String token="test-token";
        server.createContext("/v1/hello",exchange->{
            ok(exchange.getRequestHeaders().getFirst("Authorization").equals("Bearer "+token),"authorized hello");
            var req=Json.object(Json.parse(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8)));
            ok(req.get("protocolVersion").equals("1.0"),"protocol hello");hello.incrementAndGet();
            byte[] body=Json.encode(Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","instance-42","heartbeatTimeoutSeconds",3)).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();
        });
        server.createContext("/v1/heartbeat",exchange->{heartbeats.incrementAndGet();byte[] body="{\"ok\":true}".getBytes(StandardCharsets.UTF_8);exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();});
        server.start();
        try{
            Map<String,String> env=new HashMap<>();env.put("NEVERLAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+server.getAddress().getPort());env.put("NEVERLAUNCHER_EXTENSION_HOST_TOKEN",token);env.put("NEVERLAUNCHER_EXTENSION_ID","org.test");env.put("NEVERLAUNCHER_EXTENSION_VERSION","1.0.0");env.put("NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL","1.0");env.put("NEVERLAUNCHER_EXTENSION_API_VERSION","1.0");env.put("NEVERLAUNCHER_EXTENSION_INSTANCE_ID","instance-42");
            try(HostSession session=HostSession.fromEnvironment(env,dep("org.test","1.0.0","[]"))){session.connect();Thread.sleep(1300);ok(session.healthy(),"heartbeat healthy");}
            ok(hello.get()==1&&heartbeats.get()>=1,"real HTTP exchange");
            env.put("NEVERLAUNCHER_EXTENSION_ID","wrong");throwsType(IllegalArgumentException.class,()->HostSession.fromEnvironment(env,dep("org.test","1.0.0","[]")));
        }finally{server.stop(0);}
    }
    public static void main(String[] args)throws Exception{jsonAndManifest();semver();graph();cancellationAndDeadline();lifecycle();host();System.out.println("PASS: "+assertions+" Java SDK Core checks");}
}

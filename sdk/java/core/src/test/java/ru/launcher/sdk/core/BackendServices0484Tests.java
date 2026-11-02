package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Actual authenticated loopback HTTP transport and typed-response regressions. */
public final class BackendServices0484Tests {
    private static int checks;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void expect(Class<? extends Throwable> type,Action action)throws Exception {
        checks++;
        try {action.call();throw new AssertionError("expected " + type.getSimpleName());}
        catch(Throwable ex){if(!type.isInstance(ex))throw new AssertionError("unexpected exception",ex);}
    }
    private interface Action {void call()throws Exception;}
    private static void respond(HttpExchange x,int status,Object obj)throws IOException {
        byte[] data=Json.encode(obj).getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type","application/json");
        x.sendResponseHeaders(status,data.length);
        try(var out=x.getResponseBody()){out.write(data);}
    }
    private static Map<String,Object> p(String id){return Map.of("id",id,"name","A project","description","desc","homepage","https://example.org","repository","","defaultChannel","stable","createdAt","2026-11-02T00:00:00Z","updatedAt","2026-11-02T00:00:00Z");}
    private static Map<String,Object> profile(String project){return Map.of("id","profile-a","projectId",project,"name","Demo","loader","fabric","javaMajor",21,"revision",2,"isDefault",true);}
    private static Map<String,Object> channel(String project){return Map.of("id","ch1","projectId",project,"name","stable","description","Published","protected",true);}
    private static Map<String,Object> release(String project){return Map.of("id","rel1","projectId",project,"profileId","profile-a","channel","stable","version","1.0.0","status","published","manifest",Map.of("schemaVersion","3.0"),"publishedAt","2026-11-02T00:00:00Z");}
    private static Map<String,Object> job(String project){return Map.of("id","job1","projectId",project,"kind","publish","status","succeeded","attemptCount",2,"maxAttempts",3,"createdAt","2026-11-02T00:00:00Z","updatedAt","2026-11-02T00:00:00Z","completedAt","2026-11-02T00:01:00Z");}
    private static void run()throws Exception {
        AtomicBoolean revoked=new AtomicBoolean();
        AtomicBoolean malformed=new AtomicBoolean();
        HttpServer broker=HttpServer.create(new InetSocketAddress("127.0.0.1",0),10);
        broker.createContext("/v1/",x->{
            try {
                if(!"Bearer token".equals(x.getRequestHeaders().getFirst("Authorization"))){respond(x,401,Map.of("error","unauthorized"));return;}
                String path=x.getRequestURI().getPath();
                if(path.equals("/v1/hello")){
                    respond(x,200,Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","run-1","heartbeatTimeoutSeconds",300,
                            "capabilities",List.of("project.get","project.list","profile.list","profile.get","channel.list","channel.get","release.page","release.get","job.get")));
                    return;
                }
                if(path.equals("/v1/heartbeat")){respond(x,200,Map.of("ok",true));return;}
                if(!path.startsWith("/v1/capabilities/")){respond(x,404,Map.of("error","not found"));return;}
                if(revoked.get()){respond(x,403,Map.of("error","revoked"));return;}
                Map<String,Object> args=Json.object(Json.parse(new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8)));
                String project=(String)args.getOrDefault("projectId","");
                if(!project.isEmpty()&&!project.equals("p1")){respond(x,403,Map.of("error","project scope"));return;}
                Object answer;
                String operation=path.substring("/v1/capabilities/".length());
                if(operation.equals("project.get"))answer=Map.of("project",p("p1"));
                else if(operation.equals("project.list"))answer=Map.of("items",List.of(p("p1")),"nextOffset",1);
                else if(operation.equals("profile.list"))answer=Map.of("items",List.of(profile(malformed.get()?"p2":"p1")));
                else if(operation.equals("profile.get"))answer=Map.of("profile",profile("p1"));
                else if(operation.equals("channel.list"))answer=Map.of("items",List.of(channel("p1")));
                else if(operation.equals("channel.get"))answer=Map.of("channel",channel("p1"));
                else if(operation.equals("release.page"))answer=Map.of("items",List.of(release("p1")));
                else if(operation.equals("release.get"))answer=Map.of("release",release("p1"));
                else if(operation.equals("job.get"))answer=Map.of("job",job("p1"));
                else {respond(x,404,Map.of("error","unavailable"));return;}
                respond(x,200,answer);
            }catch(Exception e){respond(x,500,Map.of("error",e.getClass().getSimpleName()));}
        });
        broker.start();
        try {
            var manifest=ExtensionManifest.parse("{\"schemaVersion\":\"2.0\",\"id\":\"org.backend\",\"name\":\"Backend\",\"version\":\"1.0.0\",\"publisher\":\"test\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/main.jar\"}]}");
            Map<String,String> env=Map.of("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+broker.getAddress().getPort(),
                    "LAUNCHER_EXTENSION_ID","org.backend","LAUNCHER_EXTENSION_VERSION","1.0.0","LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0",
                    "LAUNCHER_EXTENSION_API_VERSION","1.0","LAUNCHER_EXTENSION_HOST_TOKEN","token","LAUNCHER_EXTENSION_INSTANCE_ID","run-1");
            try(var host=HostSession.fromEnvironment(env,manifest)){
                host.connect();
                try(var runtime=new RuntimeServices(host,Set.of())){
                    BackendServices api=runtime.backend();
                    check(api.project("p1").id().equals("p1"),"project get via HTTP");
                    check(api.projects(0,1).nextOffset()==1,"pagination cursor preserved");
                    check(api.profiles("p1",0,10).items().get(0).javaMajor()==21,"profile typed Java release");
                    check(api.profile("p1","profile-a").revision()==2,"profile lookup");
                    check(api.channels("p1",0,10).items().get(0).protectedChannel(),"channel typed read");
                    check(api.channel("p1","stable").name().equals("stable"),"channel lookup");
                    check(api.releases("p1",0,10).items().get(0).version().equals("1.0.0"),"release page");
                    check(api.release("p1","rel1").manifest().containsKey("schemaVersion"),"release manifest");
                    check(api.job("p1","job1").status().equals("succeeded"),"durable job status");
                    expect(IllegalArgumentException.class,()->api.projects(-1,10));
                    expect(IllegalArgumentException.class,()->api.releases("p1",0,100));
                    expect(HostSession.HostError.class,()->api.project("p2"));
                    malformed.set(true);
                    expect(SecurityException.class,()->api.profiles("p1",0,10));
                    malformed.set(false);
                    revoked.set(true);
                    expect(HostSession.HostError.class,()->api.job("p1","job1"));
                    expect(HostSession.HostError.class,()->api.channels("p1",0,10));
                }
            }
        } finally {broker.stop(0);}
    }
    public static void main(String[] argv)throws Exception {run();System.out.println("PASS: "+checks+" Java Backend Services typed HTTP, pagination and revocation checks");}
}

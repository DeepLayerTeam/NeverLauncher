package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Проверяет реальные аутентифицированные loopback-колбэки, типизированные политики и исходы постоянных заданий. */
public final class AdvancedEvents0487Tests {
    private static int checks;
    private static void check(boolean pass,String message){checks++;if(!pass)throw new AssertionError(message);}
    private static void respond(com.sun.net.httpserver.HttpExchange x,int status,Object body)throws java.io.IOException{
        byte[] bytes=Json.encode(body).getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type","application/json");x.sendResponseHeaders(status,bytes.length);
        try(var out=x.getResponseBody()){out.write(bytes);}
    }
    private static HttpResponse<String> call(HttpClient http,String endpoint,Map<String,Object> body,String token)throws Exception{
        return http.send(HttpRequest.newBuilder(URI.create(endpoint)).timeout(Duration.ofSeconds(3))
            .header("Authorization","Bearer "+token)
            .POST(HttpRequest.BodyPublishers.ofString(Json.encode(body))).build(),HttpResponse.BodyHandlers.ofString());
    }
    private static Map<String,Object> envelope(String type,String mode,String id,Object payload){
        return Map.of("protocolVersion","1.0","subscription",Map.of("eventType",type,"mode",mode),
            "event",Map.ofEntries(Map.entry("type",type),Map.entry("id",id),Map.entry("sequence",12L),Map.entry("schemaVersion",1L),Map.entry("projectId","p-1"),
                Map.entry("aggregateType","release"),Map.entry("aggregateId","rel-1"),Map.entry("orderingKey","release:rel-1"),Map.entry("source","unit-test"),
                Map.entry("idempotencyKey","unique-1"),Map.entry("payload",payload)));
    }
    public static void main(String[] args)throws Exception {
        HttpServer broker=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        AtomicInteger subscribed=new AtomicInteger();
        broker.createContext("/v1/",x->{
            try{
                if(!"Bearer host-key".equals(x.getRequestHeaders().getFirst("Authorization"))){respond(x,401,Map.of());return;}
                switch(x.getRequestURI().getPath()){
                    case "/v1/hello" -> respond(x,200,Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","one", "heartbeatTimeoutSeconds",6L,
                        "capabilities",List.of(),"eventProtocolVersion","1.0","events",List.of("project.saved","release.before-publish","release.published")));
                    case "/v1/events/subscriptions" -> respond(x,201,Map.of("id",subscribed.incrementAndGet()));
                    case "/v1/heartbeat" -> respond(x,200,Map.of("ok",true));
                    default -> respond(x,404,Map.of());
                }
            }catch(Exception e){respond(x,500,Map.of("error",e.getClass().getSimpleName()));}
        });
        broker.start();
        try{
            String manifest="{\"schemaVersion\":\"2.0\",\"id\":\"test.events487\",\"name\":\"Events\",\"version\":\"1.0.0\",\"publisher\":\"test\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/main.jar\"}]}";
            var env=new HashMap<String,String>(Map.of(
                "LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+broker.getAddress().getPort(),
                "LAUNCHER_EXTENSION_HOST_TOKEN","host-key","LAUNCHER_EXTENSION_ID","test.events487",
                "LAUNCHER_EXTENSION_VERSION","1.0.0","LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0",
                "LAUNCHER_EXTENSION_API_VERSION","1.0","LAUNCHER_EXTENSION_INSTANCE_ID","one"));
            try(var host=HostSession.fromEnvironment(env,ExtensionManifest.parse(manifest));
                var services=new RuntimeServices(host,Set.of());
                var callback=new RuntimeCallbackServer("callback-secret",services)){
                host.connect(callback.url());
                AtomicInteger executions=new AtomicInteger();
                services.events().subscribeJob("project.saved",null,Json::object,event->{
                    check(event.metadata().sequence()==12L,"sequence metadata propagated");
                    check(event.metadata().schemaVersion()==1,"schema version propagated");
                    check(event.metadata().aggregateId().equals("rel-1"),"aggregate metadata propagated");
                    check(event.event().idempotencyKey().equals("unique-1"),"durable idempotency key propagated");
                    int n=executions.incrementAndGet();
                    if(n==1)throw new java.io.IOException("temporary backend unavailable");
                    if(n==2)throw new RuntimeEvents.PermanentFailure("invalid task");
                });
                AtomicInteger hookRuns=new AtomicInteger();
                services.events().subscribeHook("release.before-publish",null,Json::object,event->{
                    int call=hookRuns.incrementAndGet();
                    if(call==1)return RuntimeEvents.HookDecision.deny("unsigned package");
                    if(call==2)return null;
                    return RuntimeEvents.HookDecision.allow();
                });
                HttpClient http=HttpClient.newHttpClient();
                String base=callback.url();
                var task=envelope("project.saved","async","evt-1",Map.of("change",1));
                HttpResponse<String> retry=call(http,base+"/v1/events",task,"callback-secret");
                check(retry.statusCode()==503,"temporary failure must retry");
                check(retry.body().contains("EVENT_RETRY"),"temporary retry is explicit");
                HttpResponse<String> dead=call(http,base+"/v1/events",task,"callback-secret");
                check(dead.statusCode()==422,"permanent task failure is nonretryable");
                check(dead.body().contains("EVENT_REJECTED"),"permanent failure has stable code");
                HttpResponse<String> ack=call(http,base+"/v1/events",task,"callback-secret");
                check(ack.statusCode()==200 && Json.object(Json.parse(ack.body())).get("accepted").equals(Boolean.TRUE),"successful task has explicit ACK");
                check(executions.get()==3,"three actual task attempts");
                var hook=envelope("release.before-publish","sync","evt-hook",Map.of("signed",false));
                check(call(http,base+"/v1/hooks",hook,"callback-secret").statusCode()==422,"hook veto denies publish");
                check(call(http,base+"/v1/hooks",hook,"callback-secret").statusCode()==422,"null policy denies publish");
                HttpResponse<String> ok=call(http,base+"/v1/hooks",hook,"callback-secret");
                check(ok.statusCode()==200 && Json.object(Json.parse(ok.body())).get("ok").equals(Boolean.TRUE),"explicit policy allow works");
                check(call(http,base+"/v1/hooks",hook,"wrong-key").statusCode()==401,"unauthorized policy callback denied");
                check(subscribed.get()==2,"two durable backend subscriptions made");
                services.events().close();
                check(call(http,base+"/v1/events",task,"callback-secret").statusCode()==422,"shutdown unregisters local handlers");
            }
        }finally{broker.stop(0);}
        System.out.println("PASS: "+checks+" Java advanced typed jobs, permanent/retry and sync policy checks");
    }
}

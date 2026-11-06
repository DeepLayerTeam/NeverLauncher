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
                    check(event.metadata().sequence()==12L,"метаданные последовательности переданы");
                    check(event.metadata().schemaVersion()==1,"версия схемы передана");
                    check(event.metadata().aggregateId().equals("rel-1"),"метаданные агрегата переданы");
                    check(event.event().idempotencyKey().equals("unique-1"),"устойчивый ключ идемпотентности передан");
                    int n=executions.incrementAndGet();
                    if(n==1)throw new java.io.IOException("Временная недоступность сервера");
                    if(n==2)throw new RuntimeEvents.PermanentFailure("Недопустимое задание");
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
                check(retry.statusCode()==503,"временная ошибка должна вызывать повтор");
                check(retry.body().contains("EVENT_RETRY"),"повтор временной ошибки указан явно");
                HttpResponse<String> dead=call(http,base+"/v1/events",task,"callback-secret");
                check(dead.statusCode()==422,"постоянная ошибка задания не допускает повтора");
                check(dead.body().contains("EVENT_REJECTED"),"постоянная ошибка имеет стабильный код");
                HttpResponse<String> ack=call(http,base+"/v1/events",task,"callback-secret");
                check(ack.statusCode()==200 && Json.object(Json.parse(ack.body())).get("accepted").equals(Boolean.TRUE),"успешное задание имеет явное подтверждение");
                check(executions.get()==3,"Три фактические попытки выполнения задания");
                var hook=envelope("release.before-publish","sync","evt-hook",Map.of("signed",false));
                check(call(http,base+"/v1/hooks",hook,"callback-secret").statusCode()==422,"запрет обработчика блокирует публикацию");
                check(call(http,base+"/v1/hooks",hook,"callback-secret").statusCode()==422,"отсутствие политики блокирует публикацию");
                HttpResponse<String> ok=call(http,base+"/v1/hooks",hook,"callback-secret");
                check(ok.statusCode()==200 && Json.object(Json.parse(ok.body())).get("ok").equals(Boolean.TRUE),"явное разрешение политики действует");
                check(call(http,base+"/v1/hooks",hook,"wrong-key").statusCode()==401,"неавторизованный вызов политики отклонён");
                check(subscribed.get()==2,"Созданы две сохраняемые подписки на события Backend");
                services.events().close();
                check(call(http,base+"/v1/events",task,"callback-secret").statusCode()==422,"завершение работы отменяет регистрацию локальных обработчиков");
            }
        }finally{broker.stop(0);}
        System.out.println("PASS: "+checks+" проверок типизированных заданий Java, постоянных и повторных операций и политики синхронизации");
    }
}

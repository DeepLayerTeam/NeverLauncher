package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public final class StateMigrations04810Tests {
    private static int checks;
    private static void check(boolean b,String message){checks++;if(!b)throw new AssertionError(message);}
    @FunctionalInterface interface Op{void run()throws Exception;}
    private static void fails(Op op)throws Exception{
        checks++;try{op.run();throw new AssertionError("операция неожиданно завершилась успешно");}
        catch(IllegalStateException|IllegalArgumentException expected){}
    }
    private static Map<String,Object> rpc(RuntimeCallbackServer server,String secret,String from,String to,int code)throws Exception{
        var request=HttpRequest.newBuilder(URI.create(server.url()+"/v1/rpc"))
            .timeout(Duration.ofSeconds(4)).header("Authorization","Bearer "+secret)
            .POST(HttpRequest.BodyPublishers.ofString(Json.encode(Map.of("protocolVersion","1.0","requestId","migration1","method","state.migrate","deadlineMs",1600L,"params",Map.of("fromVersion",from,"toVersion",to))))).build();
        var response=HttpClient.newHttpClient().send(request,HttpResponse.BodyHandlers.ofString());
        check(response.statusCode()==code,"HTTP-статус миграции "+response.statusCode()+" expected "+code);
        return Json.object(Json.parse(response.body()));
    }
    public static void main(String[] ignored)throws Exception {
        var bare=new RuntimeStateMigrations(null,null);
        AtomicInteger n=new AtomicInteger();
        bare.register("1.0.0","1.1.0",(c,s)->n.incrementAndGet());
        bare.register("1.1.0","2.0.0",(c,s)->n.incrementAndGet());
        fails(()->bare.register("2.0.0","1.0.0",(c,s)->{}));
        fails(()->bare.register("1.0.0","1.2.0",(c,s)->{}));
        check(Boolean.TRUE.equals(bare.apply("1.0.0","2.0.0").get("applied")),"цепочка выполнена");
        check(n.get()==2,"обе миграции выполнены");
        fails(()->bare.apply("1.0.0","3.0.0"));
        fails(()->bare.apply("2.0.0","1.0.0"));
        var none=new RuntimeStateMigrations(null,null);
        check(Boolean.FALSE.equals(none.apply("1.0.0","2.0.0").get("applied")),"совместимое обновление схемы не требует миграций");
        String source="{\"schemaVersion\":\"2.0\",\"id\":\"example.state\",\"name\":\"State\",\"version\":\"2.0.0\",\"api\":\"1.0\",\"publisher\":\"test\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/extension\"}]}";
        var manifest=ExtensionManifest.parse(source);
        var docs=new ConcurrentHashMap<String,Object>();
        docs.put("storage:counter",Map.of("value",7));
        HttpServer broker=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        broker.createContext("/v1/hello",e->{try{
            byte[] b=Json.encode(Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","migration","heartbeatTimeoutSeconds",30,"capabilities",List.of("runtime.storage.get","runtime.storage.put"),"events",List.of(),"eventProtocolVersion","1.0")).getBytes();
            e.sendResponseHeaders(200,b.length);e.getResponseBody().write(b);
        }finally{e.close();}});
        broker.createContext("/v1/capabilities/",e->{try{
            String method=e.getRequestURI().getPath();var params=Json.object(Json.parse(new String(e.getRequestBody().readAllBytes())));
            String key="storage:"+Json.string(params,"key",true);
            int status=200;Object result;
            if(method.endsWith(".get")){result=Map.of("value",docs.get(key));}
            else if(method.endsWith(".put")){docs.put(key,params.get("value"));result=Map.of("saved",true);}
            else{status=403;result=Map.of("error","unsupported");}
            byte[] b=Json.encode(result).getBytes();e.sendResponseHeaders(status,b.length);e.getResponseBody().write(b);
        }finally{e.close();}});
        broker.start();
        try{
            var env=Map.of("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+broker.getAddress().getPort(),"LAUNCHER_EXTENSION_HOST_TOKEN","secret","LAUNCHER_EXTENSION_ID",manifest.id(),"LAUNCHER_EXTENSION_VERSION",manifest.versionText(),"LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0","LAUNCHER_EXTENSION_API_VERSION","1.0","LAUNCHER_EXTENSION_INSTANCE_ID","migration");
            try(var host=HostSession.fromEnvironment(env,manifest);var runtime=new RuntimeServices(host,Set.of());var callback=new RuntimeCallbackServer("callback-secret",runtime)){
                host.connect(callback.url());
                runtime.stateMigrations().register("1.0.0","2.0.0",(config,storage)->{
                    var value=Json.object(storage.get("counter",null).orElseThrow());
                    storage.put("counter",Map.of("value",((Number)value.get("value")).intValue()+1),null);
                });
                var success=rpc(callback,"callback-secret","1.0.0","2.0.0",200);
                check(Boolean.TRUE.equals(success.get("ok")),"подтверждённый удалённый вызов миграции");
                check(((Number)Json.object(docs.get("storage:counter")).get("value")).intValue()==8,"миграция сохранена через настоящий посредник хоста");
                rpc(callback,"bad-secret","1.0.0","2.0.0",401);
                rpc(callback,"callback-secret","0.9.0","2.0.0",422);
                check(((Number)Json.object(docs.get("storage:counter")).get("value")).intValue()==8,"неуспешная миграция не повредила документ");
            }
        } finally{broker.stop(0);}
        System.out.println("PASS: "+checks+" Проверены цепочка миграций состояния и аутентифицированное сохранение Runtime");
    }
}

package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Реальные аутентифицированные HTTP-колбэки в стиле Go-брокера, сохранённые настройки и подписанные действия. */
public final class AdminDesktop0489Tests {
    private static int checks;
    private static void ok(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    private static Map<String,Object> rpc(HttpClient client,RuntimeCallbackServer server,String token,String method,Map<String,Object> args,int status)throws Exception{
        var data=Map.of("protocolVersion","1.0","requestId","test-0489","method",method,"deadlineMs",1200L,"params",args);
        var request=HttpRequest.newBuilder(URI.create(server.url()+"/v1/rpc")).timeout(Duration.ofSeconds(3))
            .header("Authorization","Bearer "+token).POST(HttpRequest.BodyPublishers.ofString(Json.encode(data))).build();
        var answer=client.send(request,HttpResponse.BodyHandlers.ofString());
        ok(answer.statusCode()==status,"HTTP status for "+method+": "+answer.statusCode());
        return Json.object(Json.parse(answer.body()));
    }
    public static void main(String[] args)throws Exception{
        String source="{\"schemaVersion\":\"2.0\",\"id\":\"example.admin-desktop\",\"name\":\"Integration\",\"publisher\":\"test\",\"version\":\"0.48.9\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/main.jar\"},{\"kind\":\"admin\",\"entrypoint\":\"admin/index.html\"},{\"kind\":\"desktop\",\"entrypoint\":\"desktop/index.html\"}],\"permissions\":[\"ui:contribute\",\"desktop:contribute\",\"storage:read\",\"storage:write\"],\"admin\":{\"pages\":[{\"id\":\"main\",\"title\":\"Main\"}],\"actions\":[{\"id\":\"refresh\",\"label\":\"Refresh\",\"pageId\":\"main\"}]},\"desktop\":{\"pages\":[{\"id\":\"main\",\"title\":\"Main\"}],\"actions\":[{\"id\":\"refresh\",\"label\":\"Refresh\",\"pageId\":\"main\"}]}}";
        var manifest=ExtensionManifest.parse(source);
        String base="http://127.0.0.1:7";
        var env=Map.of("LAUNCHER_EXTENSION_HOST_URL",base,"LAUNCHER_EXTENSION_HOST_TOKEN","unused","LAUNCHER_EXTENSION_ID",manifest.id(),"LAUNCHER_EXTENSION_VERSION",manifest.versionText(),"LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0","LAUNCHER_EXTENSION_API_VERSION","1.0","LAUNCHER_EXTENSION_INSTANCE_ID","run");
        // Локальный брокер отвечает настоящим HTTP на операции хранения настроек.
        var stored=new java.util.concurrent.ConcurrentHashMap<String,Object>();
        HttpServer broker=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        broker.createContext("/v1/hello",exchange->{
            try {var body=Json.encode(Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","run","heartbeatTimeoutSeconds",30,"capabilities",List.of("runtime.config.get","runtime.config.put"),"events",List.of(),"eventProtocolVersion","1.0")).getBytes(); exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body); } finally {exchange.close();}
        });
        broker.createContext("/v1/capabilities/",exchange->{
            try{
                String path=exchange.getRequestURI().getPath();
                Map<String,Object> data=Json.object(Json.parse(new String(exchange.getRequestBody().readAllBytes())));
                String key=Json.string(data,"key",true);
                int code=200;
                Object response;
                if(path.endsWith(".get")){response=stored.containsKey(key)?Map.of("value",stored.get(key)):Map.of("error","not found");if(!stored.containsKey(key))code=404;}
                else if(path.endsWith(".put")){stored.put(key,data.get("value"));response=Map.of("saved",true);}
                else{code=403;response=Map.of("error","not allowed");}
                var body=Json.encode(response).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(code,body.length);exchange.getResponseBody().write(body);
            }catch(Exception e){throw new RuntimeException(e);}finally{exchange.close();}
        });
        broker.start();
        try {
            var runtimeEnv=new HashMap<>(env);runtimeEnv.put("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+broker.getAddress().getPort());
            try(var host=HostSession.fromEnvironment(runtimeEnv,manifest);var services=new RuntimeServices(host,Set.of(),Map.of("admin",Set.of("refresh"),"desktop",Set.of("refresh")));var server=new RuntimeCallbackServer("secret",services)){
                host.connect(server.url());
                var schema=JsonSchema.parse("{\"type\":\"object\",\"properties\":{\"theme\":{\"type\":\"string\",\"enum\":[\"dark\",\"light\"]}},\"required\":[\"theme\"],\"additionalProperties\":false}");
                AtomicInteger count=new AtomicInteger();
                services.ui().registerAction("admin","refresh",null,(actor,payload)->Map.of("from",actor.get("id"),"count",count.incrementAndGet()));
                services.ui().registerAction("desktop","refresh",null,(actor,payload)->Map.of("from",actor.get("id"),"count",count.incrementAndGet()));
                services.ui().registerSetting("admin","appearance",schema,Map.of("theme","dark"));
                services.ui().registerSetting("desktop","appearance",schema,Map.of("theme","light"));
                try{services.ui().registerAction("admin","root",null,(a,p)->null);throw new AssertionError("unsigned action accepted");}
                catch(SecurityException expected){checks++;}
                var http=HttpClient.newHttpClient();
                var input=Map.<String,Object>of("surface","admin","actionId","refresh","payload",Map.of(),"actor",Map.of("id","operator"));
                ok(Boolean.TRUE.equals(rpc(http,server,"secret","ui.action.invoke",input,200).get("ok")),"signed admin action");
                ok(count.get()==1,"Java handler executed");
                ok(Boolean.TRUE.equals(rpc(http,server,"secret","ui.action.invoke",Map.of("surface","desktop","actionId","refresh","payload",Map.of(),"actor",Map.of("id","operator")),200).get("ok")),"desktop Java action");
                ok(count.get()==2,"desktop handler executed");
                rpc(http,server,"secret","ui.action.invoke",Map.of("surface","admin","actionId","other","payload",Map.of(),"actor",Map.of("id","operator")),422);
                rpc(http,server,"bad","ui.action.invoke",input,401);
                var result=rpc(http,server,"secret","ui.settings.get",Map.of("surface","admin","key","appearance"),200);
                ok("dark".equals(Json.object(Json.object(result.get("result")).get("value")).get("theme")),"default settings loaded");
                var saved=rpc(http,server,"secret","ui.settings.put",Map.of("surface","admin","key","appearance","value",Map.of("theme","light")),200);
                ok(Boolean.TRUE.equals(Json.object(saved.get("result")).get("saved")),"persisted via Host capability");
                ok("light".equals(Json.object(stored.get("ui.admin.appearance")).get("theme")),"real broker storage write");
                rpc(http,server,"secret","ui.settings.put",Map.of("surface","admin","key","appearance","value",Map.of("theme","red")),422);
                rpc(http,server,"secret","ui.settings.get",Map.of("surface","desktop","key","unknown"),422);
                services.ui().close();
                rpc(http,server,"secret","ui.action.invoke",input,422);
            }
        }finally{broker.stop(0);}
        System.out.println("PASS: "+checks+" Admin/Desktop Java UI actions and settings HTTP integration checks");
    }
}

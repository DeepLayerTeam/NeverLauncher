package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Проверяет реальные аутентифицированные HTTP-запросы HostSession и типизированные сервисы ServerBridge. */
public final class ServerBridge0488Tests {
    private static int checks;
    private static void ok(boolean value,String why){checks++;if(!value)throw new AssertionError(why);}
    private interface Action { void run() throws Exception; }
    private static void fails(Class<? extends Throwable> type,Action action) throws Exception {
        checks++;try { action.run();throw new AssertionError("expected "+type); }
        catch(Exception ex){if(!type.isInstance(ex))throw new AssertionError("неверная ошибка",ex);}
    }
    private static void reply(HttpExchange x,int code,Object value)throws IOException {
        byte[] body=Json.encode(value).getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type","application/json");
        x.sendResponseHeaders(code,body.length);
        try(var out=x.getResponseBody()){out.write(body);}
    }
    private static Map<String,Object> node(String project){
        return Map.ofEntries(Map.entry("id","server1"),Map.entry("projectId",project),Map.entry("profileId","vanilla"),
            Map.entry("name","Game"),Map.entry("kind","paper"),Map.entry("status","active"),
            Map.entry("protocolVersion",3),Map.entry("runtimeEpoch",2),Map.entry("runtimeActive",true),
            Map.entry("lastHeartbeatAt","2026-11-02T12:00:00Z"),Map.entry("playersOnline",5),
            Map.entry("serverBrand","Paper"),Map.entry("minecraftVersion","1.21.1"));
    }
    private static Map<String,Object> command(){
        return Map.of("id","ext-c1","serverId","server1","type","message.broadcast","status","pending",
            "attempt",0,"runtimeEpoch",2,"createdAt","2026-11-02T12:00:00Z","updatedAt","2026-11-02T12:00:00Z");
    }
    public static void main(String[] args)throws Exception {
        AtomicBoolean revoked=new AtomicBoolean();AtomicBoolean wrongProject=new AtomicBoolean();
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),4);
        server.createContext("/v1/",x->{
            try {
                if(!"Bearer bridge-token".equals(x.getRequestHeaders().getFirst("Authorization"))){reply(x,401,Map.of("error","unauthorized"));return;}
                String path=x.getRequestURI().getPath();
                if(path.equals("/v1/hello")){
                    reply(x,200,Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","bridge-run",
                            "heartbeatTimeoutSeconds",300,"capabilities",List.of("bridge.servers","bridge.server","bridge.command.create","bridge.command.get","bridge.access.ticket"),
                            "events",List.of("serverbridge.event.received"),"eventProtocolVersion","1.0"));return;
                }
                if(path.equals("/v1/heartbeat")){reply(x,200,Map.of("ok",true));return;}
                if(path.equals("/v1/events/subscriptions")){reply(x,201,Map.of("id",45));return;}
                if(revoked.get()){reply(x,403,Map.of("error","revoked"));return;}
                Map<String,Object> req=Json.object(Json.parse(new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8)));
                if(!"p1".equals(req.get("projectId"))){reply(x,403,Map.of("error","project denied"));return;}
                String operation=path.substring("/v1/capabilities/".length());
                if(operation.equals("bridge.servers")){reply(x,200,Map.of("items",List.of(node(wrongProject.get()?"p2":"p1")),"nextOffset",1));return;}
                if(operation.equals("bridge.server")){reply(x,200,Map.of("server",node(wrongProject.get()?"p2":"p1")));return;}
                if(operation.equals("bridge.command.create")){
                    if(!"message.broadcast".equals(req.get("commandType"))||!Map.of("message","Hello").equals(req.get("payload"))){reply(x,400,Map.of("error","invalid command"));return;}
                    reply(x,200,Map.of("command",command(),"idempotentReplay",false));return;
                }
                if(operation.equals("bridge.access.ticket")){reply(x,200,Map.of("pendingTicket",true));return;}
                if(operation.equals("bridge.command.get")){reply(x,200,Map.of("command",command()));return;}
                reply(x,404,Map.of("error","unknown"));
            } catch(Exception e){ reply(x,500,Map.of("error",e.toString())); }
        });
        server.start();
        try {
            var manifest=ExtensionManifest.parse("{\"schemaVersion\":\"2.0\",\"id\":\"org.bridge\",\"name\":\"Bridge\",\"version\":\"1.0.0\",\"publisher\":\"test\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/main.jar\"}]}");
            var env=Map.of("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+server.getAddress().getPort(),
                "LAUNCHER_EXTENSION_ID","org.bridge","LAUNCHER_EXTENSION_VERSION","1.0.0", "LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0",
                "LAUNCHER_EXTENSION_API_VERSION","1.0","LAUNCHER_EXTENSION_HOST_TOKEN","bridge-token","LAUNCHER_EXTENSION_INSTANCE_ID","bridge-run");
            try(var host=HostSession.fromEnvironment(env,manifest)) {
                host.connect();
                try(var services=new RuntimeServices(host,Set.of())) {
                    var bridge=services.serverBridge();
                    ok(bridge.server("p1","server1").runtimeActive(),"actual typed status over HTTP");
                    ok(bridge.servers("p1",0,10).items().get(0).playersOnline()==5,"player count typed");
                    ok(bridge.servers("p1",0,10).nextOffset()==1,"cursor");
                    ok(bridge.command("p1","server1","message.broadcast",Map.of("message","Hello"),"dedupe-123",120).command().status().equals("pending"),"command enqueued, not executed");
                    ok(bridge.commandStatus("p1","server1","ext-c1").id().equals("ext-c1"),"durable command query");
                    ok(bridge.pendingJoinTicket("p1","server1","Player_1"),"pending ticket, not admission permission");
                    fails(IllegalArgumentException.class,()->bridge.pendingJoinTicket("p1","server1","../bad"));
                    fails(IllegalArgumentException.class,()->bridge.command("p1","server1","server.console",Map.of("command","op"),"dedupe-123",120));
                    fails(IllegalArgumentException.class,()->bridge.command("p1","server1","server.shutdown",Map.of(),"dedupe-123",120));
                    fails(IllegalArgumentException.class,()->bridge.servers("p1",0,51));
                    fails(HostSession.HostError.class,()->bridge.server("other","server1"));
                    wrongProject.set(true);
                    fails(SecurityException.class,()->bridge.server("p1","server1"));
                    fails(SecurityException.class,()->bridge.servers("p1",0,10));
                    wrongProject.set(false);
                    ok(bridge.subscribeEvents(value->ok(value.event().type().equals("serverbridge.event.received"),"decoded event"))==45,"event subscription via broker");
                    revoked.set(true);
                    fails(HostSession.HostError.class,()->bridge.commandStatus("p1","server1","ext-c1"));
                    fails(HostSession.HostError.class,()->bridge.command("p1","server1","message.broadcast",Map.of("message","Hello"),"dedupe-124",120));
                }
            }
        } finally {server.stop(0);}
        System.out.println("PASS: "+checks+" Java ServerBridge authenticated API and revocation assertions");
    }
}

package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Executes actual authenticated HTTP requests and typed loopback callbacks. */
public final class RuntimeApiTests {
    private static int checks;
    static void check(boolean condition,String what){checks++;if(!condition)throw new AssertionError(what);}
    static void fails(Runnable op){checks++;try{op.run();throw new AssertionError("expected rejection");}catch(IllegalArgumentException|SecurityException expected){}}
    static String manifest="{\"schemaVersion\":\"2.0\",\"id\":\"test.runtime\",\"name\":\"Runtime\",\"version\":\"1.0.0\",\"publisher\":\"test\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/run\"}],\"permissions\":[\"storage:read\",\"storage:write\",\"events:subscribe\",\"secrets:read\"]}";
    static void respond(com.sun.net.httpserver.HttpExchange x,int code,Object value)throws IOException {
        byte[] body=Json.encode(value).getBytes(StandardCharsets.UTF_8);x.getResponseHeaders().set("Content-Type","application/json");x.sendResponseHeaders(code,body.length);try(var out=x.getResponseBody()){out.write(body);}
    }
    @SuppressWarnings("unchecked")
    static void test()throws Exception {
        Map<String,Object> values=Collections.synchronizedMap(new HashMap<>());
        AtomicInteger subscribed=new AtomicInteger();
        AtomicInteger unsubscribed=new AtomicInteger();
        HttpServer fake=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        fake.createContext("/v1/",x->{
            try {
                if(!"Bearer host-token".equals(x.getRequestHeaders().getFirst("Authorization"))){respond(x,401,Map.of("error","unauthorized"));return;}
                String path=x.getRequestURI().getPath();
                // Use a single read of the request body for all paths.
                // Input is reparsed below by dedicated route handler for clarity.
                if(path.equals("/v1/hello")){respond(x,200,Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","run-1","heartbeatTimeoutSeconds",6,"capabilities",List.of("runtime.config.get","runtime.config.put","runtime.config.delete","runtime.storage.get","runtime.storage.put","runtime.storage.delete","secret.get"),"eventProtocolVersion","1.0","events",List.of("release.published","project.saved","release.before-publish")));return;}
                if(path.equals("/v1/heartbeat")){respond(x,200,Map.of("ok",true));return;}
                respond(x,404,Map.of("error","not found"));
            }catch(Exception ex){respond(x,500,Map.of("error",ex.toString()));}
        });
        // More specific contexts take priority over /v1/.
        fake.createContext("/v1/capabilities/",x->{
            try {
                check("Bearer host-token".equals(x.getRequestHeaders().getFirst("Authorization")),"broker authorized");
                String path=x.getRequestURI().getPath();var req=Json.object(Json.parse(new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8)));
                if(path.endsWith("secret.get")){if("blocked".equals(req.get("name"))){respond(x,403,Map.of("error","forbidden"));return;}respond(x,200,Map.of("valueBase64",Base64.getEncoder().encodeToString("s3cret".getBytes(StandardCharsets.UTF_8))));return;}
                String key=path+":"+req.get("key");
                if(path.endsWith(".put")){values.put(key.replace(".put:",".get:"),req.get("value"));respond(x,200,Map.of("saved",true));return;}
                if(path.endsWith(".get")){if(!values.containsKey(key)){respond(x,404,Map.of("error","missing"));return;}respond(x,200,Map.of("value",values.get(key)));return;}
                if(path.endsWith(".delete")){values.remove(key.replace(".delete:",".get:"));respond(x,200,Map.of("deleted",true));return;}
                respond(x,404,Map.of("error","missing"));
            }catch(Exception ex){respond(x,500,Map.of("error",ex.toString()));}
        });
        fake.createContext("/v1/events/subscriptions",x->{
            check("Bearer host-token".equals(x.getRequestHeaders().getFirst("Authorization")),"subscribe authorized");
            if(x.getRequestMethod().equals("DELETE")){unsubscribed.incrementAndGet();x.sendResponseHeaders(204,-1);x.close();return;}
            subscribed.incrementAndGet();respond(x,201,Map.of("id",4));
        });
        fake.start();
        try {
            var env=new HashMap<String,String>();env.put("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+fake.getAddress().getPort());env.put("LAUNCHER_EXTENSION_HOST_TOKEN","host-token");env.put("LAUNCHER_EXTENSION_ID","test.runtime");env.put("LAUNCHER_EXTENSION_VERSION","1.0.0");env.put("LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0");env.put("LAUNCHER_EXTENSION_API_VERSION","1.0");env.put("LAUNCHER_EXTENSION_INSTANCE_ID","run-1");
            var configSchema=JsonSchema.parse("{\"type\":\"object\",\"properties\":{\"enabled\":{\"type\":\"boolean\"},\"rate\":{\"type\":\"integer\",\"minimum\":0,\"maximum\":10}},\"required\":[\"enabled\"],\"additionalProperties\":false}");
            fails(()->configSchema.validate(Map.of("enabled",true,"unexpected",8)));
            fails(()->configSchema.validate(Map.of("enabled",true,"rate",11)));
            fails(()->JsonSchema.parse("{\"$ref\":\"somewhere\"}"));
            try(var host=HostSession.fromEnvironment(env,ExtensionManifest.parse(manifest));
                var services=new RuntimeServices(host,Set.of("status","empty"));
                var callbacks=new RuntimeCallbackServer("callback-token",services)) {
                host.connect(callbacks.url());
                check(host.capabilities().contains("secret.get"),"host capabilities negotiated");
                check(services.config().get("settings",configSchema).isEmpty(),"missing config");
                services.config().put("settings",Map.of("enabled",true,"rate",2),configSchema);
                check(services.config().get("settings",configSchema).isPresent(),"config stored");
                services.storage().put("counter",Map.of("count",1),null);
                check(services.storage().get("counter",null).isPresent(),"storage stored");
                services.storage().delete("counter");
                check(services.storage().get("counter",null).isEmpty(),"storage deleted");
                byte[][] view=new byte[1][];
                String secret=services.secrets().withSecret("key","",bytes->{view[0]=bytes;return new String(bytes,StandardCharsets.UTF_8);});
                check(secret.equals("s3cret")&&Arrays.equals(view[0],new byte[6]),"secret delivered, buffer zeroed");
                try{services.secrets().withSecret("blocked","",bytes->null);throw new AssertionError("policy bypass");}catch(HostSession.HostError e){check(e.status()==403,"secret broker denied access");}
                var payloadSchema=JsonSchema.parse("{\"type\":\"object\",\"properties\":{\"version\":{\"type\":\"string\",\"minLength\":1}},\"required\":[\"version\"],\"additionalProperties\":false}");
                record Release(String version){}
                AtomicInteger delivered=new AtomicInteger();
                services.events().subscribe("release.published","async",payloadSchema,raw->new Release(Json.string(Json.object(raw),"version",true)),event->{check(event.payload().version().equals("1.0.0"),"typed payload");delivered.incrementAndGet();});
                check(subscribed.get()==1,"server subscription");
                services.commands().register("status",JsonSchema.parse("{\"type\":\"object\",\"properties\":{\"verbose\":{\"type\":\"boolean\"},\"args\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}}}"),raw->Json.object(raw),args->Map.of("ok",true));
                services.commands().register("empty",null,x->x,args->null);
                fails(()->services.commands().register("danger",null,x->x,x->Map.of()));
                check(services.commands().invoke("status",Map.of("verbose",true)).equals(Map.of("ok",true)),"typed local command");
                HttpClient client=HttpClient.newHttpClient();
                String event=Json.encode(Map.of("protocolVersion","1.0","subscription",Map.of("eventType","release.published","mode","async"),"event",Map.of("type","release.published","id","ev-1","idempotencyKey","once","payload",Map.of("version","1.0.0"))));
                int denied=callback(client,callbacks.url()+"/v1/events",event,"wrong");check(denied==401,"unauthenticated event rejected");
                check(callback(client,callbacks.url()+"/v1/events",event,"callback-token")==200&&delivered.get()==1,"authenticated typed event handled");
                String malformed=event.replace("\"1.0.0\"","18");
                check(callback(client,callbacks.url()+"/v1/events",malformed,"callback-token")==422,"schema mismatch rejected");
                check(callback(client,callbacks.url()+"/v1/commands",Json.encode(Map.of("command","status","payload",Map.of("verbose",true))),"callback-token")==200,"command callback dispatched");
                check(callback(client,callbacks.url()+"/v1/commands",Json.encode(Map.of("command","empty","payload",Map.of())),"callback-token")==200,
                    "JSON null command results succeed");
                check(callback(client,callbacks.url()+"/v1/rpc",Json.encode(Map.of("protocolVersion","1.0","requestId","abc-123","method","command.invoke","deadlineMs",1500L,
                    "params",Map.of("command","empty","payload",Map.of()))),"callback-token")==200,
                    "null command results succeed through versioned JVM RPC");
                // A real event envelope can exceed 64 KiB even when its payload is
                // well inside the server's permitted 1 MiB durable event size.
                AtomicInteger largeDelivered=new AtomicInteger();
                services.events().subscribe("project.saved","async",null,Json::object,incoming->{
                    check(((String)incoming.payload().get("data")).length()==150000,"large event payload intact");
                    largeDelivered.incrementAndGet();
                });
                String largeEvent=Json.encode(Map.of("protocolVersion","1.0",
                    "subscription",Map.of("eventType","project.saved","mode","async"),
                    "event",Map.of("type","project.saved","id","ev-large","idempotencyKey","large-1",
                        "payload",Map.of("data","x".repeat(150000)))));
                check(largeEvent.length()>65536,"large event exceeds RPC limit");
                check(callback(client,callbacks.url()+"/v1/events",largeEvent,"callback-token")==200 && largeDelivered.get()==1,
                    "durable-size event delivered through real HTTP callback");
                // A noncooperative callback must not be able to bypass request bounds.
                check(callback(client,callbacks.url()+"/v1/events"," ".repeat(2*1024*1024+1),"callback-token")==413,
                    "oversized event rejected");
                check(callback(client,callbacks.url()+"/v1/rpc"," ".repeat(65537),"callback-token")==413,
                    "RPC keeps original independent 64 KiB limit");
                services.events().subscribe("release.before-publish","sync",null,Json::object,incoming->{
                    throw new IllegalArgumentException("operator rejected publish");
                });
                String hook=Json.encode(Map.of("protocolVersion","1.0",
                    "subscription",Map.of("eventType","release.before-publish","mode","sync"),
                    "event",Map.of("type","release.before-publish","id","ev-hook","payload",Map.of("version","2"))));
                check(callback(client,callbacks.url()+"/v1/hooks",hook,"callback-token")==422,
                    "rejected synchronous hook fails closed");
                check(callback(client,callbacks.url()+"/v1/commands",Json.encode(Map.of("command","status","payload",Map.of("verbose",true))),"wrong")==401,
                    "commands cannot be invoked without authenticated callback token");
                services.events().unsubscribe("project.saved","async");
                check(unsubscribed.get()==1,"explicit unsubscription removes backend durable subscription");
                services.close();
                check(unsubscribed.get()==1,"closing extension does not delete pending durable subscriptions");
                try(var restored=new RuntimeServices(host,Set.of("status","empty"));
                    var restoredCallback=new RuntimeCallbackServer("callback-token",restored)){
                    AtomicInteger recovered=new AtomicInteger();
                    restored.events().subscribe("release.published","async",payloadSchema,raw->new Release(Json.string(Json.object(raw),"version",true)),incoming->{recovered.incrementAndGet();});
                    check(callback(client,restoredCallback.url()+"/v1/events",event,"callback-token")==200&&recovered.get()==1,
                        "new JVM runtime can resume durable subscription after handler shutdown");
                }
                check(unsubscribed.get()==1,"recovered runtime shutdown preserves durable subscription");
            }
        }finally{fake.stop(0);}
    }
    private static int callback(HttpClient client,String url,String value,String bearer)throws Exception {
        var req=HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(3)).header("Authorization","Bearer "+bearer).POST(HttpRequest.BodyPublishers.ofString(value)).build();
        return client.send(req,HttpResponse.BodyHandlers.discarding()).statusCode();
    }
    public static void main(String[]args)throws Exception{test();System.out.println("PASS: "+checks+" Java runtime broker/event/command/schema tests");}
}

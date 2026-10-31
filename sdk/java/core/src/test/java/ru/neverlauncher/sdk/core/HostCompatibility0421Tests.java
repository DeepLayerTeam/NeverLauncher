package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Real loopback HTTP compatibility tests, including the 0.42.0 hello envelope. */
public final class HostCompatibility0421Tests {
    private static int assertions;
    private static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    private static final ExtensionManifest MANIFEST=ExtensionManifest.parse("{\"schemaVersion\":\"2.0\",\"id\":\"example.compat\",\"name\":\"Compatibility\",\"version\":\"1.0.0\",\"publisher\":\"test\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/extension.jar\"}]}");
    private static final class FakeHost implements AutoCloseable {
        final HttpServer server;
        final AtomicInteger hellos=new AtomicInteger(),capabilities=new AtomicInteger(),subscriptions=new AtomicInteger(),ready=new AtomicInteger();
        volatile Object hello=Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","i-42","heartbeatTimeoutSeconds",60,
            "capabilities",List.of("runtime.config.get","runtime.config.put","runtime.config.delete"),"events",List.of("project.saved"),"eventProtocolVersion","1.0");
        volatile int helloStatus=200;
        volatile boolean emptyReady;
        FakeHost()throws IOException {
            server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
            server.createContext("/v1/",exchange->{
                try{
                    if(!"Bearer key-42".equals(exchange.getRequestHeaders().getFirst("Authorization"))){send(exchange,401,Map.of("code","HOST_UNAUTHORIZED"));return;}
                    String path=exchange.getRequestURI().getPath();
                    if(path.equals("/v1/hello")){
                        hellos.incrementAndGet();
                        Map<String,Object> body=Json.object(Json.parse(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8)));
                        check(body.keySet().equals(Set.of("protocolVersion","extensionApiVersion","instanceId","extensionId","pid")),"SDK 0.42.0 hello fields unchanged");
                        send(exchange,helloStatus,hello);return;
                    }
                    if(path.equals("/v1/ready")){
                        ready.incrementAndGet();
                        if(emptyReady){exchange.sendResponseHeaders(200,-1);exchange.close();return;}
                        send(exchange,200,Map.of("ready",true));return;
                    }
                    if(path.startsWith("/v1/capabilities/")){capabilities.incrementAndGet();send(exchange,200,Map.of("value",3));return;}
                    if(path.equals("/v1/events/subscriptions")){subscriptions.incrementAndGet();send(exchange,201,Map.of("id",1));return;}
                    if(path.equals("/v1/heartbeat")){send(exchange,200,Map.of("ok",true));return;}
                    send(exchange,404,Map.of("error","missing"));
                }catch(Exception ex){send(exchange,500,Map.of("error","fixture failed"));}
            });
            server.start();
        }
        HostSession session(){
            var env=new HashMap<String,String>();env.put("NEVERLAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+server.getAddress().getPort());
            env.put("NEVERLAUNCHER_EXTENSION_HOST_TOKEN","key-42");env.put("NEVERLAUNCHER_EXTENSION_ID",MANIFEST.id());
            env.put("NEVERLAUNCHER_EXTENSION_VERSION","1.0.0");env.put("NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL","1.0");
            env.put("NEVERLAUNCHER_EXTENSION_API_VERSION","1.0");env.put("NEVERLAUNCHER_EXTENSION_INSTANCE_ID","i-42");
            return HostSession.fromEnvironment(env,MANIFEST);
        }
        void send(com.sun.net.httpserver.HttpExchange e,int status,Object body)throws IOException {
            byte[] bytes=Json.encode(body).getBytes(StandardCharsets.UTF_8);
            e.getResponseHeaders().set("Content-Type","application/json");
            e.sendResponseHeaders(status,bytes.length);try(var out=e.getResponseBody()){out.write(bytes);}
        }
        public void close(){server.stop(0);}
    }
    private static void successOldHost()throws Exception {
        try(var server=new FakeHost();var client=server.session()){
            client.connect("",Set.of("runtime.config.get"));
            check(client.capabilities().contains("runtime.config.get"),"0.42.0 host capabilities accepted");
            check(client.capability("runtime.config.get",Map.of("key","a")).get("value").equals(3L),"real capability RPC delivered");
            client.ready();check(server.ready.get()==1,"ready acknowledgement delivered");
            check(server.hellos.get()==1,"hello once");
            try{client.connect();throw new AssertionError("repeated hello accepted");}catch(IllegalStateException ok){assertions++;}
            check(server.hellos.get()==1,"duplicate hello not sent");
            try{client.capability("secret.get",Map.of());throw new AssertionError("missing capability accepted");}catch(SecurityException ok){assertions++;}
            check(server.capabilities.get()==1,"missing capability did not reach host");
            try{client.subscribe("release.future","async");throw new AssertionError("unknown event accepted");}catch(SecurityException ok){assertions++;}
            check(server.subscriptions.get()==0,"unknown event did not hit subscribe endpoint");
        }
    }
    private static void requiredCapabilityMissing()throws Exception {
        try(var server=new FakeHost();var client=server.session()){
            try{client.connect("",Set.of("runtime.storage.delete"));throw new AssertionError("missing feature accepted");}
            catch(HostSession.CompatibilityError ex){check(ex.code().equals("HOST_CAPABILITY_UNAVAILABLE"),"machine code for unavailable feature");}
            check(server.capabilities.get()==0&&server.ready.get()==0,"required-feature mismatch before host side effects");
        }
    }
    private static void rejectionAndMalformedHello()throws Exception {
        try(var server=new FakeHost();var client=server.session()){
            server.helloStatus=409;server.hello=Map.of("error","host hello rejected","code","HOST_EXTENSION_API_MISMATCH");
            try{client.connect();throw new AssertionError("API mismatch accepted");}
            catch(HostSession.HostError ex){check(ex.status()==409 && ex.code().equals("HOST_EXTENSION_API_MISMATCH"),"structured Go host reason retained");}
        }
        try(var server=new FakeHost();var client=server.session()){
            server.hello=Map.of("protocolVersion","2.0","extensionApiVersion","1.0","instanceId","i-42","heartbeatTimeoutSeconds",60);
            try{client.connect();throw new AssertionError("protocol mismatch accepted");}
            catch(HostSession.CompatibilityError ex){check(ex.code().equals("HOST_PROTOCOL_MISMATCH"),"protocol version reason");}
        }
        try(var server=new FakeHost();var client=server.session()){
            server.hello=Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","i-42","heartbeatTimeoutSeconds",60,"capabilities",List.of("secret.get","secret.get"));
            try{client.connect();throw new AssertionError("duplicate caps accepted");}catch(IOException ex){check(ex.getMessage().contains("capabilities"),"malformed negotiation fails");}
        }
        try(var server=new FakeHost();var client=server.session()){
            server.hello=Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","i-42","heartbeatTimeoutSeconds",60,"capabilities",List.of("secret.get"),"eventProtocolVersion","2.0");
            try{client.connect();throw new AssertionError("new event protocol accepted");}
            catch(HostSession.CompatibilityError ex){check(ex.code().equals("HOST_EVENT_PROTOCOL_MISMATCH"),"event protocol independent from Host Protocol");}
        }
    }
    private static void readyAcknowledgementAndPreconnectGuard()throws Exception {
        try(var server=new FakeHost();var client=server.session()){
            try{client.capability("runtime.config.get",Map.of());throw new AssertionError("pre-hello capability accepted");}catch(IllegalStateException ok){assertions++;}
            server.emptyReady=true;client.connect();
            try{client.ready();throw new AssertionError("missing ready acknowledgement accepted");}
            catch(IOException ex){check(ex.getMessage().contains("readiness"),"missing readiness payload rejected");}
            check(server.ready.get()==1,"ready was transmitted");
        }
    }
    public static void main(String[] args)throws Exception {
        successOldHost();requiredCapabilityMissing();rejectionAndMalformedHello();readyAcknowledgementAndPreconnectGuard();
        System.out.println("PASS: "+assertions+" Java SDK/Host Protocol 0.42.0 <-> 0.42.1 compatibility checks");
    }
}

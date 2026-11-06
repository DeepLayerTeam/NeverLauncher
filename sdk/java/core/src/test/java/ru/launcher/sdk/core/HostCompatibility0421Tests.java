package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Реальные loopback HTTP-тесты совместимости, включая конверт hello версии 0.42.0. */
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
            var env=new HashMap<String,String>();env.put("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+server.getAddress().getPort());
            env.put("LAUNCHER_EXTENSION_HOST_TOKEN","key-42");env.put("LAUNCHER_EXTENSION_ID",MANIFEST.id());
            env.put("LAUNCHER_EXTENSION_VERSION","1.0.0");env.put("LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0");
            env.put("LAUNCHER_EXTENSION_API_VERSION","1.0");env.put("LAUNCHER_EXTENSION_INSTANCE_ID","i-42");
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
            check(client.capability("runtime.config.get",Map.of("key","a")).get("value").equals(3L),"реальный удалённый вызов разрешения доставлен");
            client.ready();check(server.ready.get()==1,"подтверждение готовности доставлено");
            check(server.hellos.get()==1,"приветствие отправлено один раз");
            try{client.connect();throw new AssertionError("повторное приветствие ошибочно принято");}catch(IllegalStateException ok){assertions++;}
            check(server.hellos.get()==1,"повторное приветствие не отправлено");
            try{client.capability("secret.get",Map.of());throw new AssertionError("принят запрос без требуемого разрешения");}catch(SecurityException ok){assertions++;}
            check(server.capabilities.get()==1,"запрос без разрешения не достиг хоста");
            try{client.subscribe("release.future","async");throw new AssertionError("неизвестное событие ошибочно принято");}catch(SecurityException ok){assertions++;}
            check(server.subscriptions.get()==0,"неизвестное событие не достигло обработчика подписки");
        }
    }
    private static void requiredCapabilityMissing()throws Exception {
        try(var server=new FakeHost();var client=server.session()){
            try{client.connect("",Set.of("runtime.storage.delete"));throw new AssertionError("принят запрос без требуемой возможности");}
            catch(HostSession.CompatibilityError ex){check(ex.code().equals("HOST_CAPABILITY_UNAVAILABLE"),"машинный код недоступной возможности");}
            check(server.capabilities.get()==0&&server.ready.get()==0,"required-feature mismatch before host side effects");
        }
    }
    private static void rejectionAndMalformedHello()throws Exception {
        try(var server=new FakeHost();var client=server.session()){
            server.helloStatus=409;server.hello=Map.of("error","host hello rejected","code","HOST_EXTENSION_API_MISMATCH");
            try{client.connect();throw new AssertionError("несовместимая версия API ошибочно принята");}
            catch(HostSession.HostError ex){check(ex.status()==409 && ex.code().equals("HOST_EXTENSION_API_MISMATCH"),"структурированная причина от хоста Go сохранена");}
        }
        try(var server=new FakeHost();var client=server.session()){
            server.hello=Map.of("protocolVersion","2.0","extensionApiVersion","1.0","instanceId","i-42","heartbeatTimeoutSeconds",60);
            try{client.connect();throw new AssertionError("несовместимая версия протокола ошибочно принята");}
            catch(HostSession.CompatibilityError ex){check(ex.code().equals("HOST_PROTOCOL_MISMATCH"),"причина несовместимости версии протокола");}
        }
        try(var server=new FakeHost();var client=server.session()){
            server.hello=Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","i-42","heartbeatTimeoutSeconds",60,"capabilities",List.of("secret.get","secret.get"));
            try{client.connect();throw new AssertionError("дублирующие разрешения ошибочно приняты");}catch(IOException ex){check(ex.getMessage().contains("capabilities"),"malformed negotiation fails");}
        }
        try(var server=new FakeHost();var client=server.session()){
            server.hello=Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","i-42","heartbeatTimeoutSeconds",60,"capabilities",List.of("secret.get"),"eventProtocolVersion","2.0");
            try{client.connect();throw new AssertionError("неподдерживаемый протокол событий ошибочно принят");}
            catch(HostSession.CompatibilityError ex){check(ex.code().equals("HOST_EVENT_PROTOCOL_MISMATCH"),"протокол событий не зависит от протокола хоста");}
        }
    }
    private static void readyAcknowledgementAndPreconnectGuard()throws Exception {
        try(var server=new FakeHost();var client=server.session()){
            try{client.capability("runtime.config.get",Map.of());throw new AssertionError("разрешение до приветствия ошибочно принято");}catch(IllegalStateException ok){assertions++;}
            server.emptyReady=true;client.connect();
            try{client.ready();throw new AssertionError("отсутствие подтверждения готовности ошибочно принято");}
            catch(IOException ex){check(ex.getMessage().contains("готовность"),"отсутствие данных готовности отклонено");}
            check(server.ready.get()==1,"сообщение о готовности передано");
        }
    }
    public static void main(String[] args)throws Exception {
        successOldHost();requiredCapabilityMissing();rejectionAndMalformedHello();readyAcknowledgementAndPreconnectGuard();
        System.out.println("PASS: "+assertions+" Java SDK/Host Protocol 0.42.0 <-> 0.42.1 compatibility checks");
    }
}

package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Реальное планирование потоков и регрессионные проверки loopback HTTP для SDK/хоста 0.48.1. */
public final class HostStability0481Tests {
    private static int checks;
    private static void check(boolean yes,String message){checks++;if(!yes)throw new AssertionError(message);}
    private static final ExtensionManifest MANIFEST=ExtensionManifest.parse("{\"schemaVersion\":\"2.0\",\"id\":\"org.stability\",\"name\":\"Stability\",\"version\":\"1.0.0\",\"publisher\":\"test\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/app.jar\"}]}");
    private static void expect(Class<? extends Throwable> type,Throwing action)throws Exception {
        checks++;
        try{action.run();throw new AssertionError("ожидалось исключение "+type.getSimpleName());}
        catch(Throwable failure){if(!type.isInstance(failure))throw new AssertionError("неожиданное исключение",failure);}
    }
    private interface Throwing{void run()throws Exception;}

    private static void concurrentStopOfHungStart()throws Exception {
        CountDownLatch entered=new CountDownLatch(1),released=new CountDownLatch(1);
        AtomicInteger stops=new AtomicInteger();AtomicReference<Throwable> failure=new AtomicReference<>();
        Extension extension=new Extension(){
            public void start(ExtensionContext ctx){
                entered.countDown();
                while(released.getCount()>0){try{released.await(50,TimeUnit.MILLISECONDS);}catch(InterruptedException ignored){}}
            }
            public void stop(ExtensionContext ctx){stops.incrementAndGet();}
        };
        try(var lifecycle=new ExtensionLifecycle(extension,MANIFEST)){
            Thread worker=new Thread(()->{try{lifecycle.start(Duration.ofSeconds(10));}catch(Throwable ex){failure.set(ex);}},"test-start-thread");
            worker.start();
            try {
                check(entered.await(2,TimeUnit.SECONDS),"начался вызов обработчика запуска");
                long beginning=System.nanoTime();
                check(lifecycle.state()==ExtensionLifecycle.State.STARTING,"состояние доступно при выполнении пользовательского кода");
                lifecycle.stop(Duration.ofMillis(250));
                long milliseconds=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-beginning);
                check(milliseconds<500,"Остановка не должна ожидать заблокированный обратный вызов запуска: "+milliseconds+"ms");
                check(lifecycle.state()==ExtensionLifecycle.State.STOPPED,"остановка опережает запуск при конкурентном выполнении");
                check(lifecycle.state()==ExtensionLifecycle.State.STOPPED,"состояние остаётся стабильным после отмены");
            }finally{released.countDown();worker.join(1500);}
            check(!worker.isAlive(),"поток отменённого запуска завершился");
            check(failure.get() instanceof CancellationException,"отменённый запуск сообщает об отмене");
            check(stops.get()==0,"обработчик остановки не вызывается у незапущенного расширения");
        }
    }
    private static void concurrentStopWaitsForCleanup()throws Exception {
        CountDownLatch entered=new CountDownLatch(1),allowStop=new CountDownLatch(1);
        AtomicReference<Throwable> error=new AtomicReference<>();
        AtomicInteger count=new AtomicInteger();
        Extension extension=new Extension(){
            public void start(ExtensionContext ctx){}
            public void stop(ExtensionContext ctx)throws Exception{
                count.incrementAndGet();entered.countDown();allowStop.await();
            }
        };
        try(var lifecycle=new ExtensionLifecycle(extension,MANIFEST)){
            lifecycle.start(Duration.ofSeconds(1));
            Thread first=new Thread(()->{try{lifecycle.stop(Duration.ofSeconds(3));}catch(Throwable e){error.set(e);}});
            first.start();
            check(entered.await(1,TimeUnit.SECONDS),"вызван обработчик остановки");
            Thread second=new Thread(()->{try{lifecycle.stop(Duration.ofSeconds(3));}catch(Throwable e){error.set(e);}});
            second.start();
            try{
                Thread.sleep(90);
                check(second.isAlive(),"конкурентная остановка ожидает фактическую очистку");
                check(count.get()==1,"при конкурентном выполнении остановка вызывается один раз");
            }finally{allowStop.countDown();first.join(1000);second.join(1000);}
            check(!first.isAlive()&&!second.isAlive()&&error.get()==null,"оба конкурентных запроса остановки завершились");
            check(lifecycle.state()==ExtensionLifecycle.State.STOPPED,"конкурентная остановка достигает состояния STOPPED");
        }
    }
    private static void timeoutOfHungStop()throws Exception {
        AtomicBoolean interrupted=new AtomicBoolean();
        Extension extension=new Extension(){
            public void start(ExtensionContext ctx){}
            public void stop(ExtensionContext ctx){interrupted.set(Thread.currentThread().isInterrupted());}
        };
        try(var lifecycle=new ExtensionLifecycle(extension,MANIFEST)){
            lifecycle.start(Duration.ofSeconds(1));
            lifecycle.stop(Duration.ofSeconds(1));
            check(lifecycle.state()==ExtensionLifecycle.State.STOPPED,"корректная остановка завершается");
        }
        check(!interrupted.get(),"корректная остановка не прерывает обработчик");
        Extension stuck=new Extension(){
            public void start(ExtensionContext ctx){}
            public void stop(ExtensionContext ctx){while(true){try{Thread.sleep(1000);}catch(InterruptedException ignored){}}}
        };
        try(var lifecycle=new ExtensionLifecycle(stuck,MANIFEST)){
            lifecycle.start(Duration.ofSeconds(1));
            long started=System.nanoTime();
            expect(TimeoutException.class,()->lifecycle.stop(Duration.ofMillis(90)));
            check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started)<700,"время принудительной остановки ограничено");
            check(lifecycle.state()==ExtensionLifecycle.State.FAILED,"остановка по истечении времени помечена FAILED");
        }
    }
    private static void send(com.sun.net.httpserver.HttpExchange exchange,int status,String body)throws java.io.IOException {
        byte[] payload=body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(status,payload.length);
        try(var output=exchange.getResponseBody()){output.write(payload);}
    }
    private static Map<String,String> env(int port){return Map.of(
        "LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+port,
        "LAUNCHER_EXTENSION_HOST_TOKEN","token-481",
        "LAUNCHER_EXTENSION_ID","org.stability",
        "LAUNCHER_EXTENSION_VERSION","1.0.0",
        "LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0",
        "LAUNCHER_EXTENSION_API_VERSION","1.0",
        "LAUNCHER_EXTENSION_INSTANCE_ID","instance-481");}
    private static void heartbeatAndBoundedRPC()throws Exception {
        AtomicBoolean acknowledge=new AtomicBoolean(true);
        AtomicInteger beats=new AtomicInteger();
        HttpServer fake=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        fake.createContext("/v1/",exchange->{
            try{
                if(!"Bearer token-481".equals(exchange.getRequestHeaders().getFirst("Authorization"))){send(exchange,401,"{}");return;}
                switch(exchange.getRequestURI().getPath()){
                    case "/v1/hello" -> send(exchange,200,"{\"protocolVersion\":\"1.0\",\"extensionApiVersion\":\"1.0\",\"instanceId\":\"instance-481\",\"heartbeatTimeoutSeconds\":2,\"capabilities\":[\"runtime.config.get\"]}");
                    case "/v1/heartbeat" -> {beats.incrementAndGet();send(exchange,200,acknowledge.get()?"{\"ok\":true}":"{\"ok\":false}");}
                    case "/v1/capabilities/runtime.config.get" -> send(exchange,200," ".repeat(1_048_577));
                    default -> send(exchange,404,"{}");
                }
            }catch(Exception ex){try{send(exchange,500,"{}");}catch(Exception ignored){}}
        });
        fake.start();
        try(var session=HostSession.fromEnvironment(env(fake.getAddress().getPort()),MANIFEST)){
            session.connect();
            expect(java.io.IOException.class,()->session.capability("runtime.config.get",Map.of()));
            check(session.healthy(),"слишком большой ответ отклоняется без остановки сигналов активности");
            long start=System.nanoTime();
            while(beats.get()==0&&TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start)<3500)Thread.sleep(20);
            check(beats.get()>0&&session.healthy(),"подтверждённый сигнал активности сохраняет работоспособность хоста");
            acknowledge.set(false);
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(4);
            while(session.healthy()&&System.nanoTime()<deadline)Thread.sleep(20);
            check(!session.healthy(),"200 response without ok=true revokes health");
            expect(IllegalStateException.class,()->session.capability("runtime.config.get",Map.of()));
        }finally{fake.stop(0);}
    }
    private static void realRpcDeadline()throws Exception {
        try(var host=HostSession.fromEnvironment(env(12345),MANIFEST);
            var services=new RuntimeServices(host,Set.of("slow"));
            var callbacks=new RuntimeCallbackServer("local-callback-token",services,()->"RUNNING")){
            services.commands().register("slow",null,x->x,payload->{Thread.sleep(2000);return Map.of("done",true);});
            HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
            String request=Json.encode(Map.of("protocolVersion","1.0","requestId","rpc-481","method","command.invoke","deadlineMs",70L,
                "params",Map.of("command","slow","payload",Map.of())));
            HttpRequest rpc=HttpRequest.newBuilder(URI.create(callbacks.url()+"/v1/rpc"))
                .timeout(Duration.ofSeconds(3)).header("Authorization","Bearer local-callback-token")
                .POST(HttpRequest.BodyPublishers.ofString(request)).build();
            long before=System.nanoTime();
            var timeout=client.send(rpc,HttpResponse.BodyHandlers.ofString());
            check(timeout.statusCode()==504,"удалённый вызов JVM сообщает о превышении времени ожидания заблокированного обработчика");
            check(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-before)<1000,"превышение времени ожидания удалённого вызова обнаружено в сети");
            var unauthorized=client.send(HttpRequest.newBuilder(URI.create(callbacks.url()+"/v1/rpc"))
                .timeout(Duration.ofSeconds(3)).header("Authorization","Bearer invalid")
                .POST(HttpRequest.BodyPublishers.ofString(request)).build(),HttpResponse.BodyHandlers.ofString());
            check(unauthorized.statusCode()==401,"удалённый вызов отклоняет неверный секрет обработчика");
            String health=Json.encode(Map.of("protocolVersion","1.0","requestId","health-481","method","health","deadlineMs",300L,"params",Map.of()));
            var response=client.send(HttpRequest.newBuilder(URI.create(callbacks.url()+"/v1/rpc"))
                .timeout(Duration.ofSeconds(3)).header("Authorization","Bearer local-callback-token")
                .POST(HttpRequest.BodyPublishers.ofString(health)).build(),HttpResponse.BodyHandlers.ofString());
            check(response.statusCode()==200,"работоспособность сохраняется после превышения времени ожидания команды");
            check(Boolean.TRUE.equals(Json.object(Json.parse(response.body())).get("ok")),"протокол ответа удалённого вызова не повреждён");
        }
    }
    public static void main(String[] args)throws Exception{
        concurrentStopOfHungStart();concurrentStopWaitsForCleanup();timeoutOfHungStop();heartbeatAndBoundedRPC();realRpcDeadline();
        System.out.println("PASS: "+checks+" регрессионных проверок параллелизма, сигналов работоспособности и RPC Java SDK/host 0.48.1");
    }
}

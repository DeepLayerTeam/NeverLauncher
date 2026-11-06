package ru.launcher.sdk.core;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Реальные loopback HTTP-тесты завершения вызовов, перезапуска и отклонения устаревшего жизненного цикла. */
public final class RuntimeCallbacks0490Tests {
    private static int checks;
    private static void require(boolean cond, String msg){ checks++; if(!cond)throw new AssertionError(msg); }
    private static HttpRequest request(String url,String token,String method){
        return HttpRequest.newBuilder(URI.create(url+"/v1/rpc")).timeout(Duration.ofSeconds(3))
            .header("Authorization","Bearer "+token)
            .POST(HttpRequest.BodyPublishers.ofString(Json.encode(Map.of(
                "protocolVersion","1.0","requestId","acceptance-0490","method",method,
                "deadlineMs",1200L,"params",method.equals("health")?Map.of():Map.of(
                    "surface","admin","actionId","refresh","actor",Map.of("id","operator"),"payload",Map.of()))))).build();
    }
    private static int status(HttpClient http,String url,String token,String method)throws Exception {
        return http.send(request(url,token,method),HttpResponse.BodyHandlers.ofString()).statusCode();
    }
    public static void main(String[] args)throws Exception {
        String source="{\"schemaVersion\":\"2.0\",\"id\":\"example.ga-callbacks\",\"name\":\"GA callback test\",\"publisher\":\"test\",\"version\":\"0.49.0\",\"api\":\"1.0\",\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/main.jar\"}],\"permissions\":[]}";
        ExtensionManifest manifest=ExtensionManifest.parse(source);
        var env=Map.of("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:7", "LAUNCHER_EXTENSION_HOST_TOKEN","unused",
            "LAUNCHER_EXTENSION_ID",manifest.id(),"LAUNCHER_EXTENSION_VERSION",manifest.versionText(),
            "LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0","LAUNCHER_EXTENSION_API_VERSION","1.0", "LAUNCHER_EXTENSION_INSTANCE_ID","ga");
        var http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
        var state=new AtomicReference<>("STARTING");
        var calls=new AtomicInteger();
        var interrupted=new AtomicBoolean();
        var entered=new CountDownLatch(1);
        var release=new CountDownLatch(1);
        try(var host=HostSession.fromEnvironment(env,manifest);
            var runtime=new RuntimeServices(host,Set.of(),Map.of("admin",Set.of("refresh")));
            var callback=new RuntimeCallbackServer("ga-token",runtime,state::get)) {
            runtime.ui().registerAction("admin","refresh",null,(actor,payload)->{
                entered.countDown();
                try{release.await();}catch(InterruptedException e){interrupted.set(true);throw e;}
                calls.incrementAndGet();return Map.of("ok",true);
            });
            require(status(http,callback.url(),"ga-token","ui.action.invoke")==503,"состояние STARTING не позволяет выполнять действия");
            require(calls.get()==0,"до готовности не выполнялось никаких действий");
            require(status(http,callback.url(),"ga-token","health")==200,"состояние диспетчера доступно во время запуска");
            state.set("RUNNING");
            require(status(http,callback.url(),"bad-token","ui.action.invoke")==401,"некорректный токен отклонён");
            var pool=Executors.newSingleThreadExecutor();
            try{
                var pending=pool.submit(()->{try{return status(http,callback.url(),"ga-token","ui.action.invoke");}catch(Exception e){return -1;}});
                require(entered.await(3,TimeUnit.SECONDS),"реальный обработчик запущен");
                state.set("STOPPING");
                require(status(http,callback.url(),"ga-token","ui.action.invoke")==503,"состояние STOPPING отклоняет новые задания");
                callback.close();
                release.countDown();
                pending.get(4,TimeUnit.SECONDS);
                require(interrupted.get(),"Закрытие прервало выполняемый обратный вызов");
                require(calls.get()==0,"отменённое задание не изменило состояние расширения");
            }finally{release.countDown();pool.shutdownNow();}
        }
        state.set("RUNNING");
        // Новый сервер обратных вызовов при перезапуске не должен повторно использовать
        // старые токены и обработчики.
        try(var host=HostSession.fromEnvironment(env,manifest);
            var runtime=new RuntimeServices(host,Set.of(),Map.of("admin",Set.of("refresh")));
            var restarted=new RuntimeCallbackServer("fresh-token",runtime,state::get)){
            runtime.ui().registerAction("admin","refresh",null,(actor,payload)->Map.of("ok",true));
            require(status(http,restarted.url(),"ga-token","ui.action.invoke")==401,"устаревший токен отклонён после перезапуска");
            require(status(http,restarted.url(),"fresh-token","ui.action.invoke")==200,"новый экземпляр принимает разрешённое действие");
        }
        System.out.println("PASS: "+checks+" Java 0.49.0: проверены завершение обратных вызовов, устаревший жизненный цикл, ротация токена и перезапуск");
    }
}

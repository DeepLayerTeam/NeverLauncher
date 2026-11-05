package ru.launcher.sdk.core;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicBoolean;

/** Сервер обратных вызовов/RPC только для loopback, с аутентификацией и ограничениями, работающий внутри JVM. */
public final class RuntimeCallbackServer implements AutoCloseable {
    private static final int MAX_BODY=65536;
    // EventBus сохраняет до 1 МиБ канонической JSON-нагрузки. Конверт доставки
    // добавляет метаданные и экранирование JSON, поэтому обратным вызовам нужен
    // отдельный ограниченный предел. Запросы команд и проверки здоровья RPC остаются
    // в пределах 64 КиБ.
    private static final int MAX_EVENT_BODY=2*1024*1024;
    private final HttpServer server;
    private final String token;
    private final RuntimeServices services;
    private final Supplier<String> lifecycleState;
    // Отзыв доступа и завершение JVM должны прекращать приём работы ДО закрытия ресурсов.
    private final AtomicBoolean accepting=new AtomicBoolean(true);
    private final Set<Future<?>> pending=ConcurrentHashMap.newKeySet();
    private final ThreadPoolExecutor workers=pool("neverext-rpc-http",8,16);
    private final ThreadPoolExecutor handlers=pool("neverext-rpc-handler",4,8);
    private static ThreadPoolExecutor pool(String name,int threads,int queued){
        ThreadPoolExecutor pool=new ThreadPoolExecutor(threads,threads,0L,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(queued),r->{Thread t=new Thread(r,name);t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
        pool.prestartAllCoreThreads();return pool;
    }
    public RuntimeCallbackServer(String callbackToken,RuntimeServices services)throws IOException {this(callbackToken,services,()->"RUNNING");}
    public RuntimeCallbackServer(String callbackToken,RuntimeServices services,Supplier<String> lifecycleState)throws IOException {
        if(callbackToken==null||callbackToken.isBlank())throw new IllegalArgumentException("Отсутствует токен обратного вызова");
        token=callbackToken;this.services=Objects.requireNonNull(services);this.lifecycleState=Objects.requireNonNull(lifecycleState);
        server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),16);
        server.createContext("/v1/events",e->handle(e,"events"));
        server.createContext("/v1/hooks",e->handle(e,"hooks"));
        server.createContext("/v1/commands",e->handle(e,"commands"));
        server.createContext("/v1/rpc",e->handle(e,"rpc"));
        server.setExecutor(workers);server.start();
    }
    public String url(){return "http://127.0.0.1:"+server.getAddress().getPort();}
    private void handle(HttpExchange exchange,String kind){
        try {
            if(!accepting.get()){respond(exchange,503,Map.of("error","extension shutting down"));return;}
            if(!exchange.getRemoteAddress().getAddress().isLoopbackAddress()){respond(exchange,403,Map.of("error","Требуется локальный адрес обратной петли"));return;}
            String header=exchange.getRequestHeaders().getFirst("Authorization");
            byte[] expected=("Bearer "+token).getBytes(StandardCharsets.UTF_8);
            if(header==null||!MessageDigest.isEqual(expected,header.getBytes(StandardCharsets.UTF_8))){respond(exchange,401,Map.of("error","not authorized"));return;}
            if(!exchange.getRequestMethod().equals("POST")||!exchange.getRequestURI().getPath().equals("/v1/"+kind)){respond(exchange,405,Map.of("error","not allowed"));return;}
            int bodyLimit=(kind.equals("events")||kind.equals("hooks"))?MAX_EVENT_BODY:MAX_BODY;
            byte[] body=exchange.getRequestBody().readNBytes(bodyLimit+1);
            if(body.length>bodyLimit){respond(exchange,413,Map.of("error","Размер обратного вызова превышает ограничение транспорта"));return;}
            Map<String,Object> data=Json.object(Json.parse(new String(body,StandardCharsets.UTF_8),bodyLimit));
            long millis=1800;
            if(kind.equals("rpc")){
                Object raw=data.get("deadlineMs");
                String method=Json.string(data,"method",true);
                long max=method.equals("state.migrate")?8000:1800;
                if(!(raw instanceof Long n)||n<1||n>max){respond(exchange,400,Map.of("error","Недопустимый срок ожидания RPC"));return;}
                millis=n;
                if(!"1.0".equals(data.get("protocolVersion"))){respond(exchange,409,Map.of("error","Несовпадение протокола RPC"));return;}
                String id=Json.string(data,"requestId",true);
                if(id.length()>64||!id.matches("[a-zA-Z0-9_-]+")){respond(exchange,400,Map.of("error","Недопустимый идентификатор запроса RPC"));return;}
            }
            // Обратный вызов, пришедший после STOPPING, не должен фиксировать новые
            // изменения. Проверка здоровья остаётся доступной, чтобы супервизор мог
            // диагностировать завершающийся процесс.
            String method=kind.equals("rpc")?Json.string(data,"method",true):"";
            if(!"health".equals(method) && !"RUNNING".equals(lifecycleState.get())){
                respond(exchange,503,Map.of("error","Расширение не запущено"));return;
            }
            Future<Object> future;
            try{future=handlers.submit(()->{
                if(!accepting.get() || (!"health".equals(method) && !"RUNNING".equals(lifecycleState.get())))
                    throw new IllegalStateException("extension is stopping");
                return dispatch(kind,data);
            });pending.add(future);if(!accepting.get())future.cancel(true);}
            catch(RejectedExecutionException ex){respond(exchange,503,Map.of("error","callback queue full"));return;}
            try{respond(exchange,200,future.get(millis,TimeUnit.MILLISECONDS));}
            catch(TimeoutException ex){future.cancel(true);respond(exchange,504,Map.of("error","callback deadline exceeded"));}
            catch(CancellationException ex){respond(exchange,503,Map.of("error","callback cancelled during shutdown"));}
            catch(ExecutionException ex){
                Throwable cause=ex.getCause();
                if(!accepting.get()){respond(exchange,503,Map.of("error","extension shutting down"));return;}
                if(kind.equals("events")){
                    if(cause instanceof RuntimeEvents.PermanentFailure || cause instanceof IllegalArgumentException){
                        respond(exchange,422,Map.of("code","EVENT_REJECTED","error","Событие окончательно отклонено"));
                    }else{
                        respond(exchange,503,Map.of("code","EVENT_RETRY","error","Ошибка обработчика события; повторите попытку"));
                    }
                }else if(kind.equals("hooks")){
                    respond(exchange,422,Map.of("code","HOOK_REJECTED","error","Хук политики отклонил операцию или завершился ошибкой"));
                }else respond(exchange,422,Map.of("error",cause.getClass().getSimpleName()));
            }
            catch(InterruptedException ex){Thread.currentThread().interrupt();future.cancel(true);respond(exchange,503,Map.of("error","interrupted"));}
            finally{pending.remove(future);}
        }catch(Exception e){try{respond(exchange,400,Map.of("error","Недопустимый обратный вызов"));}catch(IOException ignored){}}finally{exchange.close();}
    }
    private Object dispatch(String kind,Map<String,Object> data)throws Exception{
        if(kind.equals("commands"))return nullableResult("result",services.commands().invoke(Json.string(data,"command",true),data.get("payload")));
        if(kind.equals("events")||kind.equals("hooks")){
            services.events().deliver(data,kind.equals("hooks"));
            return kind.equals("hooks")?Map.of("ok",true):Map.of("accepted",true);
        }
        String id=Json.string(data,"requestId",true),method=Json.string(data,"method",true);
        Map<String,Object> params=Json.object(data.get("params"));
        Object result;
        switch(method){
            case "health" -> {
                if(!params.isEmpty())throw new IllegalArgumentException("health does not take parameters");
                String state=lifecycleState.get();
                result=Map.of("state",state,"responsive","RUNNING".equals(state));
            }
            case "auth.health", "auth.password", "auth.resolve", "auth.session.verify", "auth.session.revoke" -> result=services.identity().dispatch(method,params);
            case "content.health", "content.source.resolve", "content.texture.resolve", "content.delivery.resolve", "content.metadata.enrich", "content.package.prepare" -> result=services.content().dispatch(method,params);
            case "ui.action.invoke", "ui.settings.get", "ui.settings.put" -> result=services.ui().invoke(method,params);
            case "state.migrate" -> result=services.stateMigrations().apply(Json.string(params,"fromVersion",true),Json.string(params,"toVersion",true));
            case "command.invoke" -> result=nullableResult("value",services.commands().invoke(Json.string(params,"command",true),params.get("payload")));
            case "event.deliver","hook.deliver" -> {
                Map<String,Object> envelope=Json.object(params.get("envelope"));
                services.events().deliver(envelope,method.equals("hook.deliver"));
                result=Map.of("accepted",true);
            }
            default -> throw new IllegalArgumentException("unknown RPC method");
        }
        return Map.of("protocolVersion","1.0","requestId",id,"ok",true,"result",result);
    }
    // JSON null является допустимым результатом команды, в отличие от значений
    // Map.of().
    private static Map<String,Object> nullableResult(String key,Object value){
        Map<String,Object> out=new LinkedHashMap<>();out.put(key,value);return out;
    }
    private static void respond(HttpExchange exchange,int status,Object object)throws IOException {
        byte[] bytes=Json.encode(object).getBytes(StandardCharsets.UTF_8);
        if(bytes.length>MAX_BODY){status=500;bytes="{\"error\":\"response too large\"}".getBytes(StandardCharsets.UTF_8);}
        exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(status,bytes.length);try(OutputStream out=exchange.getResponseBody()){out.write(bytes);}
    }
    @Override public void close(){
        if(!accepting.compareAndSet(true,false))return;
        for(Future<?> work:pending)work.cancel(true);
        server.stop(0);workers.shutdownNow();handlers.shutdownNow();
    }
}

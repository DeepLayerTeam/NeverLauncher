package ru.neverlauncher.sdk.core;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Supplier;

/** Loopback-only, authenticated and bounded callback/RPC server, running inside the JVM. */
public final class RuntimeCallbackServer implements AutoCloseable {
    private static final int MAX_BODY=65536;
    // EventBus persists 1 MiB of canonical JSON payload. Its delivery envelope
    // adds metadata and JSON escapes, so callbacks need a separate bounded cap.
    // Command and health RPC requests remain restricted to 64 KiB.
    private static final int MAX_EVENT_BODY=2*1024*1024;
    private final HttpServer server;
    private final String token;
    private final RuntimeServices services;
    private final Supplier<String> lifecycleState;
    private final ThreadPoolExecutor workers=pool("neverext-rpc-http",8,16);
    private final ThreadPoolExecutor handlers=pool("neverext-rpc-handler",4,8);
    private static ThreadPoolExecutor pool(String name,int threads,int queued){
        ThreadPoolExecutor pool=new ThreadPoolExecutor(threads,threads,0L,TimeUnit.MILLISECONDS,new ArrayBlockingQueue<>(queued),r->{Thread t=new Thread(r,name);t.setDaemon(true);return t;},new ThreadPoolExecutor.AbortPolicy());
        pool.prestartAllCoreThreads();return pool;
    }
    public RuntimeCallbackServer(String callbackToken,RuntimeServices services)throws IOException {this(callbackToken,services,()->"RUNNING");}
    public RuntimeCallbackServer(String callbackToken,RuntimeServices services,Supplier<String> lifecycleState)throws IOException {
        if(callbackToken==null||callbackToken.isBlank())throw new IllegalArgumentException("callback token missing");
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
            if(!exchange.getRemoteAddress().getAddress().isLoopbackAddress()){respond(exchange,403,Map.of("error","loopback required"));return;}
            String header=exchange.getRequestHeaders().getFirst("Authorization");
            byte[] expected=("Bearer "+token).getBytes(StandardCharsets.UTF_8);
            if(header==null||!MessageDigest.isEqual(expected,header.getBytes(StandardCharsets.UTF_8))){respond(exchange,401,Map.of("error","not authorized"));return;}
            if(!exchange.getRequestMethod().equals("POST")||!exchange.getRequestURI().getPath().equals("/v1/"+kind)){respond(exchange,405,Map.of("error","not allowed"));return;}
            int bodyLimit=(kind.equals("events")||kind.equals("hooks"))?MAX_EVENT_BODY:MAX_BODY;
            byte[] body=exchange.getRequestBody().readNBytes(bodyLimit+1);
            if(body.length>bodyLimit){respond(exchange,413,Map.of("error","callback exceeds transport limit"));return;}
            Map<String,Object> data=Json.object(Json.parse(new String(body,StandardCharsets.UTF_8),bodyLimit));
            long millis=1800;
            if(kind.equals("rpc")){
                Object raw=data.get("deadlineMs");
                if(!(raw instanceof Long n)||n<1||n>1800){respond(exchange,400,Map.of("error","invalid RPC deadline"));return;}
                millis=n;
                if(!"1.0".equals(data.get("protocolVersion"))){respond(exchange,409,Map.of("error","RPC protocol mismatch"));return;}
                String id=Json.string(data,"requestId",true);
                if(id.length()>64||!id.matches("[a-zA-Z0-9_-]+")){respond(exchange,400,Map.of("error","invalid RPC request id"));return;}
            }
            Future<Object> future;
            try{future=handlers.submit(()->dispatch(kind,data));}
            catch(RejectedExecutionException ex){respond(exchange,503,Map.of("error","callback queue full"));return;}
            try{respond(exchange,200,future.get(millis,TimeUnit.MILLISECONDS));}
            catch(TimeoutException ex){future.cancel(true);respond(exchange,504,Map.of("error","callback deadline exceeded"));}
            catch(ExecutionException ex){Throwable cause=ex.getCause();respond(exchange,422,Map.of("error",cause.getClass().getSimpleName()));}
            catch(InterruptedException ex){Thread.currentThread().interrupt();future.cancel(true);respond(exchange,503,Map.of("error","interrupted"));}
        }catch(Exception e){try{respond(exchange,400,Map.of("error","invalid callback"));}catch(IOException ignored){}}finally{exchange.close();}
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
                result=Map.of("state",state,"responsive",true);
            }
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
    // JSON null is a valid command result, unlike Map.of() values.
    private static Map<String,Object> nullableResult(String key,Object value){
        Map<String,Object> out=new LinkedHashMap<>();out.put(key,value);return out;
    }
    private static void respond(HttpExchange exchange,int status,Object object)throws IOException {
        byte[] bytes=Json.encode(object).getBytes(StandardCharsets.UTF_8);
        if(bytes.length>MAX_BODY){status=500;bytes="{\"error\":\"response too large\"}".getBytes(StandardCharsets.UTF_8);}
        exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(status,bytes.length);try(OutputStream out=exchange.getResponseBody()){out.write(bytes);}
    }
    @Override public void close(){server.stop(0);workers.shutdownNow();handlers.shutdownNow();}
}

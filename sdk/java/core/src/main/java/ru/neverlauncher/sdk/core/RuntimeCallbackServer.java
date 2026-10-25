package ru.neverlauncher.sdk.core;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Authenticated, loopback-only callback receiver for event/hook/command execution. */
public final class RuntimeCallbackServer implements AutoCloseable {
    private final HttpServer server;
    private final String token;
    private final RuntimeServices services;
    private final ExecutorService worker=Executors.newFixedThreadPool(4,r->{Thread t=new Thread(r,"neverext-callback-http");t.setDaemon(true);return t;});
    private final ExecutorService handlers=Executors.newFixedThreadPool(4,r->{Thread t=new Thread(r,"neverext-callback-handler");t.setDaemon(true);return t;});
    public RuntimeCallbackServer(String callbackToken,RuntimeServices services)throws IOException {
        if(callbackToken==null||callbackToken.isBlank())throw new IllegalArgumentException("callback token missing");
        token=callbackToken;this.services=Objects.requireNonNull(services);
        server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),16);
        server.createContext("/v1/events",e->handle(e,"events"));
        server.createContext("/v1/hooks",e->handle(e,"hooks"));
        server.createContext("/v1/commands",e->handle(e,"commands"));
        server.setExecutor(worker);server.start();
    }
    public String url(){return "http://127.0.0.1:"+server.getAddress().getPort();}
    private void handle(HttpExchange exchange,String kind){
        try {
            if(!exchange.getRemoteAddress().getAddress().isLoopbackAddress()){respond(exchange,403,Map.of("error","loopback required"));return;}
            String header=exchange.getRequestHeaders().getFirst("Authorization");
            byte[] expected=("Bearer "+token).getBytes(StandardCharsets.UTF_8);
            if(header==null||!MessageDigest.isEqual(expected,header.getBytes(StandardCharsets.UTF_8))){respond(exchange,401,Map.of("error","not authorized"));return;}
            if(!exchange.getRequestMethod().equals("POST")||!exchange.getRequestURI().getPath().equals("/v1/"+kind)){respond(exchange,405,Map.of("error","not allowed"));return;}
            byte[] body=exchange.getRequestBody().readNBytes(65537);
            if(body.length>65536){respond(exchange,413,Map.of("error","callback exceeds 64 KiB"));return;}
            Map<String,Object> data=Json.object(Json.parse(new String(body,StandardCharsets.UTF_8)));
            Future<Object> future=handlers.submit(()->{
                try {
                    if(kind.equals("commands"))return Map.of("result",services.commands().invoke(Json.string(data,"command",true),data.get("payload")));
                    services.events().deliver(data,kind.equals("hooks"));
                    return kind.equals("hooks")?Map.of("ok",true):Map.of("accepted",true);
                }catch(Exception e){throw new CompletionException(e);}
            });
            try{respond(exchange,200,future.get(1800,TimeUnit.MILLISECONDS));}
            catch(TimeoutException ex){future.cancel(true);respond(exchange,504,Map.of("error","callback deadline exceeded"));}
            catch(ExecutionException ex){Throwable cause=ex.getCause();if(cause instanceof CompletionException&&cause.getCause()!=null)cause=cause.getCause();respond(exchange,422,Map.of("error",cause.getClass().getSimpleName()));}
            catch(InterruptedException ex){Thread.currentThread().interrupt();future.cancel(true);respond(exchange,503,Map.of("error","interrupted"));}
        }catch(Exception e){try{respond(exchange,400,Map.of("error","invalid callback"));}catch(IOException ignored){}}finally{exchange.close();}
    }
    private static void respond(HttpExchange exchange,int status,Object object)throws IOException {
        byte[] bytes=Json.encode(object).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type","application/json");
        exchange.sendResponseHeaders(status,bytes.length);try(OutputStream out=exchange.getResponseBody()){out.write(bytes);}
    }
    @Override public void close(){server.stop(0);worker.shutdownNow();handlers.shutdownNow();}
}

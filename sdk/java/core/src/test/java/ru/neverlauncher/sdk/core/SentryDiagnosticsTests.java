package ru.launcher.sdk.core;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

public final class SentryDiagnosticsTests {
  public static void main(String[] args) throws Exception {
    BlockingQueue<String> received=new ArrayBlockingQueue<>(2);
    HttpServer server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),4);
    server.createContext("/api/42/envelope/",exchange->{received.offer(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));exchange.sendResponseHeaders(200,-1);exchange.close();});
    server.start();
    try {
      String dsn="http://publickey@127.0.0.1:"+server.getAddress().getPort()+"/42";
      RuntimeException e=new RuntimeException("Bearer abc123 user@example.com /home/john/password");
      SentryDiagnostics.report(e,Map.of("NEVERLAUNCHER_SENTRY_JVM_ENABLED","true","NEVERLAUNCHER_SENTRY_JVM_DSN",dsn,"NEVERLAUNCHER_SENTRY_RELEASE","launcher@0.30.9"));
      String text=received.poll(5,TimeUnit.SECONDS);if(text==null)throw new AssertionError("no Sentry envelope");
      for(String secret:List.of("abc123","user@example.com","/home/john"))if(text.contains(secret))throw new AssertionError("privacy leak "+secret);
      if(!text.contains("launcher@0.30.9")||!text.contains("RuntimeException"))throw new AssertionError("incomplete event");
      Thread.UncaughtExceptionHandler old=Thread.getDefaultUncaughtExceptionHandler();
      try {
        SentryDiagnostics.installFromEnvironment(Map.of("NEVERLAUNCHER_SENTRY_JVM_ENABLED","true", "NEVERLAUNCHER_SENTRY_JVM_DSN",dsn));
        Thread worker=new Thread(()->{throw new IllegalStateException("do-not-upload-secret-value");},"diag-fixture");
        worker.start();worker.join();
        String real=received.poll(5,TimeUnit.SECONDS);
        if(real==null || !real.contains("IllegalStateException") || real.contains("do-not-upload-secret-value"))throw new AssertionError("uncaught handler did not send safe event");
      } finally {Thread.setDefaultUncaughtExceptionHandler(old);}
      SentryDiagnostics.report(e,Map.of("NEVERLAUNCHER_SENTRY_JVM_DSN",dsn));
      if(received.poll(100,TimeUnit.MILLISECONDS)!=null)throw new AssertionError("opt-out ignored");
      try{SentryDiagnostics.installFromEnvironment(Map.of("NEVERLAUNCHER_SENTRY_JVM_ENABLED","true","NEVERLAUNCHER_SENTRY_JVM_DSN","http://abc@example.com/42"));throw new AssertionError("insecure DSN accepted");}catch(IllegalArgumentException expected){}
      System.out.println("Sentry JVM HTTP transport, redaction and opt-out passed");
    }finally{server.stop(0);}
  }
}

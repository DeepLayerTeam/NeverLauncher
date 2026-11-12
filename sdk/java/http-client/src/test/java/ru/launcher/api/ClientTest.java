package ru.launcher.api;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.http.HttpRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public final class ClientTest {
 public static void main(String[]args)throws Exception {
  var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
  server.createContext("/", e->{
   String text;int status=200;
   if(e.getRequestURI().getRawPath().equals("/api/v1/stream")) {
    if(!"Bearer token".equals(e.getRequestHeaders().getFirst("Authorization")))throw new AssertionError("bearer");
    e.getResponseHeaders().set("Content-Type", "application/octet-stream");
    e.sendResponseHeaders(200, 0);
    try(var out=e.getResponseBody()) { byte[] block=new byte[65536]; Arrays.fill(block,(byte)0xAC);
     for(int i=0;i<192;i++)out.write(block); } // 12 MiB (chunked)
    return;
   } else if(e.getRequestURI().getRawPath().equals("/api/v1/redirect")) {
    e.getResponseHeaders().set("Location", "http://127.0.0.1:1/api/v1/leak");
    e.sendResponseHeaders(307,-1);e.close();return;
   } else if(e.getRequestURI().getRawPath().equals("/api/v1/fallback-error")) {
    e.getResponseHeaders().set("X-Correlation-ID","fallback-1");
    e.sendResponseHeaders(503,-1);e.close();return;
   } else if(e.getRequestURI().getRawPath().equals("/api/v1/stream-error")) {
    byte[] b="{\"code\":\"denied\",\"message\":\"no access\"}".getBytes(StandardCharsets.UTF_8);
    e.getResponseHeaders().set("X-Correlation-ID","stream-req-1");
    e.sendResponseHeaders(403,b.length);try(var out=e.getResponseBody()){out.write(b);}return;
   } else if(e.getRequestURI().getRawPath().equals("/ready")){text="{\"version\":\"0.45.11\"}";}
   else if(e.getRequestURI().getRawPath().equals("/api/v1/projects/a%20b")){
    if(!"Bearer token".equals(e.getRequestHeaders().getFirst("Authorization")))throw new AssertionError("отсутствует токен предъявителя");
    text="{\"id\":\"a b\"}";
   } else {status=403;text="{\"code\":\"denied\",\"message\":\"forbidden\"}";e.getResponseHeaders().set("X-Correlation-ID","id-1");}
   byte[] b=text.getBytes(StandardCharsets.UTF_8);e.sendResponseHeaders(status,b.length);try(var out=e.getResponseBody()){out.write(b);}
  });
  server.start();
  try{
   var c=new LauncherAPI("http://127.0.0.1:"+server.getAddress().getPort(),"token");c.checkCompatibility();
   var obj=(Map<?,?>)c.call("get_projects_by_projectId",Map.of("projectId","a b"),Map.of(),null,"");
   if(!"a b".equals(obj.get("id")))throw new AssertionError(obj);
   try {c.call("get_projects",Map.of(),Map.of(),null,"");throw new AssertionError("отсутствует ошибка");}
   catch(LauncherAPI.ApiException e){if(e.status!=403||!e.code.equals("denied")||!e.requestId.equals("id-1"))throw e;}
   try {new LauncherAPI("http://example.com","");throw new AssertionError("небезопасный адрес ошибочно разрешён");}
   catch(IllegalArgumentException expected){}
   var streamed=new ByteArrayOutputStream();
   long n=c.requestStream("GET","/api/v1/stream",Map.of(),null,null,streamed,20L<<20,"");
   if(n != 12L<<20 || streamed.size()!=n || streamed.toByteArray()[0]!=(byte)0xAC)throw new AssertionError("несоответствие размера потоковых данных (12 МиБ)");
   try {c.requestStream("GET","/api/v1/stream",Map.of(),null,null,new ByteArrayOutputStream(),1<<20,"");
    throw new AssertionError("обход ограничения потока");} catch(IOException expected) {if(!expected.getMessage().contains("лимит размера"))throw expected;}
   try {c.requestStream("GET","/api/v1/redirect",Map.of(),null,null,new ByteArrayOutputStream(),1024,"");
    throw new AssertionError("выполнен запрещённый переход");}catch(LauncherAPI.ApiException expected){if(expected.status!=307)throw expected;}
   try {c.requestStream("GET","/api/v1/fallback-error",Map.of(),null,null,new ByteArrayOutputStream(),1024,"");
    throw new AssertionError("Отсутствует ошибка HTTP");}catch(LauncherAPI.ApiException expected){
     if(expected.status!=503 || !expected.requestId.equals("fallback-1") || !expected.getMessage().equals("HTTP 503: Сервис временно недоступен"))throw expected;}
   try {c.requestStream("GET","/api/v1/stream-error",Map.of(),null,null,new ByteArrayOutputStream(),1024,"");
    throw new AssertionError("ошибка проигнорирована");}catch(LauncherAPI.ApiException expected){
     if(expected.status!=403 || !expected.code.equals("denied") || !expected.requestId.equals("stream-req-1"))throw expected;}
   try {c.requestStream("GET","/api/v1/stream",Map.of(),null,null,new ByteArrayOutputStream(),-1,"");
    throw new AssertionError("отрицательный предел ошибочно принят");}catch(IllegalArgumentException expected){}
   if(Operations.ALL.size()<450)throw new AssertionError("реестр операций неполон");
   System.out.println("Тесты HTTP для Java REST SDK пройдены: "+Operations.ALL.size()+" операций");
  } finally {server.stop(0);}
  System.exit(0);
 }
}

package ru.neverlauncher.api;
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
   } else if(e.getRequestURI().getRawPath().equals("/api/v1/stream-error")) {
    byte[] b="{\"code\":\"denied\",\"message\":\"no access\"}".getBytes(StandardCharsets.UTF_8);
    e.getResponseHeaders().set("X-Correlation-ID","stream-req-1");
    e.sendResponseHeaders(403,b.length);try(var out=e.getResponseBody()){out.write(b);}return;
   } else if(e.getRequestURI().getRawPath().equals("/ready")){text="{\"version\":\"0.45.11\"}";}
   else if(e.getRequestURI().getRawPath().equals("/api/v1/projects/a%20b")){
    if(!"Bearer token".equals(e.getRequestHeaders().getFirst("Authorization")))throw new AssertionError("missing bearer");
    text="{\"id\":\"a b\"}";
   } else {status=403;text="{\"code\":\"denied\",\"message\":\"forbidden\"}";e.getResponseHeaders().set("X-Correlation-ID","id-1");}
   byte[] b=text.getBytes(StandardCharsets.UTF_8);e.sendResponseHeaders(status,b.length);try(var out=e.getResponseBody()){out.write(b);}
  });
  server.start();
  try{
   var c=new NeverLauncherAPI("http://127.0.0.1:"+server.getAddress().getPort(),"token");c.checkCompatibility();
   var obj=(Map<?,?>)c.call("get_projects_by_projectId",Map.of("projectId","a b"),Map.of(),null,"");
   if(!"a b".equals(obj.get("id")))throw new AssertionError(obj);
   try {c.call("get_projects",Map.of(),Map.of(),null,"");throw new AssertionError("missing error");}
   catch(NeverLauncherAPI.ApiException e){if(e.status!=403||!e.code.equals("denied")||!e.requestId.equals("id-1"))throw e;}
   try {new NeverLauncherAPI("http://example.com","");throw new AssertionError("insecure URL allowed");}
   catch(IllegalArgumentException expected){}
   var streamed=new ByteArrayOutputStream();
   long n=c.requestStream("GET","/api/v1/stream",Map.of(),null,null,streamed,20L<<20,"");
   if(n != 12L<<20 || streamed.size()!=n || streamed.toByteArray()[0]!=(byte)0xAC)throw new AssertionError("12 MiB streamed bytes mismatch");
   try {c.requestStream("GET","/api/v1/stream",Map.of(),null,null,new ByteArrayOutputStream(),1<<20,"");
    throw new AssertionError("stream limit bypass");} catch(IOException expected) {if(!expected.getMessage().contains("лимит размера"))throw expected;}
   try {c.requestStream("GET","/api/v1/redirect",Map.of(),null,null,new ByteArrayOutputStream(),1024,"");
    throw new AssertionError("redirect followed");}catch(NeverLauncherAPI.ApiException expected){if(expected.status!=307)throw expected;}
   try {c.requestStream("GET","/api/v1/stream-error",Map.of(),null,null,new ByteArrayOutputStream(),1024,"");
    throw new AssertionError("error ignored");}catch(NeverLauncherAPI.ApiException expected){
     if(expected.status!=403 || !expected.code.equals("denied") || !expected.requestId.equals("stream-req-1"))throw expected;}
   try {c.requestStream("GET","/api/v1/stream",Map.of(),null,null,new ByteArrayOutputStream(),-1,"");
    throw new AssertionError("negative limit accepted");}catch(IllegalArgumentException expected){}
   if(Operations.ALL.size()<450)throw new AssertionError("operation registry incomplete");
   System.out.println("Java REST SDK HTTP tests PASS: "+Operations.ALL.size()+" operations");
  } finally {server.stop(0);}
  System.exit(0);
 }
}

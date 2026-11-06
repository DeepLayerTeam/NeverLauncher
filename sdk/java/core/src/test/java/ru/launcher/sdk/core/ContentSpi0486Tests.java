package ru.launcher.sdk.core;

import com.sun.net.httpserver.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.*;

/** Реальный зарегистрированный провайдер, аутентифицированный JVM RPC и HTTP-хранилище Host с проверкой разрешений. */
public final class ContentSpi0486Tests {
    private static int checks;
    private static void ok(boolean v,String m){checks++;if(!v)throw new AssertionError(m);}
    private interface Op{void run()throws Exception;}
    private static void reject(Class<? extends Throwable> expected,Op op)throws Exception{
        checks++;
        try{op.run();throw new AssertionError("expected "+expected.getSimpleName());}
        catch(Throwable e){if(!expected.isInstance(e))throw new AssertionError("неверная ошибка",e);}
    }
    private static final byte[] DATA="verified-content-from-storage".getBytes(StandardCharsets.UTF_8);
    private static final String HASH=ContentServices.sha(DATA);
    private static final AtomicBoolean REVOKED=new AtomicBoolean(), CORRUPTED=new AtomicBoolean(), MALICIOUS=new AtomicBoolean();
    private static final AtomicInteger STARTED=new AtomicInteger(),STOPPED=new AtomicInteger();
    private static ContentServices.Asset asset(String project,String location){return new ContentServices.Asset(project,location,"storage".equals(location)?"release-1":"", "storage".equals(location)?"data/file.bin":"https://files.example.org/f.bin", HASH, DATA.length);}
    private static class Impl implements ContentProvider {
        public void start(ProviderContext c){STARTED.incrementAndGet();}
        public void stop(ProviderContext c){STOPPED.incrementAndGet();}
        public ContentServices.Asset source(String id,String path){return asset("p1","storage");}
        public ContentServices.Asset texture(String id,String profile,String kind){return asset("p1","storage");}
        public Map<String,Object> metadata(String id,String release,Map<String,Object> original){
            var result=new LinkedHashMap<>(original);
            if(MALICIOUS.get()){
                @SuppressWarnings("unchecked") var inner=(Map<String,Object>)result.get("signature");
                inner.put("algorithm","forged");
            }
            result.put("x-content-label","sample-rendering-metadata");return result;
        }
        public byte[] preparePackage(String id,String name,byte[] input){
            return (new String(input,StandardCharsets.UTF_8)+"-processed").getBytes(StandardCharsets.UTF_8);
        }
        public ContentServices.Asset delivery(String id,String path){return asset("p1","https");}
    }
    private static void send(HttpExchange x,int status,Object payload)throws java.io.IOException{
        byte[] bytes=Json.encode(payload).getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type","application/json");
        x.sendResponseHeaders(status,bytes.length);
        try(var out=x.getResponseBody()){out.write(bytes);}
    }
    private static Map<String,Object> rpc(HttpClient client,RuntimeCallbackServer cb,String key,String method,Map<String,Object> params)throws Exception {
        var msg=Map.of("protocolVersion","1.0","requestId","content1","method",method,"deadlineMs",1200,"params",params);
        var req=HttpRequest.newBuilder(URI.create(cb.url()+"/v1/rpc"))
            .header("Authorization","Bearer "+key).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(Json.encode(msg))).timeout(Duration.ofSeconds(2)).build();
        var resp=client.send(req,HttpResponse.BodyHandlers.ofString());
        ok(resp.statusCode()==(key.equals("callback-token")?200:401),"authenticated Java callback HTTP status");
        return Json.object(Json.parse(resp.body()));
    }
    public static void main(String[] args)throws Exception {
        reject(IllegalArgumentException.class,()->new ContentServices.Asset("project","file","x","foo",HASH,2));
        reject(IllegalArgumentException.class,()->new ContentServices.Asset("p1","storage","v1","../outside",HASH,2));
        reject(IllegalArgumentException.class,()->new ContentServices.Asset("p1","storage","v1","a/./b",HASH,2));
        reject(IllegalArgumentException.class,()->new ContentServices.Asset("p1","https","","http://localhost/",HASH,2));
        reject(IllegalArgumentException.class,()->new ContentServices.Asset("p1","storage","v1","data.bin","bad",2));
        reject(IllegalArgumentException.class,()->new ContentServices.Asset("p1","storage","v1","data.bin",HASH,600000));
        HttpServer broker=HttpServer.create(new InetSocketAddress("127.0.0.1",0),16);
        broker.createContext("/v1/",x->{
            try {
                if(!"Bearer broker-token".equals(x.getRequestHeaders().getFirst("Authorization"))) {send(x,401,Map.of());return;}
                var route=x.getRequestURI().getPath();
                if(route.equals("/v1/hello")){send(x,200,Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId","content-run","heartbeatTimeoutSeconds",300,"capabilities",List.of("storage.read","http.fetch")));return;}
                if(route.equals("/v1/heartbeat")){send(x,200,Map.of("ok",true));return;}
                if(REVOKED.get()){send(x,403,Map.of("error","revoked"));return;}
                var request=Json.object(Json.parse(new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8)));
                if(!"p1".equals(request.get("projectId"))){send(x,403,Map.of("error","scope"));return;}
                byte[] bytes=CORRUPTED.get()?"corrupted".getBytes(StandardCharsets.UTF_8):DATA;
                if(route.equals("/v1/capabilities/storage.read"))send(x,200,Map.of("size",bytes.length,"contentBase64",Base64.getEncoder().encodeToString(bytes)));
                else if(route.equals("/v1/capabilities/http.fetch"))send(x,200,Map.of("status",200,"bodyBase64",Base64.getEncoder().encodeToString(bytes)));
                else send(x,404,Map.of("error","no capability"));
            }catch(Exception e){send(x,500,Map.of("error","broker error"));}
        });
        broker.start();
        try {
            var manifest=ExtensionManifest.parse("{\"schemaVersion\":\"2.0\",\"id\":\"org.content\",\"name\":\"Content\",\"publisher\":\"test\",\"version\":\"0.48.6\",\"api\":\"1.0\",\"permissions\":[\"release:read\",\"storage:read\",\"http:outbound\"],\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/main.jar\"}]}");
            var env=Map.of("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:"+broker.getAddress().getPort(),"LAUNCHER_EXTENSION_ID",manifest.id(),"LAUNCHER_EXTENSION_VERSION",manifest.versionText(),"LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0","LAUNCHER_EXTENSION_API_VERSION","1.0","LAUNCHER_EXTENSION_HOST_TOKEN","broker-token","LAUNCHER_EXTENSION_INSTANCE_ID","content-run");
            try(var host=HostSession.fromEnvironment(env,manifest);var services=new RuntimeServices(host,Set.of())){
                host.connect();
                var extension=new Extension(){
                    public void start(ExtensionContext ctx)throws Exception{
                        ctx.providers().register(new ProviderDescriptor<>(ContentServices.CONTRACT,"files",SemVer.parse("1.0.0"),"^1.0.0","^1.0.0",Impl::new));
                        ctx.providers().select(ContentServices.CONTRACT.id(),"files",Duration.ofSeconds(1));
                    }
                    public void stop(ExtensionContext ctx){}
                };
                try(var lifecycle=new ExtensionLifecycle(extension,manifest,services);
                    var callback=new RuntimeCallbackServer("callback-token",services,()->lifecycle.state().name())) {
                    lifecycle.start(Duration.ofSeconds(2));
                    ok(STARTED.get()==1,"provider starts in real JVM lifecycle");
                    var content=services.content();
                    var source=content.source("p1","file.bin");
                    ok(source.sha256().equals(HASH),"source pins digest");
                    ok(Arrays.equals(content.readChecked(source),DATA),"real authenticated host storage read verified");
                    ok(Arrays.equals(content.readChecked(content.delivery("p1","file.bin")),DATA),"HTTPS delivery uses Host fetch and checksum");
                    ok(Arrays.equals(content.readChecked(content.texture("p1","profile-a","skin")),DATA),"texture source through verified host storage");
                    reject(IllegalArgumentException.class,()->content.texture("p1","profile-a","model"));
                    var signed=Map.<String,Object>of("projectId","p1","version","1.0.0","signature",Map.of("algorithm","Ed25519"),"files",List.of(Map.of("sha256",HASH)));
                    ok(content.metadata("p1","rel1",signed).get("x-content-label").equals("sample-rendering-metadata"),"metadata enrichment preserves signed content");
                    MALICIOUS.set(true);
                    reject(SecurityException.class,()->content.metadata("p1","rel1",signed));
                    MALICIOUS.set(false);
                    ok(Json.object(signed.get("signature")).get("algorithm").equals("Ed25519"),"provider could not mutate original nested signature");
                    var prepared=content.preparePackage("p1","mod.jar","jar-bytes".getBytes(StandardCharsets.UTF_8));
                    ok(prepared.requiresSigning()&&prepared.sha256().equals(ContentServices.sha(prepared.bytes())),"package processed as unsigned prepublication bytes");
                    ok(new String(prepared.bytes(),StandardCharsets.UTF_8).equals("jar-bytes-processed"),"real package transformer bytes");
                    var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
                    var health=rpc(client,callback,"callback-token","content.health",Map.of());
                    ok(Boolean.TRUE.equals(Json.object(health.get("result")).get("available")),"real JVM RPC selected SPI provider");
                    var remote=rpc(client,callback,"callback-token","content.source.resolve",Map.of("projectId","p1","path","mod.jar"));
                    ok(Json.object(Json.object(remote.get("result")).get("asset")).get("sha256").equals(HASH),"real JVM RPC source resolution");
                    var skin=rpc(client,callback,"callback-token","content.texture.resolve",Map.of("projectId","p1","profileId","profile-a","kind","skin"));
                    ok(Json.object(skin.get("result")).containsKey("asset"),"real JVM RPC texture");
                    var meta=rpc(client,callback,"callback-token","content.metadata.enrich",Map.of("projectId","p1","releaseId","rel1","metadata",signed));
                    ok(Json.object(meta.get("result")).containsKey("metadata"),"real JVM RPC metadata");
                    var pkg=rpc(client,callback,"callback-token","content.package.prepare",Map.of("projectId","p1","name","mod.jar","dataBase64",Base64.getEncoder().encodeToString("small".getBytes(StandardCharsets.UTF_8))));
                    ok(Boolean.TRUE.equals(Json.object(pkg.get("result")).get("requiresSigning")),"RPC transform never impersonates a signed package");
                    var wrong=rpc(client,callback,"callback-token","content.delivery.resolve",Map.of("projectId","p2","path","test.bin"));
                    ok(Json.object(wrong.get("result")).get("errorCode").equals("content_unavailable") || Json.object(wrong.get("result")).get("errorCode").equals("content_denied"),"invalid project is rejected");
                    rpc(client,callback,"bad-secret","content.source.resolve",Map.of("projectId","p1","path","test.bin"));
                    CORRUPTED.set(true);
                    reject(SecurityException.class,()->content.readChecked(source));
                    CORRUPTED.set(false);
                    REVOKED.set(true);
                    reject(HostSession.HostError.class,()->content.readChecked(source));
                    REVOKED.set(false);
                    lifecycle.stop(Duration.ofSeconds(2));
                    ok(STOPPED.get()==1,"content provider graceful shutdown");
                    reject(IllegalStateException.class,()->content.source("p1","abc"));
                }
            }
        } finally {broker.stop(0);}
        System.out.println("PASS: "+checks+" content SPI, real broker IO, RPC, integrity, permissions and lifecycle checks");
    }
}

package ru.neverlauncher.sdk.core;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Authenticated local NeverExtensions Host Protocol 1.0 hello and heartbeat client. */
public final class HostSession implements AutoCloseable {
    private final HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).proxy(new ProxySelector(){public List<Proxy> select(URI u){return List.of(Proxy.NO_PROXY);}public void connectFailed(URI u,SocketAddress a,IOException e){}}).build();
    private final URI origin;private final String token,extensionId,instanceId;
    private final ScheduledExecutorService timer=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"neverext-heartbeat");t.setDaemon(true);return t;});
    private final AtomicBoolean closed=new AtomicBoolean();
    private volatile boolean healthy=true;
    private volatile Set<String> capabilities=Set.of();
    private HostSession(URI origin,String token,String extensionId,String instanceId){this.origin=origin;this.token=token;this.extensionId=extensionId;this.instanceId=instanceId;}
    /** Read the exact active manifest from the authenticated Go supervisor, not package payload copies. */
    public static String fetchManifestFromEnvironment(Map<String,String> env)throws IOException,InterruptedException {
        String raw=required(env,"NEVERLAUNCHER_EXTENSION_HOST_URL");
        URI origin=validateOrigin(raw);
        if(!"1.0".equals(required(env,"NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL")) ||
           !"1.0".equals(required(env,"NEVERLAUNCHER_EXTENSION_API_VERSION")))throw new IllegalArgumentException("Java host protocol/API incompatible");
        try(HostSession bootstrap=new HostSession(origin,required(env,"NEVERLAUNCHER_EXTENSION_HOST_TOKEN"),
            required(env,"NEVERLAUNCHER_EXTENSION_ID"),required(env,"NEVERLAUNCHER_EXTENSION_INSTANCE_ID"))){
            return Json.encode(bootstrap.send("GET","/v1/manifest",null,200));
        }
    }
    private static URI validateOrigin(String raw){
        URI url;
        try{url=URI.create(raw);}catch(IllegalArgumentException e){throw new IllegalArgumentException("invalid local host URL",e);}
        String host=url.getHost();if(!"http".equals(url.getScheme())||host==null||(!host.equals("127.0.0.1")&&!host.equals("::1"))||url.getPort()<1||url.getRawUserInfo()!=null||url.getRawQuery()!=null||url.getRawFragment()!=null||!(url.getPath().isEmpty()||url.getPath().equals("/")))throw new IllegalArgumentException("host URL must be a loopback HTTP origin");
        return url;
    }
    public static HostSession fromEnvironment(Map<String,String> env,ExtensionManifest manifest) {
        URI url=validateOrigin(required(env,"NEVERLAUNCHER_EXTENSION_HOST_URL"));
        String id=required(env,"NEVERLAUNCHER_EXTENSION_ID");
        if(!id.equals(manifest.id())||!required(env,"NEVERLAUNCHER_EXTENSION_VERSION").equals(manifest.versionText()))throw new IllegalArgumentException("host identity differs from manifest");
        if(!required(env,"NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL").equals("1.0")||!required(env,"NEVERLAUNCHER_EXTENSION_API_VERSION").equals("1.0"))throw new IllegalArgumentException("host protocol/API incompatible");
        return new HostSession(url,required(env,"NEVERLAUNCHER_EXTENSION_HOST_TOKEN"),id,required(env,"NEVERLAUNCHER_EXTENSION_INSTANCE_ID"));
    }
    private static String required(Map<String,String> env,String key){String v=env.get(key);if(v==null||v.isBlank())throw new IllegalArgumentException("missing "+key);return v;}
    public synchronized void connect() throws IOException,InterruptedException {connect("");}
    public synchronized void connect(String callbackUrl) throws IOException,InterruptedException {
        if(closed.get())throw new IllegalStateException("session closed");
        Map<String,Object> hello=new LinkedHashMap<>(Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId",instanceId,"extensionId",extensionId,"pid",ProcessHandle.current().pid()));
        if(!callbackUrl.isBlank())hello.put("callbackUrl",callbackUrl);
        Map<String,Object> response=post("/v1/hello",hello);
        if(!"1.0".equals(response.get("protocolVersion"))||!"1.0".equals(response.get("extensionApiVersion"))||!instanceId.equals(response.get("instanceId")))throw new IOException("host hello protocol/identity mismatch");
        Object caps=response.get("capabilities");if(caps instanceof List<?> list){Set<String> parsed=new HashSet<>();for(Object item:list){if(!(item instanceof String value))throw new IOException("invalid capabilities list");parsed.add(value);}capabilities=Set.copyOf(parsed);}
        Object hb=response.get("heartbeatTimeoutSeconds");if(!(hb instanceof Number n)||n.longValue()<2||n.longValue()>3600)throw new IOException("invalid heartbeat interval");
        long period=Math.max(1,n.longValue()/3);
        timer.scheduleWithFixedDelay(()->{try{post("/v1/heartbeat",Map.of());}catch(Exception e){healthy=false;close();}},period,period,TimeUnit.SECONDS);
    }
    /** A Java target is only marked running after Extension.start() completed. */
    public void ready() throws IOException,InterruptedException {
        Map<String,Object> answer=post("/v1/ready",Map.of("protocolVersion","1.0","instanceId",instanceId));
        if(!Boolean.TRUE.equals(answer.get("ready")))throw new IOException("host did not acknowledge Java readiness");
    }
    public boolean healthy(){return healthy&&!closed.get();}
    public Set<String> capabilities(){return capabilities;}
    public Map<String,Object> capability(String name,Map<String,Object> payload) throws IOException,InterruptedException {
        if(!name.matches("[a-z][a-z0-9.]{1,96}"))throw new IllegalArgumentException("invalid capability name");
        return post("/v1/capabilities/"+name,payload);
    }
    public Map<String,Object> subscribe(String type,String mode) throws IOException,InterruptedException {return postExpect("/v1/events/subscriptions",Map.of("eventType",type,"mode",mode),201);}
    public void unsubscribe(long id) throws IOException,InterruptedException {send("DELETE","/v1/events/subscriptions/"+id,null,204);}
    private Map<String,Object> post(String path,Object payload) throws IOException,InterruptedException {return postExpect(path,payload,200);}
    private Map<String,Object> postExpect(String path,Object payload,int status) throws IOException,InterruptedException {return send("POST",path,payload,status);}
    private Map<String,Object> send(String method,String path,Object payload,int status) throws IOException,InterruptedException {
        String body=payload==null?"":Json.encode(payload);
        HttpRequest.Builder builder=HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(3)).header("Authorization","Bearer "+token).header("Content-Type","application/json");
        HttpRequest request=builder.method(method,payload==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body,StandardCharsets.UTF_8)).build();
        HttpResponse<String> response=http.send(request,HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if(response.statusCode()!=status)throw new HostError(response.statusCode(),"host request "+path+" failed with HTTP "+response.statusCode());
        if(response.body().length()>1_048_576)throw new IOException("oversized host response");
        if(response.body().isEmpty())return Map.of();
        return Json.object(Json.parse(response.body()));
    }
    public static final class HostError extends IOException {
        private final int status;public HostError(int status,String message){super(message);this.status=status;}public int status(){return status;}
    }
    @Override public void close(){if(closed.compareAndSet(false,true))timer.shutdownNow();}
}

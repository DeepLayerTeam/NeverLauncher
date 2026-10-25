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
    private HostSession(URI origin,String token,String extensionId,String instanceId){this.origin=origin;this.token=token;this.extensionId=extensionId;this.instanceId=instanceId;}
    public static HostSession fromEnvironment(Map<String,String> env,ExtensionManifest manifest) {
        String raw=required(env,"NEVERLAUNCHER_EXTENSION_HOST_URL");URI url;
        try{url=URI.create(raw);}catch(IllegalArgumentException e){throw new IllegalArgumentException("invalid local host URL",e);}
        String host=url.getHost();if(!"http".equals(url.getScheme())||host==null||(!host.equals("127.0.0.1")&&!host.equals("::1"))||url.getPort()<1||url.getRawUserInfo()!=null||url.getRawQuery()!=null||url.getRawFragment()!=null||!(url.getPath().isEmpty()||url.getPath().equals("/")))throw new IllegalArgumentException("host URL must be a loopback HTTP origin");
        String id=required(env,"NEVERLAUNCHER_EXTENSION_ID");
        if(!id.equals(manifest.id())||!required(env,"NEVERLAUNCHER_EXTENSION_VERSION").equals(manifest.versionText()))throw new IllegalArgumentException("host identity differs from manifest");
        if(!required(env,"NEVERLAUNCHER_EXTENSION_HOST_PROTOCOL").equals("1.0")||!required(env,"NEVERLAUNCHER_EXTENSION_API_VERSION").equals("1.0"))throw new IllegalArgumentException("host protocol/API incompatible");
        return new HostSession(url,required(env,"NEVERLAUNCHER_EXTENSION_HOST_TOKEN"),id,required(env,"NEVERLAUNCHER_EXTENSION_INSTANCE_ID"));
    }
    private static String required(Map<String,String> env,String key){String v=env.get(key);if(v==null||v.isBlank())throw new IllegalArgumentException("missing "+key);return v;}
    public synchronized void connect() throws IOException,InterruptedException {
        if(closed.get())throw new IllegalStateException("session closed");
        Map<String,Object> hello=Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId",instanceId,"extensionId",extensionId,"pid",ProcessHandle.current().pid());
        Map<String,Object> response=post("/v1/hello",hello);
        if(!"1.0".equals(response.get("protocolVersion"))||!"1.0".equals(response.get("extensionApiVersion"))||!instanceId.equals(response.get("instanceId")))throw new IOException("host hello protocol/identity mismatch");
        Object hb=response.get("heartbeatTimeoutSeconds");if(!(hb instanceof Number n)||n.longValue()<2||n.longValue()>3600)throw new IOException("invalid heartbeat interval");
        long period=Math.max(1,n.longValue()/3);
        timer.scheduleWithFixedDelay(()->{try{post("/v1/heartbeat",Map.of());}catch(Exception e){healthy=false;close();}},period,period,TimeUnit.SECONDS);
    }
    public boolean healthy(){return healthy&&!closed.get();}
    private Map<String,Object> post(String path,Object payload) throws IOException,InterruptedException {
        String body=Json.encode(payload);
        HttpRequest request=HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(3)).header("Authorization","Bearer "+token).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(body,StandardCharsets.UTF_8)).build();
        HttpResponse<String> response=http.send(request,HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if(response.statusCode()!=200)throw new IOException("host request "+path+" failed with HTTP "+response.statusCode());
        if(response.body().length()>1_048_576)throw new IOException("oversized host response");
        return Json.object(Json.parse(response.body()));
    }
    @Override public void close(){if(closed.compareAndSet(false,true))timer.shutdownNow();}
}

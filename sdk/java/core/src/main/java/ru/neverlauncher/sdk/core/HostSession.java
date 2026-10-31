package ru.neverlauncher.sdk.core;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Authenticated local Extensions Host Protocol 1.0 hello and heartbeat client. */
public final class HostSession implements AutoCloseable {
    private final HttpClient http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).proxy(new ProxySelector(){public List<Proxy> select(URI u){return List.of(Proxy.NO_PROXY);}public void connectFailed(URI u,SocketAddress a,IOException e){}}).build();
    private final URI origin;private final String token,extensionId,instanceId;
    private final ScheduledExecutorService timer=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"neverext-heartbeat");t.setDaemon(true);return t;});
    private final AtomicBoolean closed=new AtomicBoolean();
    private volatile boolean healthy=true;
    private volatile Set<String> capabilities=Set.of();
    private volatile Set<String> events=Set.of();
    private volatile boolean connected;
    private volatile String eventProtocol="";
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
    public synchronized void connect() throws IOException,InterruptedException {connect("",Set.of());}
    public synchronized void connect(String callbackUrl) throws IOException,InterruptedException {connect(callbackUrl,Set.of());}
    /**
     * Require capabilities before Extension.start() is invoked. The v1.0 hello
     * request is unchanged, so this client also works with the original 0.42.0
     * Go host. An old host must return its actual capability list; an absent
     * list never implies permission to perform an operation.
     */
    public synchronized void connect(String callbackUrl,Set<String> requiredCapabilities) throws IOException,InterruptedException {
        if(closed.get())throw new IllegalStateException("session closed");
        if(connected)throw new IllegalStateException("host session already connected");
        Objects.requireNonNull(requiredCapabilities,"requiredCapabilities");
        for(String name:requiredCapabilities)validCapability(name);
        if(callbackUrl==null)throw new IllegalArgumentException("callbackUrl is null");
        if(!callbackUrl.isEmpty())validateOrigin(callbackUrl);
        Map<String,Object> hello=new LinkedHashMap<>(Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId",instanceId,"extensionId",extensionId,"pid",ProcessHandle.current().pid()));
        if(!callbackUrl.isBlank())hello.put("callbackUrl",callbackUrl);
        Map<String,Object> response=post("/v1/hello",hello);
        if(!"1.0".equals(response.get("protocolVersion"))||!"1.0".equals(response.get("extensionApiVersion"))||!instanceId.equals(response.get("instanceId")))throw new CompatibilityError("HOST_PROTOCOL_MISMATCH","host hello protocol/API/identity mismatch");
        Set<String> negotiated=parseNames(response.get("capabilities"),"capabilities");
        if(!negotiated.containsAll(requiredCapabilities)){
            Set<String> missing=new TreeSet<>(requiredCapabilities);missing.removeAll(negotiated);
            throw new CompatibilityError("HOST_CAPABILITY_UNAVAILABLE","host does not grant required capabilities: "+missing);
        }
        Object version=response.get("eventProtocolVersion");
        // 0.42.0 already advertises the event protocol; the independent
        // version must be validated whenever it is present.
        if(version!=null && !"1.0".equals(version))throw new CompatibilityError("HOST_EVENT_PROTOCOL_MISMATCH","unsupported event protocol: "+version);
        Set<String> supportedEvents=parseNames(response.get("events"),"events");
        Object hb=response.get("heartbeatTimeoutSeconds");if(!(hb instanceof Number n)||n.longValue()<2||n.longValue()>3600||n.doubleValue()!=n.longValue())throw new IOException("invalid heartbeat interval");
        capabilities=negotiated;
        events=supportedEvents;
        eventProtocol=version==null?"":"1.0";
        connected=true;
        long period=Math.max(1,n.longValue()/3);
        timer.scheduleWithFixedDelay(()->{try{post("/v1/heartbeat",Map.of());}catch(Exception e){healthy=false;close();}},period,period,TimeUnit.SECONDS);
    }
    private static Set<String> parseNames(Object raw,String field)throws IOException {
        if(raw==null)return Set.of();
        if(!(raw instanceof List<?> list)||list.size()>512)throw new IOException("invalid host "+field);
        Set<String> result=new HashSet<>();
        for(Object item:list){
            if(!(item instanceof String name)||name.length()>128||!name.matches("[a-z][a-z0-9.:-]*")||!result.add(name))throw new IOException("invalid host "+field+" entry");
        }
        return Set.copyOf(result);
    }
    private static void validCapability(String name){
        if(name==null||!name.matches("[a-z][a-z0-9.]{1,96}"))throw new IllegalArgumentException("invalid capability name");
    }
    private void requireConnected(){if(!connected||closed.get()||!healthy)throw new IllegalStateException("extension host session is not connected or healthy");}
    public void requireCapability(String name){
        validCapability(name);requireConnected();
        if(!capabilities.contains(name))throw new SecurityException("host capability unavailable: "+name);
    }
    public void requireEvent(String eventType){
        requireConnected();
        if(!events.contains(eventType))throw new SecurityException("host event unavailable: "+eventType);
        if(!eventProtocol.isEmpty()&&!"1.0".equals(eventProtocol))throw new SecurityException("event protocol unsupported");
    }
    /** A Java target is only marked running after Extension.start() completed. */
    public void ready() throws IOException,InterruptedException {
        requireConnected();
        Map<String,Object> answer=post("/v1/ready",Map.of("protocolVersion","1.0","instanceId",instanceId));
        if(!Boolean.TRUE.equals(answer.get("ready")))throw new IOException("host did not acknowledge Java readiness");
    }
    public boolean healthy(){return connected&&healthy&&!closed.get();}
    public Set<String> capabilities(){return capabilities;}
    public Set<String> events(){return events;}
    public Map<String,Object> capability(String name,Map<String,Object> payload) throws IOException,InterruptedException {
        requireCapability(name);
        return post("/v1/capabilities/"+name,payload);
    }
    public Map<String,Object> subscribe(String type,String mode) throws IOException,InterruptedException {requireEvent(type);return postExpect("/v1/events/subscriptions",Map.of("eventType",type,"mode",mode),201);}
    public void unsubscribe(long id) throws IOException,InterruptedException {requireConnected();send("DELETE","/v1/events/subscriptions/"+id,null,204);}
    private Map<String,Object> post(String path,Object payload) throws IOException,InterruptedException {return postExpect(path,payload,200);}
    private Map<String,Object> postExpect(String path,Object payload,int status) throws IOException,InterruptedException {return send("POST",path,payload,status);}
    private Map<String,Object> send(String method,String path,Object payload,int status) throws IOException,InterruptedException {
        String body=payload==null?"":Json.encode(payload);
        HttpRequest.Builder builder=HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(3)).header("Authorization","Bearer "+token).header("Content-Type","application/json");
        HttpRequest request=builder.method(method,payload==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body,StandardCharsets.UTF_8)).build();
        HttpResponse<String> response=http.send(request,HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if(response.body().length()>1_048_576)throw new IOException("oversized host response");
        if(response.statusCode()!=status){
            String code="HOST_HTTP_"+response.statusCode();
            try{
                Map<String,Object> fault=Json.object(Json.parse(response.body()));
                Object value=fault.get("code");
                if(value instanceof String v&&v.matches("[A-Z][A-Z0-9_]{2,63}"))code=v;
            }catch(IllegalArgumentException ignored){/* original 0.42.0 Go host uses plaintext http.Error */}
            throw new HostError(response.statusCode(),code,"host request "+path+" failed with HTTP "+response.statusCode()+" ("+code+")");
        }
        if(response.body().isEmpty())return Map.of();
        return Json.object(Json.parse(response.body()));
    }
    public static final class HostError extends IOException {
        private final int status;
        private final String code;
        public HostError(int status,String message){this(status,"HOST_HTTP_"+status,message);}
        public HostError(int status,String code,String message){super(message);this.status=status;this.code=code;}
        public int status(){return status;}
        public String code(){return code;}
    }
    public static final class CompatibilityError extends IOException {
        private final String code;
        public CompatibilityError(String code,String message){super(message);this.code=code;}
        public String code(){return code;}
    }
    @Override public void close(){if(closed.compareAndSet(false,true))timer.shutdownNow();}
}

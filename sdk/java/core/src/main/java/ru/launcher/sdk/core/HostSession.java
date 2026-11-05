package ru.launcher.sdk.core;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.Flow;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Аутентифицированный локальный клиент hello/heartbeat протокола Extensions Host 1.0. */
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
    /** Читать точный активный манифест из аутентифицированного Go-супервизора, а не из копий содержимого пакета. */
    public static String fetchManifestFromEnvironment(Map<String,String> env)throws IOException,InterruptedException {
        String raw=required(env,"LAUNCHER_EXTENSION_HOST_URL");
        URI origin=validateOrigin(raw);
        if(!"1.0".equals(required(env,"LAUNCHER_EXTENSION_HOST_PROTOCOL")) ||
           !"1.0".equals(required(env,"LAUNCHER_EXTENSION_API_VERSION")))throw new IllegalArgumentException("Несовместимые протокол или API Java-хоста");
        try(HostSession bootstrap=new HostSession(origin,required(env,"LAUNCHER_EXTENSION_HOST_TOKEN"),
            required(env,"LAUNCHER_EXTENSION_ID"),required(env,"LAUNCHER_EXTENSION_INSTANCE_ID"))){
            return Json.encode(bootstrap.send("GET","/v1/manifest",null,200));
        }
    }
    private static URI validateOrigin(String raw){
        URI url;
        try{url=URI.create(raw);}catch(IllegalArgumentException e){throw new IllegalArgumentException("Некорректный локальный URL хоста",e);}
        String host=url.getHost();if(!"http".equals(url.getScheme())||host==null||(!host.equals("127.0.0.1")&&!host.equals("::1"))||url.getPort()<1||url.getRawUserInfo()!=null||url.getRawQuery()!=null||url.getRawFragment()!=null||!(url.getPath().isEmpty()||url.getPath().equals("/")))throw new IllegalArgumentException("URL хоста должен быть локальным HTTP-адресом loopback");
        return url;
    }
    public static HostSession fromEnvironment(Map<String,String> env,ExtensionManifest manifest) {
        URI url=validateOrigin(required(env,"LAUNCHER_EXTENSION_HOST_URL"));
        String id=required(env,"LAUNCHER_EXTENSION_ID");
        if(!id.equals(manifest.id())||!required(env,"LAUNCHER_EXTENSION_VERSION").equals(manifest.versionText()))throw new IllegalArgumentException("Идентификатор хоста отличается от манифеста");
        if(!required(env,"LAUNCHER_EXTENSION_HOST_PROTOCOL").equals("1.0")||!required(env,"LAUNCHER_EXTENSION_API_VERSION").equals("1.0"))throw new IllegalArgumentException("Несовместимые протокол или API хоста");
        return new HostSession(url,required(env,"LAUNCHER_EXTENSION_HOST_TOKEN"),id,required(env,"LAUNCHER_EXTENSION_INSTANCE_ID"));
    }
    private static String required(Map<String,String> env,String key){String v=env.get(key);if(v==null||v.isBlank())throw new IllegalArgumentException("Отсутствует обязательная переменная "+key);return v;}
    public synchronized void connect() throws IOException,InterruptedException {connect("",Set.of());}
    public synchronized void connect(String callbackUrl) throws IOException,InterruptedException {connect(callbackUrl,Set.of());}
    /**
     * Проверить возможности до вызова Extension.start(). Запрос hello версии v1.0
     * остаётся неизменным, поэтому этот клиент также работает с исходным Go-хостом 0.42.0.
     * Старый хост обязан возвращать реальный список возможностей; отсутствие
     * списка никогда не означает разрешение на выполнение операции.
     */
    public synchronized void connect(String callbackUrl,Set<String> requiredCapabilities) throws IOException,InterruptedException {
        if(closed.get())throw new IllegalStateException("Сессия закрыта");
        if(connected)throw new IllegalStateException("Сессия хоста уже подключена");
        Objects.requireNonNull(requiredCapabilities,"requiredCapabilities");
        for(String name:requiredCapabilities)validCapability(name);
        if(callbackUrl==null)throw new IllegalArgumentException("Значение callbackUrl отсутствует");
        if(!callbackUrl.isEmpty())validateOrigin(callbackUrl);
        Map<String,Object> hello=new LinkedHashMap<>(Map.of("protocolVersion","1.0","extensionApiVersion","1.0","instanceId",instanceId,"extensionId",extensionId,"pid",ProcessHandle.current().pid()));
        if(!callbackUrl.isBlank())hello.put("callbackUrl",callbackUrl);
        Map<String,Object> response=post("/v1/hello",hello);
        if(!"1.0".equals(response.get("protocolVersion"))||!"1.0".equals(response.get("extensionApiVersion"))||!instanceId.equals(response.get("instanceId")))throw new CompatibilityError("HOST_PROTOCOL_MISMATCH","Несовпадение протокола, API или удостоверения при приветствии хоста");
        Set<String> negotiated=parseNames(response.get("capabilities"),"capabilities");
        if(!negotiated.containsAll(requiredCapabilities)){
            Set<String> missing=new TreeSet<>(requiredCapabilities);missing.removeAll(negotiated);
            throw new CompatibilityError("HOST_CAPABILITY_UNAVAILABLE","Хост не предоставляет необходимые возможности: "+missing);
        }
        Object version=response.get("eventProtocolVersion");
        // Версия 0.42.0 уже объявляет протокол событий; при его наличии независимую
        // версию обязательно проверять.
        if(version!=null && !"1.0".equals(version))throw new CompatibilityError("HOST_EVENT_PROTOCOL_MISMATCH","Неподдерживаемый протокол событий: "+version);
        Set<String> supportedEvents=parseNames(response.get("events"),"events");
        Object hb=response.get("heartbeatTimeoutSeconds");if(!(hb instanceof Number n)||n.longValue()<2||n.longValue()>3600||n.doubleValue()!=n.longValue())throw new IOException("Некорректный интервал сигналов активности");
        capabilities=negotiated;
        events=supportedEvents;
        eventProtocol=version==null?"":"1.0";
        connected=true;
        long period=Math.max(1,n.longValue()/3);
        long requestMillis=Math.max(500,Math.min(3000,n.longValue()*1000/3));
        timer.scheduleWithFixedDelay(()->{
            if(closed.get())return;
            try{
                Map<String,Object> ack=send("POST","/v1/heartbeat",Map.of(),200,Duration.ofMillis(requestMillis));
                if(!Boolean.TRUE.equals(ack.get("ok")))throw new IOException("Хост отклонил подтверждение сигнала активности");
            }catch(Exception e){healthy=false;close();}
        },period,period,TimeUnit.SECONDS);
    }
    private static Set<String> parseNames(Object raw,String field)throws IOException {
        if(raw==null)return Set.of();
        if(!(raw instanceof List<?> list)||list.size()>512)throw new IOException("Некорректный хост "+field);
        Set<String> result=new HashSet<>();
        for(Object item:list){
            if(!(item instanceof String name)||name.length()>128||!name.matches("[a-z][a-z0-9.:-]*")||!result.add(name))throw new IOException("Некорректный элемент поля хоста "+field);
        }
        return Set.copyOf(result);
    }
    private static void validCapability(String name){
        if(name==null||!name.matches("[a-z][a-z0-9.]{1,96}"))throw new IllegalArgumentException("Некорректное имя разрешённой возможности");
    }
    private void requireConnected(){if(!connected||closed.get()||!healthy)throw new IllegalStateException("Сессия хоста расширения не подключена или неисправна");}
    public void requireCapability(String name){
        validCapability(name);requireConnected();
        if(!capabilities.contains(name))throw new SecurityException("Возможность хоста недоступна: "+name);
    }
    public void requireEvent(String eventType){
        requireConnected();
        if(!events.contains(eventType))throw new SecurityException("Событие хоста недоступно: "+eventType);
        if(!eventProtocol.isEmpty()&&!"1.0".equals(eventProtocol))throw new SecurityException("Протокол событий не поддерживается");
    }
    /** Цель Java считается работающей только после завершения Extension.start(). */
    public void ready() throws IOException,InterruptedException {
        requireConnected();
        Map<String,Object> answer=post("/v1/ready",Map.of("protocolVersion","1.0","instanceId",instanceId));
        if(!Boolean.TRUE.equals(answer.get("ready")))throw new IOException("Хост не подтвердил готовность Java");
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
        return send(method,path,payload,status,Duration.ofSeconds(3));
    }
    private Map<String,Object> send(String method,String path,Object payload,int status,Duration timeout) throws IOException,InterruptedException {
        String body=payload==null?"":Json.encode(payload);
        HttpRequest.Builder builder=HttpRequest.newBuilder(origin.resolve(path)).timeout(timeout).header("Authorization","Bearer "+token).header("Content-Type","application/json");
        HttpRequest request=builder.method(method,payload==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(body,StandardCharsets.UTF_8)).build();
        // Потоковый BodySubscriber применяет предел до буферизации сверх 1 МиБ; в
        // отличие от ofInputStream() срок запроса охватывает и ввод-вывод тела.
        HttpResponse<byte[]> response=http.send(request,info->new BoundedBody(1_048_576));
        String responseBody=new String(response.body(),StandardCharsets.UTF_8);
        if(response.statusCode()!=status){
            String code="HOST_HTTP_"+response.statusCode();
            try{
                Map<String,Object> fault=Json.object(Json.parse(responseBody));
                Object value=fault.get("code");
                if(value instanceof String v&&v.matches("[A-Z][A-Z0-9_]{2,63}"))code=v;
            }catch(IllegalArgumentException ignored){/* исходный Go-хост версии 0.42.0 использует обычный текстовый http.Error */}
            throw new HostError(response.statusCode(),code,"Запрос хоста "+path+" завершился ошибкой HTTP "+response.statusCode()+" ("+code+")");
        }
        if(responseBody.isEmpty())return Map.of();
        return Json.object(Json.parse(responseBody));
    }
    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> completion=new CompletableFuture<>();
        private final ByteArrayOutputStream content=new ByteArrayOutputStream();
        private final int limit;
        private Flow.Subscription subscription;
        private boolean done;
        BoundedBody(int limit){this.limit=limit;}
        @Override public CompletionStage<byte[]> getBody(){return completion;}
        @Override public void onSubscribe(Flow.Subscription next){
            subscription=next;next.request(1);
        }
        @Override public void onNext(List<ByteBuffer> chunks){
            if(done)return;
            for(ByteBuffer chunk:chunks){
                if(chunk.remaining()>limit-content.size()){
                    done=true;subscription.cancel();
                    completion.completeExceptionally(new IOException("Ответ хоста превышает допустимый размер"));
                    return;
                }
                byte[] bytes=new byte[chunk.remaining()];chunk.get(bytes);
                content.write(bytes,0,bytes.length);
            }
            subscription.request(1);
        }
        @Override public void onError(Throwable cause){done=true;completion.completeExceptionally(cause);}
        @Override public void onComplete(){done=true;completion.complete(content.toByteArray());}
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

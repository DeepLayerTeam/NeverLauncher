package ru.neverlauncher.api;

import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import ru.launcher.sdk.core.Json;

/** Рабочий клиент REST API v1. Использует существующий JSON-парсер Java-ядра NeverLauncher. */
public final class NeverLauncherAPI {
    public static final String CONTRACT_VERSION = "1.0.0";
    private static final int MAX_RESPONSE = 8 * 1024 * 1024;
    private static final long MAX_STREAM = 1L << 30;
    private static final Pattern PARAM = Pattern.compile("\\{([^{}]+)\\}");
    private final URI base;
    private final String token;
    private final HttpClient http;

    public static final class ApiException extends RuntimeException {
        public final int status;
        public final String code, requestId;
        public ApiException(int status, String code, String message, String requestId) {
            super(message); this.status=status;this.code=code;this.requestId=requestId;
        }
    }
    public NeverLauncherAPI(String baseUrl, String bearerToken) {
        URI u=URI.create(Objects.requireNonNull(baseUrl));
        String h=u.getHost();
        boolean loop=h!=null && (h.equalsIgnoreCase("localhost") || h.equals("127.0.0.1") || h.equals("::1"));
        if(h==null || u.getUserInfo()!=null || u.getQuery()!=null || u.getFragment()!=null ||
           !(u.getPath().equals("") || u.getPath().equals("/")) ||
           !(u.getScheme().equals("https") || u.getScheme().equals("http") && loop))
            throw new IllegalArgumentException("API requires HTTPS (HTTP only permitted on loopback)");
        this.base=URI.create(u.getScheme()+"://"+u.getRawAuthority());
        this.token=bearerToken==null?"":bearerToken;
        this.http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();
    }
    public static String resolvePath(String template, Map<String,String> params) {
        if(!template.startsWith("/") || template.contains("?") || template.contains("#"))throw new IllegalArgumentException("invalid path template");
        var m=PARAM.matcher(template);var result=new StringBuffer();var used=new java.util.HashSet<String>();
        while(m.find()) {
            String key=m.group(1),v=params.get(key);used.add(key);
            if(v==null || v.isEmpty() || v.equals(".") || v.equals("..") || v.contains("/") || v.contains("\\"))throw new IllegalArgumentException("invalid path parameter: "+key);
            m.appendReplacement(result,Matcher.quoteReplacement(URLEncoder.encode(v,StandardCharsets.UTF_8).replace("+","%20")));
        }
        m.appendTail(result);
        if(!used.containsAll(params.keySet()) || result.indexOf("{")>=0 || result.indexOf("}")>=0)throw new IllegalArgumentException("unknown path parameter");
        return result.toString();
    }
    public Object call(String operationId,Map<String,String> pathParameters,Map<String,String> query,Object jsonBody,String idempotencyKey) throws IOException,InterruptedException {
        var op=Operations.ALL.get(operationId);
        if(op==null)throw new IllegalArgumentException("unknown OpenAPI operation: "+operationId);
        byte[] body=jsonBody==null?null:Json.encode(jsonBody).getBytes(StandardCharsets.UTF_8);
        return request(op.method(),resolvePath(op.path(),pathParameters),query,body,body==null?null:"application/json",idempotencyKey);
    }
    public Object request(String method,String path,Map<String,String> query,byte[] body,String contentType,String idempotencyKey) throws IOException,InterruptedException {
        byte[] raw = requestBytes(method,path,query,body,contentType,idempotencyKey);
        if(raw.length == 0)return null;
        if(raw.length>1_048_576)throw new IOException("JSON API response exceeds Java Core parser limit (1 MiB); use requestBytes");
        try {return Json.parse(new String(raw,StandardCharsets.UTF_8));}
        catch(RuntimeException ex){throw new IOException("invalid JSON API response",ex);}
    }
    /** Двоичный/multipart-транспорт с ограниченным ответом, полезный для скачивания и загрузки файлов. */
    public byte[] requestBytes(String method,String path,Map<String,String> query,byte[] body,String contentType,String idempotencyKey) throws IOException,InterruptedException {
        if(!allowedRoute(path) || path.contains("?") || path.contains("#") || path.contains(".."))throw new IllegalArgumentException("unsafe API route");
        var uri=base.resolve(path+(query==null||query.isEmpty()?"":"?"+query.entrySet().stream().sorted(Map.Entry.comparingByKey())
            .map(e->URLEncoder.encode(e.getKey(),StandardCharsets.UTF_8)+"="+URLEncoder.encode(e.getValue(),StandardCharsets.UTF_8)).reduce((a,b)->a+"&"+b).orElse("")));
        var builder=HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(15)).header("Accept","application/json");
        if(!token.isBlank())builder.header("Authorization","Bearer "+token);
        if(contentType!=null)builder.header("Content-Type",contentType);
        if(idempotencyKey!=null && !idempotencyKey.isEmpty()) {
            if(idempotencyKey.contains("\r")||idempotencyKey.contains("\n"))throw new IllegalArgumentException("invalid idempotency key");
            builder.header("Idempotency-Key",idempotencyKey);
        }
        var response=http.send(builder.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofByteArray(body)).build(),HttpResponse.BodyHandlers.ofInputStream());
        byte[] bytes;
        try(var input=response.body()) { bytes=input.readNBytes(MAX_RESPONSE+1); }
        if(bytes.length>MAX_RESPONSE)throw new IOException("API response exceeds 8 MiB");
        if(response.statusCode()<200 || response.statusCode()>299){
            Object data=null;
            try { if(bytes.length>0 && bytes.length<=1_048_576)data=Json.parse(new String(bytes,StandardCharsets.UTF_8)); }
            catch(RuntimeException ignored) {}
            Map<String,Object> e=data instanceof Map?Json.object(data):Map.of();
            throw new ApiException(response.statusCode(),String.valueOf(e.getOrDefault("code","")),
                String.valueOf(e.getOrDefault("message",e.getOrDefault("error","HTTP "+response.statusCode()))),
                response.headers().firstValue("X-Correlation-ID").orElse(""));
        }
        return bytes;
    }
    /** Потоковая передача больших ответов API в каталог назначения оператора (не более 1 ГиБ).
     *
     * При возникновении IOException вызывающий код должен удалить результат: при
     * прерывании сети в нём может остаться неполезная часть данных.
     * Перенаправления никогда не выполняются, даже для предоставленных вызывающим тел запросов.
     * Для больших загрузок используйте HttpRequest.BodyPublishers.ofFile(...), а не byte[].
     * Нулевой лимит означает верхнюю границу 1 ГиБ. Этот метод никогда не закрывает
     * предоставленный вызывающим OutputStream.
     */
    public long requestStream(String method, String path, Map<String,String> query,
                              HttpRequest.BodyPublisher requestBody, String contentType,
                              OutputStream destination, long limit, String idempotencyKey)
            throws IOException, InterruptedException {
        Objects.requireNonNull(destination, "response destination");
        if (limit == 0) limit = MAX_STREAM;
        if (limit < 1 || limit > MAX_STREAM) throw new IllegalArgumentException("invalid stream limit");
        if (!allowedRoute(path) || path.contains("?") || path.contains("#") || path.contains("..") || path.startsWith("//"))
            throw new IllegalArgumentException("unsafe API route");
        if (idempotencyKey != null && (idempotencyKey.contains("\r") || idempotencyKey.contains("\n")))
            throw new IllegalArgumentException("invalid idempotency key");
        var qs = query == null || query.isEmpty() ? "" : "?" + query.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .reduce((a, b) -> a + "&" + b).orElse("");
        var builder = HttpRequest.newBuilder(base.resolve(path + qs))
            .timeout(Duration.ofMinutes(5)).header("Accept", "*/*");
        if (!token.isBlank()) builder.header("Authorization", "Bearer " + token);
        if (contentType != null) builder.header("Content-Type", contentType);
        if (idempotencyKey != null && !idempotencyKey.isEmpty()) builder.header("Idempotency-Key", idempotencyKey);
        var publisher = requestBody == null ? HttpRequest.BodyPublishers.noBody() : requestBody;
        var response = http.send(builder.method(method, publisher).build(), HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream stream = response.body()) {
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                // Ограничивайте разбор ошибок отдельно от предела успешного потока.
                byte[] raw = stream.readNBytes(MAX_RESPONSE + 1);
                if (raw.length > MAX_RESPONSE) throw new IOException("API error response exceeds 8 MiB");
                Object data = null;
                try { if (raw.length > 0 && raw.length <= 1_048_576) data = Json.parse(new String(raw, StandardCharsets.UTF_8)); }
                catch (RuntimeException ignored) { }
                Map<String,Object> e = data instanceof Map ? Json.object(data) : Map.of();
                throw new ApiException(response.statusCode(), String.valueOf(e.getOrDefault("code", "")),
                    String.valueOf(e.getOrDefault("message", e.getOrDefault("error", "HTTP " + response.statusCode()))),
                    response.headers().firstValue("X-Correlation-ID").orElse(""));
            }
            var declared = response.headers().firstValueAsLong("Content-Length");
            if (declared.isPresent() && declared.getAsLong() > limit)
                throw new IOException("API stream exceeds configured size limit");
            byte[] buffer = new byte[64 * 1024];
            long written = 0;
            int n;
            while ((n = stream.read(buffer)) != -1) {
                if (n > limit - written) throw new IOException("API stream exceeds configured size limit");
                destination.write(buffer, 0, n);
                written += n;
            }
            return written;
        }
    }

    /** Вызывает сгенерированную операцию OpenAPI с потоковым запросом и ответом. */
    public long callStream(String operationId, Map<String,String> pathParameters, Map<String,String> query,
                           HttpRequest.BodyPublisher requestBody, String contentType,
                           OutputStream destination, long limit, String idempotencyKey)
            throws IOException, InterruptedException {
        var operation = Operations.ALL.get(operationId);
        if (operation == null) throw new IllegalArgumentException("unknown OpenAPI operation: " + operationId);
        return requestStream(operation.method(), resolvePath(operation.path(), pathParameters), query,
                             requestBody, contentType, destination, limit, idempotencyKey);
    }

    private static boolean allowedRoute(String path){
        return path.startsWith("/api/v1/") || path.equals("/health") || path.equals("/ready") || path.equals("/metrics") ||
               path.startsWith("/api/profiles/minecraft") || path.startsWith("/api/user/profile/") ||
               path.startsWith("/authserver/") || path.startsWith("/sessionserver/");
    }
    /** Совместимость N-1: в 0.45.11 отсутствовал заголовок контракта; определяющая версия находится в /ready. */
    public void checkCompatibility() throws IOException,InterruptedException {
        var response=http.send(HttpRequest.newBuilder(base.resolve("/ready")).timeout(Duration.ofSeconds(10)).GET().build(),HttpResponse.BodyHandlers.ofString());
        if(response.statusCode()!=200)throw new IOException("backend not ready: "+response.statusCode());
        var contract=response.headers().firstValue("X-Launcher-API-Contract");
        if(contract.isPresent()) {
            if(!contract.get().equals(CONTRACT_VERSION))throw new IOException("incompatible OpenAPI contract: "+contract.get());
            return;
        }
        var data=Json.object(Json.parse(response.body()));var version=data.get("version");
        if(!"0.45.11".equals(version) && !"0.45.12".equals(version))throw new IOException("unsupported legacy backend version");
    }
}

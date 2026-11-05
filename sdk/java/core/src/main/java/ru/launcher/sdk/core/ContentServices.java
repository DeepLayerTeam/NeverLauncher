package ru.launcher.sdk.core;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/** Рабочий Java SPI для контента. Любое чтение источника проходит через аутентифицированный
 * Go Host Broker; провайдерам не предоставляется прямой доступ к внешней сети или хранилищу.
 * Преобразованный пакет — данные ТОЛЬКО ДО ПОДПИСИ, которые должны быть подписаны и опубликованы
 * через существующий конвейер выпуска NeverLauncher. */
public final class ContentServices {
    public static final ProviderService<ContentProvider> CONTRACT =
        new ProviderService<>("never.content", ContentProvider.class, SemVer.parse("1.0.0"));
    private static final int MAX_ASSET = 512 * 1024; // Данные Base64 должны помещаться в ответ Host объёмом 1 МиБ.
    private static final int MAX_RPC_BYTES = 24 * 1024;
    private volatile ProviderRegistry registry;
    private final HostSession host;
    public ContentServices(HostSession host) { this.host = Objects.requireNonNull(host); }
    void bind(ProviderRegistry r) { registry = Objects.requireNonNull(r); }
    private ProviderRegistry registry() {
        var r = registry;
        if (r == null) throw new IllegalStateException("Интерфейс SPI содержимого недоступен");
        return r;
    }
    private static String ident(String value) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}") || value.equals(".."))
            throw new IllegalArgumentException("Некорректный идентификатор содержимого");
        return value;
    }
    private static String path(String value) {
        if (value == null || value.length() > 512 || value.isEmpty() || value.startsWith("/") || value.contains("\\") || value.indexOf('\0') >= 0)
            throw new IllegalArgumentException("Некорректный путь к содержимому");
        for (String part : value.split("/",-1)) if (part.isEmpty() || part.equals(".") || part.equals(".."))
            throw new IllegalArgumentException("Путь к содержимому выходит за пределы каталога");
        return value;
    }
    /** Дескриптор закрепляет точные байты. HTTPS-источники остаются под контролем Go-списка исходящих соединений.
     * Локальное хранилище использует существующее пространство версий проекта. */
    public record Asset(String projectId, String location, String version, String path,
                        String sha256, int size) {
        public Asset {
            projectId = ident(projectId);
            if (!"storage".equals(location) && !"https".equals(location))
                throw new IllegalArgumentException("Неподдерживаемое расположение содержимого");
            if ("storage".equals(location)) { version = ident(version); path = ContentServices.path(path); }
            else {
                if (version != null && !version.isEmpty()) throw new IllegalArgumentException("Удалённый ресурс содержит версию");
                version = "";
                var uri = java.net.URI.create(path);
                if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null)
                    throw new IllegalArgumentException("Некорректный HTTPS-адрес содержимого");
                if (path.length() > 2048) throw new IllegalArgumentException("Слишком длинный URL содержимого");
            }
            if (sha256 == null || !sha256.matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("Отсутствует: SHA-256");
            sha256 = sha256.toLowerCase(Locale.ROOT);
            if (size < 0 || size > MAX_ASSET) throw new IllegalArgumentException("Содержимое превышает ограничения брокера");
        }
        public Map<String,Object> wire() {
            return Map.of("projectId",projectId,"location",location,"version",version,"path",path,"sha256",sha256,"size",size);
        }
    }
    public record PreparedPackage(byte[] bytes, String sha256, int size, boolean requiresSigning) {
        public PreparedPackage { bytes = bytes.clone(); }
        @Override public byte[] bytes() { return bytes.clone(); }
    }
    private <R> R invoke(java.util.function.Function<ContentProvider,R> action) {
        return registry().call(CONTRACT,action);
    }
    private static final class Checked extends RuntimeException {
        final Exception cause;
        Checked(Exception cause) { super(cause); this.cause=cause; }
    }
    private <R> R checked(Throwing<ContentProvider,R> fn) throws Exception {
        try { return invoke(p -> { try { return fn.run(p); } catch (Exception e) { throw new Checked(e); } }); }
        catch (Checked e) { throw e.cause; }
    }
    @FunctionalInterface private interface Throwing<T,R> { R run(T value) throws Exception; }
    private static Asset scoped(Asset asset,String projectId) {
        if (asset == null || !asset.projectId().equals(projectId)) throw new SecurityException("Провайдер содержимого вернул результат другого проекта");
        return asset;
    }
    public Asset source(String projectId,String logicalPath) throws Exception {
        ident(projectId); path(logicalPath);
        return scoped(checked(p -> p.source(projectId,logicalPath)),projectId);
    }
    public Asset texture(String projectId,String profileId,String kind) throws Exception {
        ident(projectId); ident(profileId);
        if (!"skin".equals(kind) && !"cape".equals(kind)) throw new IllegalArgumentException("Неподдерживаемый тип текстуры");
        return scoped(checked(p -> p.texture(projectId,profileId,kind)),projectId);
    }
    public Asset delivery(String projectId,String logicalPath) throws Exception {
        ident(projectId);path(logicalPath);
        return scoped(checked(p -> p.delivery(projectId,logicalPath)),projectId);
    }
    public Map<String,Object> metadata(String projectId,String releaseId,Map<String,Object> original) throws Exception {
        ident(projectId);ident(releaseId);Objects.requireNonNull(original);
        if (Json.encode(original).length()>MAX_RPC_BYTES) throw new IllegalArgumentException("Метаданные слишком велики");
        // Провайдер получает изолированную копию: даже изменение вложенных карт не
        // может изменить канонические подписанные значения, с которыми сравнивается его
        // вывод.
        Map<String,Object> baseline=Json.object(Json.parse(Json.encode(original)));
        Map<String,Object> input=Json.object(Json.parse(Json.encode(original)));
        var result = checked(p -> p.metadata(projectId,releaseId,input));
        if (result == null || Json.encode(result).length()>MAX_RPC_BYTES) throw new IllegalArgumentException("Некорректные метаданные содержимого");
        for(var entry:baseline.entrySet())
            if (!result.containsKey(entry.getKey()) || !Objects.equals(result.get(entry.getKey()),entry.getValue()))
                throw new SecurityException("Провайдер попытался изменить подписанные метаданные: "+entry.getKey());
        for(String key:result.keySet())
            if (!baseline.containsKey(key) && !key.matches("x-[a-z0-9][a-z0-9-]{0,62}"))
                throw new SecurityException("Провайдер попытался добавить метаданные вне пространства расширения: "+key);
        return Collections.unmodifiableMap(new LinkedHashMap<>(Json.object(Json.parse(Json.encode(result)))));
    }
    public PreparedPackage preparePackage(String projectId,String name,byte[] input) throws Exception {
        ident(projectId);path(name);Objects.requireNonNull(input);
        if (input.length>MAX_ASSET) throw new IllegalArgumentException("Входной пакет превышает лимит SPI");
        byte[] result = checked(p -> p.preparePackage(projectId,name,input.clone()));
        if (result == null || result.length>MAX_ASSET) throw new IllegalArgumentException("Некорректный преобразованный пакет");
        return new PreparedPackage(result,sha(result),result.length,true);
    }
    /** Байты проверяются ДО передачи расширению. Ни один источник по умолчанию не считается доверенным
     * опубликованным выпуском; основная проверка манифеста и подписи остаётся обязательной. */
    public byte[] readChecked(Asset asset) throws IOException,InterruptedException {
        Objects.requireNonNull(asset);
        Map<String,Object> res;
        if (asset.location().equals("storage"))
            res=host.capability("storage.read",Map.of("projectId",asset.projectId(),"version",asset.version(),"path",asset.path()));
        else {
            res=host.capability("http.fetch",Map.of("projectId",asset.projectId(),"method","GET","url",asset.path()));
            if (!(res.get("status") instanceof Number code) || code.intValue()!=200 || code.doubleValue()!=200)
                throw new IOException("Внешний источник содержимого не вернул HTTP 200");
        }
        Object raw=res.get(asset.location().equals("storage")?"contentBase64":"bodyBase64");
        if (!(raw instanceof String b64) || b64.length()>((MAX_ASSET+2)/3)*4+8)
            throw new IOException("Некорректный ответ брокера содержимого");
        byte[] bytes;
        try { bytes=Base64.getDecoder().decode(b64); }
        catch(IllegalArgumentException e) { throw new IOException("Некорректная кодировка Base64 содержимого",e); }
        if (bytes.length!=asset.size() || !MessageDigest.isEqual(hexBytes(sha(bytes)),hexBytes(asset.sha256())))
            throw new SecurityException("Несовпадение контрольной суммы содержимого");
        return bytes;
    }
    private static byte[] hexBytes(String hex) { return java.util.HexFormat.of().parseHex(hex); }
    public static String sha(byte[] bytes) {
        try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch(NoSuchAlgorithmException e){throw new IllegalStateException(e);}
    }
    /** Аутентифицированный обратный вызов Go->JVM для фактически выбранных провайдеров контента. */
    Map<String,Object> dispatch(String method,Map<String,Object> params) {
        try {
            if (method.equals("content.health")) return Map.of("available",registry().selected(CONTRACT.id()).isPresent());
            String projectId=ident(Json.string(params,"projectId",true));
            return switch(method) {
                case "content.source.resolve" -> Map.of("asset",source(projectId,Json.string(params,"path",true)).wire());
                case "content.texture.resolve" -> Map.of("asset",texture(projectId,Json.string(params,"profileId",true),Json.string(params,"kind",true)).wire());
                case "content.delivery.resolve" -> Map.of("asset",delivery(projectId,Json.string(params,"path",true)).wire());
                case "content.metadata.enrich" -> Map.of("metadata",metadata(projectId,Json.string(params,"releaseId",true),Json.object(params.get("metadata"))));
                case "content.package.prepare" -> {
                    byte[] input=Base64.getDecoder().decode(Json.string(params,"dataBase64",true));
                    if(input.length>MAX_RPC_BYTES)throw new IllegalArgumentException("Входные данные RPC пакета превышают лимит");
                    PreparedPackage prepared=preparePackage(projectId,Json.string(params,"name",true),input);
                    if(prepared.size()>MAX_RPC_BYTES)throw new IllegalArgumentException("Выходные данные RPC пакета превышают лимит");
                    yield Map.of("dataBase64",Base64.getEncoder().encodeToString(prepared.bytes()),
                                 "sha256",prepared.sha256(),"size",prepared.size(),"requiresSigning",true);
                }
                default -> throw new IllegalArgumentException("Неизвестная операция RPC содержимого");
            };
        } catch (Exception e) { return Map.of("errorCode", e instanceof SecurityException ? "content_denied" : "content_unavailable"); }
    }
}

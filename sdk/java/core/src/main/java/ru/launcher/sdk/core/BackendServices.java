package ru.launcher.sdk.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/** Доступные только для чтения сервисы Backend в рамках проекта через аутентифицированный Go-брокер возможностей.
 * Расширениям не предоставляются клиенты БД, новые учётные данные или внутренние HTTP-маршруты.
 * Брокер проверяет актуальные разрешения как перед выполнением, так и перед возвратом ответа.
 */
public final class BackendServices {
    private final HostSession host;

    BackendServices(HostSession host) { this.host = Objects.requireNonNull(host); }

    public record Page<T>(List<T> items, Integer nextOffset) {
        public Page { items = List.copyOf(items); }
    }
    public record Project(String id, String name, String description, String homepage,
                          String repository, String defaultChannel, String createdAt, String updatedAt) {}
    public record Profile(String id, String projectId, String name, String description,
                          String loader, String minecraftVersion, String loaderVersion,
                          int javaMajor, String preset, boolean isDefault, long revision) {}
    public record Channel(String id, String projectId, String name, String description, boolean protectedChannel) {}
    public record Release(String id, String projectId, String profileId, String channel,
                          String version, String status, String publishedAt, Map<String,Object> manifest) {
        public Release { manifest = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(manifest)); }
    }
    /** Намеренно исключает полезную нагрузку/результат/учётные данные аренды задания, исполнителя и текст ошибки. */
    public record Job(String id, String projectId, String kind, String status,
                      int attemptCount, int maxAttempts, String createdAt,
                      String updatedAt, String completedAt) {}

    private static String id(String value, String field) {
        if (value == null || value.isBlank() || value.length() > 128 || value.chars().anyMatch(c -> c < 32 || c == 127))
            throw new IllegalArgumentException("invalid " + field);
        return value;
    }
    private static Map<String,Object> request(String projectId) { return Map.of("projectId", id(projectId,"projectId")); }
    private Map<String,Object> call(String capability, Map<String,Object> payload) throws IOException,InterruptedException {
        return host.capability(capability, payload);
    }
    private static Map<String,Object> record(Map<String,Object> response, String key) {
        return Json.object(Objects.requireNonNull(response.get(key),"В ответе Backend отсутствует " + key));
    }
    private static String text(Map<String,Object> raw,String key) {
        Object v=raw.get(key);
        if(v==null)return "";
        if(!(v instanceof String s))throw new IllegalArgumentException("Недопустимое поле Backend: " + key);
        return s;
    }
    private static String required(Map<String,Object> raw,String key) {
        return id(Json.string(raw,key,true),key);
    }
    private static boolean bool(Map<String,Object> raw,String key) {
        Object n=raw.get(key);
        if(!(n instanceof Boolean b))throw new IllegalArgumentException("Недопустимое логическое значение Backend: "+key);
        return b;
    }
    private static long number(Map<String,Object> raw,String key) {
        Object n=raw.get(key);
        if(!(n instanceof Number value)||value.longValue()!=value.doubleValue()||value.longValue()<0)
            throw new IllegalArgumentException("Некорректное число Backend: "+key);
        return value.longValue();
    }
    private static int narrow(Map<String,Object> raw,String key) {
        long v=number(raw,key);
        if(v>Integer.MAX_VALUE)throw new IllegalArgumentException("Переполнение целочисленного значения Backend: "+key);
        return (int)v;
    }
    private static Project project(Map<String,Object> m) {
        return new Project(required(m,"id"),required(m,"name"),text(m,"description"),text(m,"homepage"),
                text(m,"repository"),text(m,"defaultChannel"),text(m,"createdAt"),text(m,"updatedAt"));
    }
    private static Profile profile(Map<String,Object> m) {
        return new Profile(required(m,"id"),required(m,"projectId"),required(m,"name"),text(m,"description"),
                text(m,"loader"),text(m,"minecraftVersion"),text(m,"loaderVersion"),
                narrow(m,"javaMajor"),text(m,"preset"),bool(m,"isDefault"),number(m,"revision"));
    }
    private static Channel channel(Map<String,Object> m) {
        return new Channel(required(m,"id"),required(m,"projectId"),required(m,"name"),
                text(m,"description"),bool(m,"protected"));
    }
    private static Release release(Map<String,Object> m) {
        return new Release(required(m,"id"),required(m,"projectId"),required(m,"profileId"),
                required(m,"channel"),required(m,"version"),required(m,"status"),
                text(m,"publishedAt"),m.get("manifest")==null?Map.of():Json.object(m.get("manifest")));
    }
    private static Job job(Map<String,Object> m) {
        return new Job(required(m,"id"),required(m,"projectId"),required(m,"kind"),
                required(m,"status"),narrow(m,"attemptCount"),narrow(m,"maxAttempts"),
                text(m,"createdAt"),text(m,"updatedAt"),text(m,"completedAt"));
    }
    private <T> Page<T> page(String operation,Map<String,Object> base,int offset,int limit,Function<Map<String,Object>,T> decoder)
            throws IOException,InterruptedException {
        if(offset<0||offset>1_000_000||limit<1||limit>50)throw new IllegalArgumentException("Некорректные параметры страницы");
        var params=new java.util.LinkedHashMap<>(base);
        params.put("offset",offset);params.put("limit",limit);
        var response=call(operation,params);
        Object raw=response.get("items");
        if(!(raw instanceof List<?> items)||items.size()>limit)throw new IllegalArgumentException("Некорректная страница данных Backend");
        List<T> decoded=new ArrayList<>(items.size());
        for(Object item:items) {
            Map<String,Object> map=Json.object(item);
            T value=decoder.apply(map);
            // Не допускайте, чтобы повреждённый или устаревший брокер смешивал данные
            // проектов.
            Object expected=base.get("projectId");
            if(expected!=null && !Objects.equals(expected,map.get("projectId")))
                throw new SecurityException("Ответ Backend относится к другому проекту");
            decoded.add(value);
        }
        Integer next=null;
        if(response.containsKey("nextOffset")) {
            long n=number(response,"nextOffset");
            if(n<=offset||n>1_000_000)throw new IllegalArgumentException("Некорректный указатель выборки Backend");
            next=(int)n;
        }
        return new Page<>(decoded,next);
    }
    private static void checkScope(String projectId,String expected) {
        if(!projectId.equals(expected))throw new SecurityException("Ответ Backend относится к другому проекту");
    }

    /** Требуется project:read и глобальное разрешение для расширения глобальной области действия. */
    public Page<Project> projects(int offset,int limit)throws IOException,InterruptedException {
        return page("project.list",Map.of(),offset,limit,BackendServices::project);
    }
    /** Для этого проекта требуется project:read. */
    public Project project(String projectId)throws IOException,InterruptedException {
        Project p=project(record(call("project.get",request(projectId)),"project"));
        checkScope(projectId,p.id());return p;
    }
    /** Для этого проекта требуется project:read. */
    public Page<Profile> profiles(String projectId,int offset,int limit)throws IOException,InterruptedException {
        return page("profile.list",request(projectId),offset,limit,BackendServices::profile);
    }
    public Profile profile(String projectId,String profileId)throws IOException,InterruptedException {
        Map<String,Object> req=Map.of("projectId",id(projectId,"projectId"),"profileId",id(profileId,"profileId"));
        Profile p=profile(record(call("profile.get",req),"profile"));checkScope(projectId,p.projectId());return p;
    }
    /** Для этого проекта требуется release:read. */
    public Page<Channel> channels(String projectId,int offset,int limit)throws IOException,InterruptedException {
        return page("channel.list",request(projectId),offset,limit,BackendServices::channel);
    }
    public Channel channel(String projectId,String name)throws IOException,InterruptedException {
        Map<String,Object> req=Map.of("projectId",id(projectId,"projectId"),"name",id(name,"name"));
        Channel c=channel(record(call("channel.get",req),"channel"));checkScope(projectId,c.projectId());return c;
    }
    /** Ограниченная альтернатива устаревшему release.list без постраничной выдачи. */
    public Page<Release> releases(String projectId,int offset,int limit)throws IOException,InterruptedException {
        return page("release.page",request(projectId),offset,limit,BackendServices::release);
    }
    public Release release(String projectId,String releaseId)throws IOException,InterruptedException {
        Map<String,Object> req=Map.of("projectId",id(projectId,"projectId"),"name",id(releaseId,"releaseId"));
        Release r=release(record(call("release.get",req),"release"));checkScope(projectId,r.projectId());return r;
    }
    /** Чтение только сохранённого состояния задания; требуется project:read. Задание без соответствующего проекта недоступно. */
    public Job job(String projectId,String jobId)throws IOException,InterruptedException {
        Map<String,Object> req=Map.of("projectId",id(projectId,"projectId"),"name",id(jobId,"jobId"));
        Job j=job(record(call("job.get",req),"job"));checkScope(projectId,j.projectId());return j;
    }
}

package ru.neverlauncher.sdk.core;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/** Fail-closed opt-in Sentry exception reporting for hosted Java extensions.
 * No exception messages, arguments, secrets, usernames, environment or raw paths are serialized.
 */
public final class SentryDiagnostics {
    private SentryDiagnostics() {}
    private static final Pattern IDENT = Pattern.compile("[A-Za-z_$][A-Za-z0-9_.$]{0,190}");
    private static final Pattern FILE = Pattern.compile("[A-Za-z0-9_.-]{1,120}");
    public static void installFromEnvironment(Map<String,String> env) {
        if (!"true".equalsIgnoreCase(env.getOrDefault("NEVERLAUNCHER_SENTRY_JVM_ENABLED","false"))) return;
        String dsn = env.get("NEVERLAUNCHER_SENTRY_JVM_DSN");
        if (dsn == null || dsn.isBlank()) return;
        Destination destination = Destination.parse(dsn);
        String release = env.getOrDefault("NEVERLAUNCHER_SENTRY_RELEASE","neverlauncher@0.30.9");
        if (!release.matches("[A-Za-z0-9_.@+\\-]{1,128}")) throw new IllegalArgumentException("invalid Sentry release");
        Thread.UncaughtExceptionHandler original = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, failure) -> {
            // Preserve the JVM's standard diagnostic/exit behavior.
            if (original != null) original.uncaughtException(thread,failure);
            else {System.err.println("Java extension failed: " + failure.getClass().getSimpleName());}
            try {send(destination,release,failure);} catch (Exception ignored) { /* diagnostics never hide failure */ }
        });
    }
    private record Destination(String dsn,String endpoint,String key) {
        static Destination parse(String dsn) {
            URI uri = URI.create(dsn);
            String user = uri.getRawUserInfo();
            if (user == null || user.isBlank() || user.contains(":") || uri.getHost()==null || uri.getRawQuery()!=null || uri.getRawFragment()!=null)
                throw new IllegalArgumentException("invalid Sentry DSN");
            if (!"https".equals(uri.getScheme()) && !("http".equals(uri.getScheme()) &&
                  ("localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "::1".equals(uri.getHost()))))
                throw new IllegalArgumentException("Sentry requires HTTPS");
            String rawPath = uri.getRawPath();
            if(rawPath==null || !rawPath.matches("(?:/[A-Za-z0-9_-]+)*/[0-9]{1,20}")) throw new IllegalArgumentException("invalid Sentry project");
            int last=rawPath.lastIndexOf('/');
            String endpoint=uri.getScheme()+"://"+uri.getRawAuthority().substring(uri.getRawAuthority().indexOf('@')+1)+rawPath.substring(0,last)+"/api/"+rawPath.substring(last+1)+"/envelope/";
            if (!user.matches("[A-Za-z0-9]{1,128}")) throw new IllegalArgumentException("invalid Sentry public key");
            return new Destination(dsn,endpoint,user);
        }
    }
    /** Can be called by exception boundaries which catch and rethrow failures. */
    public static void report(Throwable failure,Map<String,String> env) {
        if (!"true".equalsIgnoreCase(env.getOrDefault("NEVERLAUNCHER_SENTRY_JVM_ENABLED","false"))) return;
        String dsn=env.get("NEVERLAUNCHER_SENTRY_JVM_DSN");if(dsn==null||dsn.isBlank())return;
        String release=env.getOrDefault("NEVERLAUNCHER_SENTRY_RELEASE","neverlauncher@0.30.9");
        if(!release.matches("[A-Za-z0-9_.@+\\-]{1,128}"))return;
        try {send(Destination.parse(dsn),release,failure);} catch(Exception ignored) { /* fail open game / preserve original throwable */ }
    }
    private static void send(Destination dest,String release,Throwable failure) throws Exception {
        String name=failure.getClass().getName();
        if(!IDENT.matcher(name).matches())name="RuntimeException";
        List<Map<String,Object>> frames=new ArrayList<>();
        for(StackTraceElement f: failure.getStackTrace()) {
            if(frames.size()==24)break;
            if(!IDENT.matcher(f.getClassName()).matches() || !IDENT.matcher(f.getMethodName()).matches())continue;
            Map<String,Object> item=new LinkedHashMap<>();
            item.put("function",f.getClassName()+"."+f.getMethodName());
            if(f.getFileName()!=null && FILE.matcher(f.getFileName()).matches())item.put("filename",f.getFileName());
            if(f.getLineNumber()>0)item.put("lineno",f.getLineNumber());
            frames.add(item);
        }
        Collections.reverse(frames); // Sentry expects oldest frame first.
        String id=UUID.randomUUID().toString().replace("-","");
        Map<String,Object> event=new LinkedHashMap<>();
        event.put("event_id",id);event.put("timestamp",Instant.now().toString());event.put("platform","java");event.put("level","error");event.put("release",release);
        event.put("exception",Map.of("values",List.of(Map.of("type",name,"value","Hosted JVM extension failed","stacktrace",Map.of("frames",frames)))));
        event.put("sdk",Map.of("name","neverlauncher.jvm","version","0.30.9"));
        String envelope=Json.encode(Map.of("event_id",id,"dsn",dest.dsn))+"\n"+Json.encode(Map.of("type","event"))+"\n"+Json.encode(event)+"\n";
        HttpRequest request=HttpRequest.newBuilder(URI.create(dest.endpoint)).timeout(Duration.ofSeconds(3))
            .header("Content-Type","application/x-sentry-envelope")
            .header("X-Sentry-Auth","Sentry sentry_version=7,sentry_client=neverlauncher.jvm/0.30.9,sentry_key="+dest.key)
            .POST(HttpRequest.BodyPublishers.ofString(envelope)).build();
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build().send(request,HttpResponse.BodyHandlers.discarding());
    }
}

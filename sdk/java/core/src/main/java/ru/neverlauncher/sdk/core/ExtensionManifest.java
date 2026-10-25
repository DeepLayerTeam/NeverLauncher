package ru.neverlauncher.sdk.core;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Pattern;

/** Reads the actual NeverExtensions 2.0 signed-package manifest format; does not replace package signature verification. */
public record ExtensionManifest(String id, String name, SemVer version, String versionText, String publisher, String api,
        List<Target> targets, Set<String> permissions, List<String> hooks,
        List<Dependency> dependencies, List<Conflict> conflicts) {
    public record Target(String kind, String entrypoint) {}
    public record Dependency(String id, String range, boolean optional) {}
    public record Conflict(String id, String range) {}
    private static final Pattern ID=Pattern.compile("^[a-z0-9][a-z0-9._-]{2,127}$");
    private static final Set<String> KEYS=Set.of("schemaVersion","id","name","version","publisher","description","homepage","repository","api","targets","permissions","hooks","dependencies","conflicts","metadata","admin","desktop","cli");
    public ExtensionManifest {
        targets=List.copyOf(targets);permissions=Set.copyOf(permissions);hooks=List.copyOf(hooks);
        dependencies=List.copyOf(dependencies);conflicts=List.copyOf(conflicts);
    }
    public static ExtensionManifest load(Path file) throws IOException {
        if (Files.size(file)>1_048_576)throw new IOException("manifest exceeds 1 MiB");
        return parse(Files.readString(file,StandardCharsets.UTF_8));
    }
    public static ExtensionManifest parse(String json) {
        Map<String,Object> m=Json.object(Json.parse(json));
        for(String key:m.keySet())if(!KEYS.contains(key))throw new IllegalArgumentException("unknown manifest key: "+key);
        if(!"2.0".equals(Json.string(m,"schemaVersion",true)))throw new IllegalArgumentException("manifest schema must be 2.0");
        String id=ident(Json.string(m,"id",true)),api=Json.string(m,"api",true);
        if(Json.string(m,"name",true).length()>160||Json.string(m,"publisher",true).length()>160)throw new IllegalArgumentException("manifest name or publisher too long");
        if(!api.equals("1.0")&&!api.equals("3.7"))throw new IllegalArgumentException("unsupported extension API: "+api);
        List<Target> targets=new ArrayList<>();Set<String> kinds=new HashSet<>();
        for(Map<String,Object> t:records(m,"targets",true)){
            checkKeys(t,Set.of("kind","entrypoint"));
            String kind=Json.string(t,"kind",true);String entry=Json.string(t,"entrypoint",true);
            if(!Set.of("backend","admin","desktop","cli").contains(kind)||!kinds.add(kind))throw new IllegalArgumentException("invalid or duplicate target: "+kind);
            if(entry.chars().anyMatch(c->c<32)||entry.startsWith("/")||entry.contains("\\")||Arrays.stream(entry.split("/",-1)).anyMatch(x->x.isEmpty()||x.equals(".")||x.equals("..")))throw new IllegalArgumentException("unsafe entrypoint path");
            targets.add(new Target(kind,entry));
        }
        if(targets.isEmpty())throw new IllegalArgumentException("at least one target required");
        for(String value:strings(m,"permissions"))nameToken(value,"permission");
        for(String value:strings(m,"hooks"))nameToken(value,"hook");
        Set<String> perms=new LinkedHashSet<>(strings(m,"permissions"));
        if(perms.size()!=strings(m,"permissions").size())throw new IllegalArgumentException("duplicate permissions");
        List<Dependency> deps=new ArrayList<>();Set<String> used=new HashSet<>();
        for(Map<String,Object> d:records(m,"dependencies",false)){
            checkKeys(d,Set.of("id","version","optional"));String dep=ident(Json.string(d,"id",true));
            if(!used.add(dep)||dep.equals(id))throw new IllegalArgumentException("duplicate/self dependency: "+dep);
            String range=Json.string(d,"version",true);validateRange(range);
            Object opt=d.getOrDefault("optional",false);if(!(opt instanceof Boolean))throw new IllegalArgumentException("optional must be boolean");
            deps.add(new Dependency(dep,range,(Boolean)opt));
        }
        List<Conflict> conflicts=new ArrayList<>();used.clear();
        for(Map<String,Object> c:records(m,"conflicts",false)){
            checkKeys(c,Set.of("id","version"));String other=ident(Json.string(c,"id",true));
            if(!used.add(other)||other.equals(id))throw new IllegalArgumentException("duplicate/self conflict: "+other);
            String range=Json.string(c,"version",true);validateRange(range);
            conflicts.add(new Conflict(other,range));
        }
        return new ExtensionManifest(id,Json.string(m,"name",true),SemVer.parse(Json.string(m,"version",true)),Json.string(m,"version",true),Json.string(m,"publisher",true),api,targets,perms,strings(m,"hooks"),deps,conflicts);
    }
    private static void nameToken(String token,String kind){if(!token.matches("[a-z0-9][a-z0-9._:-]{1,127}"))throw new IllegalArgumentException("invalid "+kind+": "+token);}
    private static String ident(String v){if(!ID.matcher(v).matches())throw new IllegalArgumentException("invalid extension id: "+v);return v;}
    private static void validateRange(String range){new SemVer(1,2,3,List.of()).matches(range);}
    private static void checkKeys(Map<String,Object> m,Set<String> allowed){for(String k:m.keySet())if(!allowed.contains(k))throw new IllegalArgumentException("unknown field: "+k);}
    private static List<Map<String,Object>> records(Map<String,Object> m,String key,boolean required){
        Object obj=m.get(key);if(obj==null&&!required)return List.of();
        if(!(obj instanceof List<?> list))throw new IllegalArgumentException(key+" must be an array");
        if(list.size()>2048)throw new IllegalArgumentException(key+" too large");
        List<Map<String,Object>> result=new ArrayList<>();for(Object value:list)result.add(Json.object(value));return result;
    }
    private static List<String> strings(Map<String,Object> m,String key){
        Object obj=m.get(key);if(obj==null)return List.of();if(!(obj instanceof List<?> list))throw new IllegalArgumentException(key+" must be an array");
        if(list.size()>2048)throw new IllegalArgumentException(key+" too large");
        List<String> result=new ArrayList<>();for(Object value:list){if(!(value instanceof String s)||s.isBlank())throw new IllegalArgumentException("invalid "+key+" entry");result.add(s);}return result;
    }
}

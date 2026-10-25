package ru.neverlauncher.sdk.core;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Typed command registry for Java CLI targets and authenticated callbacks. */
public final class RuntimeCommands {
    @FunctionalInterface public interface Decoder<T>{T decode(Object json)throws Exception;}
    @FunctionalInterface public interface Handler<T>{Object execute(T arguments)throws Exception;}
    private record Entry<T>(JsonSchema schema,Decoder<T> decoder,Handler<T> handler){}
    private final Map<String,Entry<?>> handlers=new ConcurrentHashMap<>();
    private final Set<String> declared;
    RuntimeCommands(Set<String> declared){this.declared=Set.copyOf(declared);}
    public <T> void register(String name,JsonSchema schema,Decoder<T> decoder,Handler<T> handler){
        if(!name.matches("[a-z][a-z0-9_-]{0,63}"))throw new IllegalArgumentException("invalid command name");
        if(!declared.contains(name))throw new SecurityException("command is absent from signed cli manifest: "+name);
        if(handlers.putIfAbsent(name,new Entry<>(schema,Objects.requireNonNull(decoder),Objects.requireNonNull(handler)))!=null)throw new IllegalArgumentException("duplicate command: "+name);
    }
    @SuppressWarnings("unchecked")
    public Object invoke(String name,Object payload)throws Exception {
        Entry<?> entry=handlers.get(name);if(entry==null)throw new IllegalArgumentException("unregistered command: "+name);
        return run((Entry<Object>)entry,payload);
    }
    private static <T> Object run(Entry<T> entry,Object payload)throws Exception {
        if(entry.schema()!=null)entry.schema().validate(payload);
        Object result=entry.handler().execute(entry.decoder().decode(payload));
        if(Json.encode(result).length()>64<<10)throw new IllegalArgumentException("command output too large");
        return result;
    }
}

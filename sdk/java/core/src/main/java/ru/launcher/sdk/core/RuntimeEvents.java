package ru.launcher.sdk.core;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Typed, validated callbacks delivered by the existing Extensions EventBus. */
public final class RuntimeEvents implements AutoCloseable {
    @FunctionalInterface public interface Decoder<T>{T decode(Object json)throws Exception;}
    @FunctionalInterface public interface Listener<T>{void onEvent(Envelope<T> event)throws Exception;}
    public record Envelope<T>(String id,String type,String projectId,String idempotencyKey,T payload){}
    private record Binding<T>(JsonSchema schema,Decoder<T> decoder,Listener<T> listener){}
    private final HostSession host;
    private final Map<String,Binding<?>> handlers=new ConcurrentHashMap<>();
    // These IDs belong to the durable backend EventBus, not to the JVM process.
    // Removing them on normal shutdown loses events published during downtime.
    private final Map<String,Long> subscriptions=new HashMap<>();
    private boolean closed;
    RuntimeEvents(HostSession host){this.host=host;}
    public synchronized <T> long subscribe(String eventType,String mode,JsonSchema schema,Decoder<T> decoder,Listener<T> listener)throws IOException,InterruptedException {
        if(closed)throw new IllegalStateException("runtime events closed");
        if(!eventType.matches("[a-z][a-z0-9.-]{1,127}")||!Set.of("async","sync").contains(mode))throw new IllegalArgumentException("invalid event subscription");
        Objects.requireNonNull(decoder);Objects.requireNonNull(listener);
        host.requireEvent(eventType);
        String key=eventType+":"+mode;
        if(handlers.putIfAbsent(key,new Binding<>(schema,decoder,listener))!=null)throw new IllegalArgumentException("duplicate event subscription: "+key);
        try{
            Map<String,Object> response=host.subscribe(eventType,mode);
            Object id=response.get("id");if(!(id instanceof Number number)||number.longValue()<1)throw new IOException("host returned invalid subscription id");
            subscriptions.put(key,number.longValue());return number.longValue();
        }catch(IOException|InterruptedException|RuntimeException e){handlers.remove(key);throw e;}
    }
    @SuppressWarnings("unchecked")
    void deliver(Map<String,Object> data,boolean sync)throws Exception {
        if(!"1.0".equals(data.get("protocolVersion")))throw new IllegalArgumentException("event protocol mismatch");
        var sub=Json.object(data.get("subscription"));var raw=Json.object(data.get("event"));
        String type=Json.string(raw,"type",true),mode=Json.string(sub,"mode",true);
        if(!type.equals(sub.get("eventType"))||!mode.equals(sync?"sync":"async"))throw new IllegalArgumentException("event subscription mismatch");
        Binding<?> binding=handlers.get(type+":"+mode);
        if(binding==null)throw new IllegalArgumentException("no event handler for "+type+":"+mode);
        run((Binding<Object>)binding,new Envelope<>(Json.string(raw,"id",true),type,Json.string(raw,"projectId",false),Json.string(raw,"idempotencyKey",false),raw.get("payload")));
    }
    private static <T> void run(Binding<T> binding,Envelope<Object> raw)throws Exception {
        if(binding.schema()!=null)binding.schema().validate(raw.payload());
        binding.listener().onEvent(new Envelope<>(raw.id(),raw.type(),raw.projectId(),raw.idempotencyKey(),binding.decoder().decode(raw.payload())));
    }
    /**
     * Permanently remove a subscription from the durable event queue. Use this
     * only when the extension explicitly stops consuming an event type.
     * Shutdown, upgrade and temporary outages must use close() instead.
     */
    public synchronized void unsubscribe(String eventType,String mode)throws IOException,InterruptedException {
        String key=eventType+":"+mode;
        Long id=subscriptions.get(key);
        if(id==null)throw new IllegalArgumentException("subscription is not registered: "+key);
        host.unsubscribe(id);
        subscriptions.remove(key);
        handlers.remove(key);
    }
    /** Shut down local handlers; retain backend subscriptions and their backlog. */
    @Override public synchronized void close(){closed=true;handlers.clear();subscriptions.clear();}
}

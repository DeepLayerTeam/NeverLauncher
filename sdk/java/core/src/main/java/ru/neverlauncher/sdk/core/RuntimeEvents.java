package ru.neverlauncher.sdk.core;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Typed, validated callbacks delivered by the existing NeverExtensions EventBus. */
public final class RuntimeEvents implements AutoCloseable {
    @FunctionalInterface public interface Decoder<T>{T decode(Object json)throws Exception;}
    @FunctionalInterface public interface Listener<T>{void onEvent(Envelope<T> event)throws Exception;}
    public record Envelope<T>(String id,String type,String projectId,String idempotencyKey,T payload){}
    private record Binding<T>(JsonSchema schema,Decoder<T> decoder,Listener<T> listener){}
    private final HostSession host;
    private final Map<String,Binding<?>> handlers=new ConcurrentHashMap<>();
    private final List<Long> subscriptions=Collections.synchronizedList(new ArrayList<>());
    RuntimeEvents(HostSession host){this.host=host;}
    public <T> long subscribe(String eventType,String mode,JsonSchema schema,Decoder<T> decoder,Listener<T> listener)throws IOException,InterruptedException {
        if(!eventType.matches("[a-z][a-z0-9.-]{1,127}")||!Set.of("async","sync").contains(mode))throw new IllegalArgumentException("invalid event subscription");
        Objects.requireNonNull(decoder);Objects.requireNonNull(listener);
        String key=eventType+":"+mode;
        if(handlers.putIfAbsent(key,new Binding<>(schema,decoder,listener))!=null)throw new IllegalArgumentException("duplicate event subscription: "+key);
        try{
            Map<String,Object> response=host.subscribe(eventType,mode);
            Object id=response.get("id");if(!(id instanceof Number number)||number.longValue()<1)throw new IOException("host returned invalid subscription id");
            subscriptions.add(number.longValue());return number.longValue();
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
    @Override public void close(){synchronized(subscriptions){for(long id:subscriptions)try{host.unsubscribe(id);}catch(Exception ignored){/* host process cleanup removes subscriptions */}subscriptions.clear();}handlers.clear();}
}

package ru.launcher.sdk.core;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Постоянные задания событий с доставкой как минимум один раз и хуки политик с отказом по умолчанию через Go EventBus. */
public final class RuntimeEvents implements AutoCloseable {
    @FunctionalInterface public interface Decoder<T>{T decode(Object json)throws Exception;}
    @FunctionalInterface public interface Listener<T>{void onEvent(Envelope<T> event)throws Exception;}
    @FunctionalInterface public interface DetailedListener<T>{void onEvent(DetailedEnvelope<T> event)throws Exception;}
    @FunctionalInterface public interface Hook<T>{HookDecision evaluate(DetailedEnvelope<T> event)throws Exception;}
    @FunctionalInterface public interface AsyncJob<T>{void execute(DetailedEnvelope<T> event)throws Exception;}
    public record Envelope<T>(String id,String type,String projectId,String idempotencyKey,T payload){}
    public record Metadata(long sequence,int schemaVersion,String aggregateType,String aggregateId,
        String orderingKey,String source,String payloadSha256,String occurredAt){}
    public record DetailedEnvelope<T>(Envelope<T> event,Metadata metadata){}
    public record HookDecision(boolean allowed,String reason){
        public HookDecision {reason=reason==null?"":reason;
            if(reason.length()>512)throw new IllegalArgumentException("Причина перехвата длиннее 512 символов");}
        public static HookDecision allow(){return new HookDecision(true,"");}
        public static HookDecision deny(String reason){return new HookDecision(false,reason);}
    }
    /** Намеренный отказ от события без повторной попытки. Go-шина переносит его в очередь недоставленных сообщений. */
    public static final class PermanentFailure extends Exception {
        public PermanentFailure(String reason){super(reason);}
    }
    /** Запрет политики. Go прерывает защищённую операцию; событие нельзя подтвердить ACK как принятое. */
    public static final class HookRejected extends Exception {
        public HookRejected(String reason){super(reason);}
    }
    private record Binding<T>(JsonSchema schema,Decoder<T> decoder,DetailedListener<T> listener){}
    private final HostSession host;
    private final Map<String,Binding<?>> handlers=new ConcurrentHashMap<>();
    private final Map<String,Long> subscriptions=new HashMap<>();
    private boolean closed;
    RuntimeEvents(HostSession host){this.host=host;}
    public <T> long subscribe(String eventType,String mode,JsonSchema schema,Decoder<T> decoder,Listener<T> listener)throws IOException,InterruptedException {
        Objects.requireNonNull(listener);
        return subscribeDetailed(eventType,mode,schema,decoder,details->listener.onEvent(details.event()));
    }
    /** Расширенная типизированная подписка; метаданные относятся к неизменяемой записи события Go. */
    public synchronized <T> long subscribeDetailed(String eventType,String mode,JsonSchema schema,Decoder<T> decoder,DetailedListener<T> listener)throws IOException,InterruptedException {
        if(closed)throw new IllegalStateException("Приём событий среды выполнения закрыт");
        if(eventType==null||!eventType.matches("[a-z][a-z0-9.-]{1,127}")||!Set.of("async","sync").contains(mode))throw new IllegalArgumentException("Некорректная подписка на события");
        Objects.requireNonNull(decoder);Objects.requireNonNull(listener);
        host.requireEvent(eventType);
        String key=eventType+":"+mode;
        if(handlers.putIfAbsent(key,new Binding<>(schema,decoder,listener))!=null)throw new IllegalArgumentException("Повторяющаяся подписка на события: "+key);
        try{
            Map<String,Object> response=host.subscribe(eventType,mode);
            Object id=response.get("id");if(!(id instanceof Number number)||number.longValue()<1)throw new IOException("Хост вернул некорректный идентификатор подписки");
            subscriptions.put(key,number.longValue());return number.longValue();
        }catch(IOException|InterruptedException|RuntimeException e){handlers.remove(key);throw e;}
    }
    /** Асинхронное задание получает долговременную аренду, повторные попытки и отправку в dead-letter через Go EventBus. */
    public <T> long subscribeJob(String eventType,JsonSchema schema,Decoder<T> decoder,AsyncJob<T> job)throws IOException,InterruptedException {
        Objects.requireNonNull(job);
        return subscribeDetailed(eventType,"async",schema,decoder,job::execute);
    }
    /** Синхронный хук политики обязан явно разрешить изменение; null и исключения означают запрет. */
    public <T> long subscribeHook(String eventType,JsonSchema schema,Decoder<T> decoder,Hook<T> hook)throws IOException,InterruptedException {
        Objects.requireNonNull(hook);
        return subscribeDetailed(eventType,"sync",schema,decoder,event->{
            HookDecision decision=hook.evaluate(event);
            if(decision==null||!decision.allowed())throw new HookRejected(decision==null?"Хук не вернул решение":decision.reason());
        });
    }
    @SuppressWarnings("unchecked")
    void deliver(Map<String,Object> data,boolean sync)throws Exception {
        if(!"1.0".equals(data.get("protocolVersion")))throw new IllegalArgumentException("Версия протокола событий не совпадает");
        var sub=Json.object(data.get("subscription"));var raw=Json.object(data.get("event"));
        String type=Json.string(raw,"type",true),mode=Json.string(sub,"mode",true);
        if(!type.equals(sub.get("eventType"))||!mode.equals(sync?"sync":"async"))throw new IllegalArgumentException("Подписка на события не совпадает");
        Binding<?> binding=handlers.get(type+":"+mode);
        if(binding==null)throw new IllegalArgumentException("Нет обработчика события для "+type+":"+mode);
        String id=Json.string(raw,"id",true);
        if(id.isBlank()||id.length()>128)throw new IllegalArgumentException("Недопустимый идентификатор события");
        Envelope<Object> event=new Envelope<>(id,type,Json.string(raw,"projectId",false),Json.string(raw,"idempotencyKey",false),raw.get("payload"));
        int schemaVersion=boundedInt(raw.get("schemaVersion"),1,1,1024);
        long sequence=boundedLong(raw.get("sequence"),0,0,Long.MAX_VALUE);
        Metadata metadata=new Metadata(sequence,schemaVersion,opt(raw,"aggregateType"),opt(raw,"aggregateId"),opt(raw,"orderingKey"),opt(raw,"source"),opt(raw,"payloadSha256"),opt(raw,"occurredAt"));
        run((Binding<Object>)binding,new DetailedEnvelope<>(event,metadata));
    }
    private static int boundedInt(Object raw,int fallback,int min,int max){long n=boundedLong(raw,fallback,min,max);return (int)n;}
    private static long boundedLong(Object raw,long fallback,long min,long max){
        if(raw==null)return fallback;
        if(!(raw instanceof Number n)||n.longValue()<min||n.longValue()>max||n.doubleValue()!=n.longValue())throw new IllegalArgumentException("Недопустимое числовое значение метаданных события");
        return n.longValue();
    }
    private static String opt(Map<String,Object> raw,String key){
        Object v=raw.get(key);if(v==null)return "";if(!(v instanceof String s)||s.length()>2048)throw new IllegalArgumentException("Некорректные метаданные события "+key);return s;
    }
    private static <T> void run(Binding<T> binding,DetailedEnvelope<Object> raw)throws Exception {
        if(binding.schema()!=null)binding.schema().validate(raw.event().payload());
        Envelope<T> typed=new Envelope<>(raw.event().id(),raw.event().type(),raw.event().projectId(),raw.event().idempotencyKey(),binding.decoder().decode(raw.event().payload()));
        binding.listener().onEvent(new DetailedEnvelope<>(typed,raw.metadata()));
    }
    public synchronized void unsubscribe(String eventType,String mode)throws IOException,InterruptedException {
        String key=eventType+":"+mode;
        Long id=subscriptions.get(key);
        if(id==null)throw new IllegalArgumentException("Подписка не зарегистрирована: "+key);
        host.unsubscribe(id);
        subscriptions.remove(key);handlers.remove(key);
    }
    /** Локальное завершение никогда не удаляет ожидающую работу из постоянного Go-хранилища. */
    @Override public synchronized void close(){closed=true;handlers.clear();subscriptions.clear();}
}

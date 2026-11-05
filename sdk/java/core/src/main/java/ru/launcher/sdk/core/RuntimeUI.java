package ru.launcher.sdk.core;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Реальные обработчики Admin/Desktop, вызываемые через аутентифицированный брокер Go -> JVM.
 * Страницы остаются изолированными; в эти Java-обработчики поступают только подписанные ID действий.
 */
public final class RuntimeUI implements AutoCloseable {
    @FunctionalInterface public interface Action { Object invoke(Map<String,Object> actor, Object payload) throws Exception; }
    private record Binding(JsonSchema schema, Action handler) {}
    private record Setting(JsonSchema schema, Object fallback) {}
    private final Map<String,Binding> actions=new ConcurrentHashMap<>();
    private final Map<String,Setting> settings=new ConcurrentHashMap<>();
    private final Map<String,Set<String>> declared;
    private final RuntimeDocuments config;
    private volatile boolean closed;

    RuntimeUI(RuntimeDocuments config,Map<String,Set<String>> declared){
        this.config=Objects.requireNonNull(config);
        var copy=new HashMap<String,Set<String>>();
        for(var e:declared.entrySet())copy.put(e.getKey(),Set.copyOf(e.getValue()));
        this.declared=Map.copyOf(copy);
    }
    private static String surface(String value){
        if(!"admin".equals(value)&&!"desktop".equals(value))throw new IllegalArgumentException("Некорректная область интерфейса");
        return value;
    }
    private static String token(String value){
        if(value==null||!value.matches("[a-z][a-z0-9_-]{0,63}"))throw new IllegalArgumentException("Некорректный идентификатор интерфейса");
        return value;
    }
    private void active(){if(closed)throw new IllegalStateException("Среда выполнения интерфейса закрыта");}
    public synchronized void registerAction(String target,String actionId,JsonSchema schema,Action handler){
        active();String key=surface(target)+":"+token(actionId);
        if(!declared.getOrDefault(target,Set.of()).contains(actionId))throw new SecurityException("Действие отсутствует в подписанных элементах "+target+" contributions");
        if(actions.putIfAbsent(key,new Binding(schema,Objects.requireNonNull(handler)))!=null)throw new IllegalArgumentException("Повторяющееся действие интерфейса");
    }
    /** Каждый параметр должен быть явно зарегистрирован в Java и сохранён в существующей конфигурации расширения. */
    public synchronized void registerSetting(String target,String name,JsonSchema schema,Object fallback){
        active();String key=surface(target)+":"+token(name);
        Objects.requireNonNull(schema,"Для настроек необходима схема");
        if(fallback!=null)schema.validate(fallback);
        if(settings.putIfAbsent(key,new Setting(schema,fallback))!=null)throw new IllegalArgumentException("Повторяющаяся настройка интерфейса");
    }
    Object invoke(String method,Map<String,Object> request)throws Exception {
        active();String target=surface(Json.string(request,"surface",true));
        if("ui.action.invoke".equals(method)){
            String action=token(Json.string(request,"actionId",true));
            Binding binding=actions.get(target+":"+action);
            if(binding==null)throw new IllegalArgumentException("Незарегистрированное действие интерфейса");
            Object payload=request.get("payload");
            if(binding.schema()!=null)binding.schema().validate(payload);
            Map<String,Object> actor=Map.copyOf(Json.object(request.get("actor")));
            String id=Json.string(actor,"id",true);
            if(id.length()>160)throw new IllegalArgumentException("Некорректный исполнитель");
            Object answer=binding.handler().invoke(actor,payload);
            if(Json.encode(answer).getBytes(java.nio.charset.StandardCharsets.UTF_8).length>48*1024)throw new IllegalArgumentException("Размер ответа интерфейса превышает ограничение");
            return answer;
        }
        String name=token(Json.string(request,"key",true));
        Setting setting=settings.get(target+":"+name);
        if(setting==null)throw new IllegalArgumentException("Незарегистрированная настройка интерфейса");
        String storageKey="ui."+target+"."+name;
        if("ui.settings.get".equals(method)){
            Object value=config.get(storageKey,setting.schema()).orElse(setting.fallback());
            return Map.of("key",name,"value",value==null?"":value);
        }
        if("ui.settings.put".equals(method)){
            Object value=Objects.requireNonNull(request.get("value"),"Значение null в JSON настроек не поддерживается");
            setting.schema().validate(value);
            config.put(storageKey,value,setting.schema());
            return Map.of("saved",true,"key",name);
        }
        throw new IllegalArgumentException("Неизвестный метод интерфейса");
    }
    @Override public synchronized void close(){closed=true;actions.clear();settings.clear();}
}

package ru.launcher.sdk.core;

import java.util.*;

/** Версионированные синхронные миграции сохранённых JSON-документов расширения.
 * Регистрировать при Extension.start(); никогда не изменять состояние другого расширения.
 * Менеджер обновлений Go создаёт контрольную копию документов перед вызовом этих миграций
 * и восстанавливает её, если обновление или проверка работоспособности завершатся неудачно.
 */
public final class RuntimeStateMigrations {
    @FunctionalInterface public interface Migration {
        void apply(RuntimeDocuments config, RuntimeDocuments storage) throws Exception;
    }
    private record Step(SemVer target, Migration migration) {}
    private final RuntimeDocuments config,storage;
    private final Map<SemVer,Step> steps=new HashMap<>();
    private boolean executing;

    RuntimeStateMigrations(RuntimeDocuments config,RuntimeDocuments storage){this.config=config;this.storage=storage;}
    public synchronized void register(String fromVersion,String toVersion,Migration migration){
        if(executing)throw new IllegalStateException("cannot register migrations while upgrading");
        SemVer from=SemVer.parse(fromVersion),to=SemVer.parse(toVersion);
        if(from.compareTo(to)>=0)throw new IllegalArgumentException("state migrations must advance versions");
        Objects.requireNonNull(migration,"migration");
        if(steps.putIfAbsent(from,new Step(to,migration))!=null)
            throw new IllegalArgumentException("duplicate migration starting at "+from);
    }
    /** Вызывается только аутентифицированным хостом при обновлении после остановки старой версии. */
    synchronized Map<String,Object> apply(String fromVersion,String toVersion) throws Exception {
        SemVer from=SemVer.parse(fromVersion),target=SemVer.parse(toVersion);
        if(from.compareTo(target)>=0)throw new IllegalArgumentException("migration requires increasing versions");
        if(executing)throw new IllegalStateException("concurrent state migration");
        executing=true;
        try{
            // Расширениям с прежней JSON-схемой миграция не нужна. Если зарегистрирован
            // граф миграций, каждый переход должен быть полным.
            if(steps.isEmpty())return Map.of("applied",false,"fromVersion",fromVersion,"toVersion",toVersion);
            SemVer cursor=from;
            int applied=0;
            while(cursor.compareTo(target)<0){
                if(++applied>32)throw new IllegalStateException("state migration chain too long");
                Step step=steps.get(cursor);
                if(step==null||step.target.compareTo(target)>0)
                    throw new IllegalStateException("missing state migration from "+cursor+" to "+target);
                step.migration.apply(config,storage);
                cursor=step.target;
            }
            return Map.of("applied",true,"steps",applied,"fromVersion",fromVersion,"toVersion",toVersion);
        }finally{executing=false;}
    }
}

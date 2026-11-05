package pro.gravit.launcher.base.modules;
import java.util.*;

/** Подмножество API жизненного цикла/событий модулей Gravit на основе настоящего хоста Extensions. */
public abstract class LauncherModule {
    public static class Event {
        public boolean isCancel(){return false;}
        public void cancel(){throw new UnsupportedOperationException("Отмена Gravit не сопоставлена с асинхронными событиями расширений");}
    }
    @FunctionalInterface public interface EventHandler<T extends Event> { void event(T e); }
    public enum InitStatus { CREATED, PRE_INIT_WAIT, PRE_INIT, INIT_WAIT, INIT, FINISH }
    protected final LauncherModuleInfo moduleInfo;
    protected LauncherModulesManager modulesManager;
    protected InitStatus initStatus=InitStatus.CREATED;
    protected LauncherModule(){this(new LauncherModuleInfoBuilder().createLauncherModuleInfo());}
    protected LauncherModule(LauncherModuleInfo info){moduleInfo=Objects.requireNonNull(info);}
    public final LauncherModuleInfo getModuleInfo(){return moduleInfo;}
    public final InitStatus getInitStatus(){return initStatus;}
    public void preInitAction(){}
    public abstract void init(LauncherInitContext context);
    protected final <T extends Event> boolean registerEvent(EventHandler<T> handler,Class<T> type) {
        if(modulesManager==null||initStatus!=InitStatus.INIT)throw new IllegalStateException("registerEvent разрешён только во время инициализации");
        return modulesManager.registerEvent(type,handler);
    }
    /** Вызывается только загрузчиком совместимости, не недоверенным внешним кодом. */
    public final void initialize(LauncherModulesManager manager,LauncherInitContext context){
        if(initStatus!=InitStatus.CREATED)throw new IllegalStateException("Инициализация уже выполнена");
        modulesManager=Objects.requireNonNull(manager);initStatus=InitStatus.PRE_INIT_WAIT;
        try{initStatus=InitStatus.PRE_INIT;preInitAction();initStatus=InitStatus.INIT_WAIT;initStatus=InitStatus.INIT;init(context);initStatus=InitStatus.FINISH;}
        catch(RuntimeException|Error e){initStatus=InitStatus.CREATED;modulesManager=null;throw e;}
    }
}

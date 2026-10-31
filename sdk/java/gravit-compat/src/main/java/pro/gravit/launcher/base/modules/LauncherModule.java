package pro.gravit.launcher.base.modules;
import java.util.*;

/** Gravit module lifecycle/event API subset, backed by a real Extensions host. */
public abstract class LauncherModule {
    public static class Event {
        public boolean isCancel(){return false;}
        public void cancel(){throw new UnsupportedOperationException("Gravit cancellation is not mapped to Extensions async events");}
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
        if(modulesManager==null||initStatus!=InitStatus.INIT)throw new IllegalStateException("registerEvent only during init");
        return modulesManager.registerEvent(type,handler);
    }
    /** Called only by the compatibility bootstrap, not by untrusted external code. */
    public final void initialize(LauncherModulesManager manager,LauncherInitContext context){
        if(initStatus!=InitStatus.CREATED)throw new IllegalStateException("already initialized");
        modulesManager=Objects.requireNonNull(manager);initStatus=InitStatus.PRE_INIT_WAIT;
        try{initStatus=InitStatus.PRE_INIT;preInitAction();initStatus=InitStatus.INIT_WAIT;initStatus=InitStatus.INIT;init(context);initStatus=InitStatus.FINISH;}
        catch(RuntimeException|Error e){initStatus=InitStatus.CREATED;modulesManager=null;throw e;}
    }
}

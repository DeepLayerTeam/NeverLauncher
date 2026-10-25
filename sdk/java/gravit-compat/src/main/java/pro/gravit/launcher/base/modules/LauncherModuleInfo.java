package pro.gravit.launcher.base.modules;
import java.util.*;
import pro.gravit.utils.Version;

/** Fixed API subset; not the full Gravit modules manager. */
public final class LauncherModuleInfo {
    public final String name;
    public final Version version;
    public final int priority;
    public final String[] dependencies;
    public final String[] providers;
    public LauncherModuleInfo(String name,Version version,int priority,String[] dependencies,String[] providers){
        if(name==null||!name.matches("[A-Za-z][A-Za-z0-9_-]{1,63}"))throw new IllegalArgumentException("invalid module name");
        this.name=name;this.version=Objects.requireNonNull(version);this.priority=priority;
        this.dependencies=Objects.requireNonNull(dependencies).clone();this.providers=Objects.requireNonNull(providers).clone();
    }
}

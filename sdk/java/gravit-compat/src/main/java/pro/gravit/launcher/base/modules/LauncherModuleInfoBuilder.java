package pro.gravit.launcher.base.modules;
import pro.gravit.utils.Version;
public final class LauncherModuleInfoBuilder {
    private String name="UnknownModule";
    private Version version=new Version(0,0,0,0,Version.Type.DEV);
    private int priority;
    private String[] dependencies=new String[0],providers=new String[0];
    public LauncherModuleInfoBuilder setName(String value){name=value;return this;}
    public LauncherModuleInfoBuilder setVersion(Version value){version=value;return this;}
    public LauncherModuleInfoBuilder setPriority(int value){priority=value;return this;}
    public LauncherModuleInfoBuilder setDependencies(String[] value){dependencies=value.clone();return this;}
    public LauncherModuleInfoBuilder setProviders(String[] value){providers=value.clone();return this;}
    public LauncherModuleInfo createLauncherModuleInfo(){return new LauncherModuleInfo(name,version,priority,dependencies,providers);}
}

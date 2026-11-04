package ru.example.gravit;
import pro.gravit.launcher.base.modules.*;
/** Отрицательная фикстура: внутренние зависимости Gravit нужно переносить явно. */
public final class UnportedModule extends LauncherModule {
    public UnportedModule(){super(new LauncherModuleInfoBuilder().setName("UnportedModule").setDependencies(new String[]{"LaunchServerCore"}).createLauncherModuleInfo());}
    public void init(LauncherInitContext context){throw new AssertionError("an unresolved Gravit dependency must reject before init");}
}

package ru.example.gravit;
import pro.gravit.launcher.base.modules.*;
/** Отрицательная фикстура: не придумывайте сопоставления для посторонних событий Gravit. */
public final class UnsupportedEventModule extends LauncherModule {
    public static final class GravitInternalEvent extends Event {}
    public UnsupportedEventModule(){super(new LauncherModuleInfoBuilder().setName("UnsupportedEventModule").createLauncherModuleInfo());}
    public void init(LauncherInitContext context){registerEvent(event->{},GravitInternalEvent.class);}
}

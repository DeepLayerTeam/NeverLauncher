package ru.example.gravit;
import pro.gravit.launcher.base.modules.*;
/** Negative fixture: do not invent mappings for unrelated Gravit events. */
public final class UnsupportedEventModule extends LauncherModule {
    public static final class GravitInternalEvent extends Event {}
    public UnsupportedEventModule(){super(new LauncherModuleInfoBuilder().setName("UnsupportedEventModule").createLauncherModuleInfo());}
    public void init(LauncherInitContext context){registerEvent(event->{},GravitInternalEvent.class);}
}

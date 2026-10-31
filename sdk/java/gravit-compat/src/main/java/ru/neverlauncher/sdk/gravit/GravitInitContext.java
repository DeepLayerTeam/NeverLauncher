package ru.launcher.sdk.gravit;
import pro.gravit.launcher.base.modules.LauncherInitContext;
import pro.gravit.launcher.base.modules.LauncherModulesManager;
import ru.launcher.sdk.core.ExtensionContext;
/** Explicit Launcher host services, not a fake LaunchServer object. */
public record GravitInitContext(ExtensionContext extension,LauncherModulesManager manager) implements LauncherInitContext {}

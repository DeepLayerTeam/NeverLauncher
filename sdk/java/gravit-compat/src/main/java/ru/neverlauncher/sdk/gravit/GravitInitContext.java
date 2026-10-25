package ru.neverlauncher.sdk.gravit;
import pro.gravit.launcher.base.modules.LauncherInitContext;
import pro.gravit.launcher.base.modules.LauncherModulesManager;
import ru.neverlauncher.sdk.core.ExtensionContext;
/** Explicit NeverLauncher host services, not a fake LaunchServer object. */
public record GravitInitContext(ExtensionContext extension,LauncherModulesManager manager) implements LauncherInitContext {}

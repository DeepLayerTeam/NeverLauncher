package ru.launcher.sdk.gravit;
import pro.gravit.launcher.base.modules.LauncherInitContext;
import pro.gravit.launcher.base.modules.LauncherModulesManager;
import ru.launcher.sdk.core.ExtensionContext;
/** Явные сервисы хоста Launcher, а не фиктивный объект LaunchServer. */
public record GravitInitContext(ExtensionContext extension,LauncherModulesManager manager) implements LauncherInitContext {}

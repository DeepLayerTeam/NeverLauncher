package ru.neverlauncher.sdk.gravit;
import java.net.URI;
import java.util.*;
import java.util.jar.*;
import pro.gravit.launcher.base.modules.*;
import ru.neverlauncher.sdk.core.*;

/** Executable adapter for explicitly ported Gravit-style modules in signed .nlext JARs. */
public final class GravitCompatExtension implements Extension {
    private LauncherModule module;
    private volatile boolean initialized;
    @Override public void start(ExtensionContext context)throws Exception {
        URI code=GravitCompatExtension.class.getProtectionDomain().getCodeSource().getLocation().toURI();
        String className;
        try(JarFile jar=new JarFile(java.nio.file.Path.of(code).toFile())) {
            Attributes attrs=jar.getManifest().getMainAttributes();
            if(!GravitCompatExtension.class.getName().equals(attrs.getValue("NeverLauncher-Extension-Class")))throw new SecurityException("not a Gravit compatibility package");
            className=attrs.getValue("NeverLauncher-Gravit-Module-Class");
        }
        if(className==null||!className.matches("[a-zA-Z_$][a-zA-Z0-9_$.]{1,200}")||className.contains("..")||className.startsWith("pro.gravit.launcher.")||className.startsWith("ru.neverlauncher.sdk."))throw new SecurityException("invalid ported Gravit module class");
        Class<?> type=Class.forName(className,false,GravitCompatExtension.class.getClassLoader());
        if(!LauncherModule.class.isAssignableFrom(type)||java.lang.reflect.Modifier.isAbstract(type.getModifiers()))throw new SecurityException("class is not a concrete LauncherModule");
        module=(LauncherModule)type.getDeclaredConstructor().newInstance();
        LauncherModulesManager manager=new LauncherModulesManager(context.runtime());
        // Dependencies must be ported to NeverExtensions manifest: do not silently resolve Gravit internal modules.
        for(String dependency:module.getModuleInfo().dependencies) {
            if(dependency==null||!dependency.isBlank())throw new UnsupportedOperationException("Gravit internal dependency requires an explicit port: "+dependency);
        }
        module.initialize(manager,new GravitInitContext(context,manager));
        manager.activate();
        initialized=true;
    }
    @Override public void stop(ExtensionContext context)throws Exception {
        if(initialized&&module instanceof AutoCloseable closable)closable.close();
        initialized=false;
    }
}

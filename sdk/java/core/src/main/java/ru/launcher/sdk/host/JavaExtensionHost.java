package ru.launcher.sdk.host;

import java.net.URI;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import ru.launcher.sdk.core.ExtensionRunner;

/** Executable Java 17+ Extensions host: java -jar backend/extension.jar. */
public final class JavaExtensionHost {
    private JavaExtensionHost(){}
    public static void main(String[] args)throws Exception {
        ru.launcher.sdk.core.SentryDiagnostics.installFromEnvironment(System.getenv());
        URI location=JavaExtensionHost.class.getProtectionDomain().getCodeSource().getLocation().toURI();
        Path jar=Path.of(location).toRealPath();
        if(!jar.toString().toLowerCase(java.util.Locale.ROOT).endsWith(".jar"))throw new IllegalArgumentException("Java Extension Host must be launched from a JAR");
        String className;
        try(JarFile file=new JarFile(jar.toFile())){
            if(file.getManifest()==null)throw new IllegalArgumentException("JAR manifest missing");
            Attributes attributes=file.getManifest().getMainAttributes();
            if(!JavaExtensionHost.class.getName().equals(attributes.getValue("Main-Class")))throw new IllegalArgumentException("wrong JAR Main-Class");
            className=attributes.getValue("Launcher-Extension-Class");
            if(className==null||!className.matches("[a-zA-Z_$][a-zA-Z0-9_$.]{1,200}"))throw new IllegalArgumentException("invalid Launcher-Extension-Class");
        }
        String target=System.getenv().getOrDefault("LAUNCHER_EXTENSION_TARGET","backend");
        if("backend".equals(target)){
            if(args.length!=0)throw new IllegalArgumentException("backend host does not accept arguments");
            ExtensionRunner.runManagedFromHost(className,System.getenv());
        }else if("cli".equals(target)){
            if(args.length==0)throw new IllegalArgumentException("cli host requires a command");
            ExtensionRunner.runManagedCliFromHost(className,System.getenv(),Arrays.copyOf(args,args.length));
        }else throw new IllegalArgumentException("unsupported Java Extension Host target");
    }
}

package ru.launcher.sdk.core;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** Load a real third-party bytecode class from a pinned nested JAR. */
public final class ModulePackaging0482Tests {
    private static int checks;
    private static void check(boolean condition,String label){checks++;if(!condition)throw new AssertionError(label);}
    private static void reject(Checked action){checks++;try{action.run();throw new AssertionError("accepted unsafe JAR");}catch(SecurityException expected){/* fail closed */}catch(Exception unexpected){throw new AssertionError("unexpected exception",unexpected);}}
    private interface Checked{void run()throws Exception;}
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("pass the real built dependency host jar");
        Path packageJar=Path.of(args[0]).toRealPath();
        try{Class.forName("example.deps.Greeter",false,ModulePackaging0482Tests.class.getClassLoader());throw new AssertionError("test dependency leaked into SDK classpath");}
        catch(ClassNotFoundException expected){checks++;}
        try(BundledLibraries loaded=BundledLibraries.open(packageJar,"1.0",ModulePackaging0482Tests.class.getClassLoader())){
            Class<?> greeter=Class.forName("example.deps.Greeter",true,loaded.classLoader());
            check("dependency-loaded-0482".equals(greeter.getMethod("greeting").invoke(null)),"external library loaded actual bytecode");
            check(greeter.getClassLoader()==loaded.classLoader(),"isolated URLClassLoader used");
            check(loaded.classLoader()!=ModulePackaging0482Tests.class.getClassLoader(),"not the SDK classloader");
            Class<?> extensionType=Class.forName("example.extension.DependencyExtension",false,loaded.classLoader());
            check(extensionType.getClassLoader()==loaded.classLoader(),"extension and library share isolated classloader");
            Extension extension=(Extension)extensionType.getDeclaredConstructor().newInstance();
            extension.start(null);
            extension.stop(null);
            check(extensionType.getClassLoader().loadClass("ru.launcher.sdk.core.Extension")==Extension.class,"SDK API identity shared with parent");
        }
        reject(()->BundledLibraries.open(packageJar,"3.7",ModulePackaging0482Tests.class.getClassLoader()));
        Path modified=Files.createTempFile("neverlauncher-0482-bad-hash", ".jar");
        try{
            try(ZipFile zip=new ZipFile(packageJar.toFile());ZipOutputStream out=new ZipOutputStream(Files.newOutputStream(modified,StandardOpenOption.TRUNCATE_EXISTING))){
                Enumeration<? extends ZipEntry> contents=zip.entries();
                while(contents.hasMoreElements()){
                    ZipEntry entry=contents.nextElement();
                    byte[] body;try(InputStream stream=zip.getInputStream(entry)){body=stream.readAllBytes();}
                    if(entry.getName().equals("META-INF/launcher/libraries.lock")){
                        String text=new String(body,java.nio.charset.StandardCharsets.UTF_8);
                        body=text.replace("test:dep", "test:dep-corrupt").replaceFirst("[a-f0-9]{64}","0".repeat(64)).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    }
                    out.putNextEntry(new ZipEntry(entry.getName()));out.write(body);out.closeEntry();
                }
            }
            reject(()->BundledLibraries.open(modified,"1.0",ModulePackaging0482Tests.class.getClassLoader()));
        }finally{Files.deleteIfExists(modified);}
        System.out.println("PASS: "+checks+" real nested JAR classloading, API, and integrity checks");
    }
}

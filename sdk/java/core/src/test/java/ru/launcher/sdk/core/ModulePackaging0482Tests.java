package ru.launcher.sdk.core;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/** Загрузить реальный байткод стороннего класса из закреплённого вложенного JAR. */
public final class ModulePackaging0482Tests {
    private static int checks;
    private static void check(boolean condition,String label){checks++;if(!condition)throw new AssertionError(label);}
    private static void reject(Checked action){checks++;try{action.run();throw new AssertionError("небезопасный JAR ошибочно принят");}catch(SecurityException expected){/* отказ с сохранением безопасного состояния */}catch(Exception unexpected){throw new AssertionError("неожиданное исключение",unexpected);}}
    private interface Checked{void run()throws Exception;}
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("укажите настоящий собранный JAR хоста зависимостей");
        Path packageJar=Path.of(args[0]).toRealPath();
        try{Class.forName("example.deps.Greeter",false,ModulePackaging0482Tests.class.getClassLoader());throw new AssertionError("тестовая зависимость попала в путь классов SDK");}
        catch(ClassNotFoundException expected){checks++;}
        try(BundledLibraries loaded=BundledLibraries.open(packageJar,"1.0",ModulePackaging0482Tests.class.getClassLoader())){
            Class<?> greeter=Class.forName("example.deps.Greeter",true,loaded.classLoader());
            check("dependency-loaded-0482".equals(greeter.getMethod("greeting").invoke(null)),"внешняя библиотека загрузила настоящий байткод");
            check(greeter.getClassLoader()==loaded.classLoader(),"использован изолированный URLClassLoader");
            check(loaded.classLoader()!=ModulePackaging0482Tests.class.getClassLoader(),"использован не загрузчик классов SDK");
            Class<?> extensionType=Class.forName("example.extension.DependencyExtension",false,loaded.classLoader());
            check(extensionType.getClassLoader()==loaded.classLoader(),"расширение и библиотека используют общий изолированный загрузчик классов");
            Extension extension=(Extension)extensionType.getDeclaredConstructor().newInstance();
            extension.start(null);
            extension.stop(null);
            check(extensionType.getClassLoader().loadClass("ru.launcher.sdk.core.Extension")==Extension.class,"идентичность API SDK общая с родительским загрузчиком");
        }
        reject(()->BundledLibraries.open(packageJar,"3.7",ModulePackaging0482Tests.class.getClassLoader()));
        Path modified=Files.createTempFile("launcher-0482-bad-hash", ".jar");
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
        System.out.println("PASS: "+checks+" проверок реальной загрузки вложенных JAR, API и целостности");
    }
}

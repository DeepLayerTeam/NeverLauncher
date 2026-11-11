package ru.launcher.sdk.core;

import java.io.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Загружает встроенные JAR-зависимости подписанного пакета в процесс расширения, но никогда в JVM лаунчера. */
public final class BundledLibraries implements AutoCloseable {
    private static final String PREFIX="META-INF/launcher/libs/";
    private static final String LOCK="META-INF/launcher/libraries.lock";
    private static final int MAX_LIBS=64, MAX_LIB_BYTES=16*1024*1024, MAX_ALL_BYTES=64*1024*1024;
    private final Path directory;
    private final URLClassLoader loader;
    private final ClassLoader parent;
    private BundledLibraries(Path directory,URLClassLoader loader,ClassLoader parent){this.directory=directory;this.loader=loader;this.parent=parent;}
    public ClassLoader classLoader(){return loader==null?parent:loader;}
    private static final class ExtensionClassLoader extends URLClassLoader {
        ExtensionClassLoader(URL[] urls,ClassLoader parent){super(urls,parent);}
        @Override protected synchronized Class<?> loadClass(String name,boolean resolve)throws ClassNotFoundException {
            // SDK, хост и JDK остаются одиночными объектами в родительском загрузчике;
            // классы расширений ищутся сначала дочерним загрузчиком, чтобы их символьные
            // ссылки разрешали встроенные библиотеки, не раскрывая эти библиотеки ядру
            // JVM.
            boolean protectedName=name.startsWith("java.")||name.startsWith("javax.")||name.startsWith("jdk.")||
                name.startsWith("sun.")||name.startsWith("com.sun.")||name.startsWith("org.w3c.")||name.startsWith("org.xml.")||name.startsWith("ru.launcher.sdk.")||name.startsWith("pro.gravit.");
            Class<?> found=findLoadedClass(name);
            if(found==null&&!protectedName){try{found=findClass(name);}catch(ClassNotFoundException ignored){}}
            if(found==null)found=super.loadClass(name,false);
            if(resolve)resolveClass(found);
            return found;
        }
    }
    public static BundledLibraries open(String api)throws Exception {
        ClassLoader parent=ExtensionRunner.class.getClassLoader();
        URL source=ExtensionRunner.class.getProtectionDomain().getCodeSource().getLocation();
        if(!source.getProtocol().equals("file"))return new BundledLibraries(null,null,parent);
        Path host=Path.of(source.toURI());
        if(!Files.isRegularFile(host)||!host.toString().endsWith(".jar"))return new BundledLibraries(null,null,parent);
        return open(host,api,parent);
    }
    public static BundledLibraries open(Path host,String api,ClassLoader parent)throws Exception {
        if(!api.equals("1.0")&&!api.equals("3.7"))throw new SecurityException("Неподдерживаемый API хоста");
        Path directory=null;
        try(JarFile jar=new JarFile(host.toFile(),true)){
            if(jar.getManifest()==null)throw new SecurityException("Отсутствует манифест JAR хоста");
            if(jar.getManifest().getMainAttributes().getValue("Class-Path")!=null)throw new SecurityException("Внешний Class-Path запрещён");
            Map<String,JarEntry> entries=new HashMap<>();Set<String> ownClasses=new HashSet<>();
            Enumeration<JarEntry> enumeration=jar.entries();
            while(enumeration.hasMoreElements()){
                JarEntry entry=enumeration.nextElement();
                if(entries.putIfAbsent(entry.getName(),entry)!=null)throw new SecurityException("Повторяющийся элемент JAR хоста");
                if(entry.getName().endsWith(".class"))ownClasses.add(entry.getName());
            }
            JarEntry index=entries.get(LOCK);
            List<Library> libraries=new ArrayList<>();
            if(index!=null){
                if(index.getSize()>65536||index.getSize()<0)throw new SecurityException("Некорректный размер файла фиксации зависимостей");
                String text=new String(readBounded(jar.getInputStream(index),65536),StandardCharsets.UTF_8);
                if(!StandardCharsets.UTF_8.newEncoder().canEncode(text))throw new SecurityException("Некорректная кодировка файла фиксации зависимостей");
                Set<String> names=new HashSet<>(),artifacts=new HashSet<>();
                for(String line:text.split("\\n",-1)){
                    if(line.isEmpty())continue;
                    if(libraries.size()>=MAX_LIBS)throw new SecurityException("Слишком много библиотек");
                    String[] parts=line.split("\\t",-1);
                    if(parts.length!=5)throw new SecurityException("Некорректная запись файла фиксации библиотек");
                    String name=parts[0],coordinate=parts[1],version=parts[2],hash=parts[3],range=parts[4];
                    if(!name.matches("META-INF/launcher/libs/[A-Za-z0-9._-]+\\.jar")||!coordinate.matches("[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+")||!hash.matches("[0-9a-f]{64}")||!names.add(name)||!artifacts.add(coordinate))throw new SecurityException("Некорректный или повторяющийся идентификатор библиотеки");
                    SemVer.parse(version);
                    if(!SemVer.parse(api).matches(range))throw new SecurityException("Библиотека "+coordinate+" требует несовместимый API SDK: "+range);
                    JarEntry bundled=entries.get(name);
                    if(bundled==null||bundled.isDirectory()||bundled.getSize()<1||bundled.getSize()>MAX_LIB_BYTES)throw new SecurityException("Библиотека отсутствует или превышает допустимый размер: "+name);
                    libraries.add(new Library(name,hash,bundled));
                }
                if(libraries.isEmpty())throw new SecurityException("Пустой файл фиксации библиотек");
            }
            for(String name:entries.keySet())if(name.startsWith(PREFIX)&&name.endsWith(".jar")&&(index==null||libraries.stream().noneMatch(x->x.name.equals(name))))throw new SecurityException("Встроенный JAR не указан в файле фиксации: "+name);
            if(libraries.isEmpty())return new BundledLibraries(null,null,parent);
            directory=Files.createTempDirectory("neverlauncher-ext-libs-");
            try{Files.setPosixFilePermissions(directory,Set.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE,PosixFilePermission.OWNER_EXECUTE));}catch(UnsupportedOperationException ignored){}
            int total=0;Set<String> classes=new HashSet<>(ownClasses);List<URL> urls=new ArrayList<>();
            for(int i=0;i<libraries.size();i++){
                Library lib=libraries.get(i);
                byte[] bytes=readBounded(jar.getInputStream(lib.entry),MAX_LIB_BYTES);
                total=Math.addExact(total,bytes.length);
                if(total>MAX_ALL_BYTES)throw new SecurityException("Встроенные зависимости превышают лимит размера");
                if(!MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(bytes),HexFormat.of().parseHex(lib.sha256)))throw new SecurityException("Контрольная сумма зависимости не совпадает: "+lib.name);
                validateJar(bytes,classes);
                Path dest=directory.resolve("dep-"+i+".jar");
                Files.write(dest,bytes,StandardOpenOption.CREATE_NEW);
                try{Files.setPosixFilePermissions(dest,Set.of(PosixFilePermission.OWNER_READ,PosixFilePermission.OWNER_WRITE));}catch(UnsupportedOperationException ignored){}
                urls.add(dest.toUri().toURL());
            }
            urls.add(0,host.toUri().toURL());
            return new BundledLibraries(directory,new ExtensionClassLoader(urls.toArray(URL[]::new),parent),parent);
        }catch(Exception ex){if(directory!=null)delete(directory);throw ex;}
    }
    private record Library(String name,String sha256,JarEntry entry){}
    private static byte[] readBounded(InputStream stream,int limit)throws IOException {
        try(InputStream in=stream;ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[8192];int count;
            while((count=in.read(buffer))!=-1){if(out.size()+count>limit)throw new IOException("Элемент JAR превышает допустимый размер");out.write(buffer,0,count);}
            return out.toByteArray();
        }
    }
    private static void validateJar(byte[] bytes,Set<String> classes)throws Exception {
        int count=0;long expanded=0;Set<String> seen=new HashSet<>();
        try(JarInputStream jin=new JarInputStream(new ByteArrayInputStream(bytes),true)){
            Manifest m=jin.getManifest();
            if(m!=null){
                Attributes a=m.getMainAttributes();
                if(a.getValue("Class-Path")!=null||"true".equalsIgnoreCase(a.getValue("Multi-Release")))throw new SecurityException("Внешняя библиотека или библиотека с несколькими версиями запрещена");
            }
            JarEntry entry;
            while((entry=jin.getNextJarEntry())!=null){
                if(++count>4096)throw new SecurityException("Слишком много вложенных элементов библиотеки");
                String name=entry.getName();
                if(name.isEmpty()||name.startsWith("/")||name.contains("\\")||name.contains("//")||Arrays.asList(name.split("/",-1)).contains("..")||!seen.add(name))throw new SecurityException("Небезопасный или повторяющийся вложенный элемент JAR");
                if(entry.isDirectory())continue;
                if(name.startsWith("META-INF/versions/"))throw new SecurityException("Классы библиотеки с несколькими версиями не поддерживаются");
                byte[] payload=readEntryBounded(jin,16*1024*1024);
                expanded+=payload.length;
                if(expanded>64L*1024*1024)throw new SecurityException("Распакованный размер вложенного JAR превышает лимит");
                if(name.equalsIgnoreCase("META-INF/MANIFEST.MF")){
                    String data=new String(payload,StandardCharsets.UTF_8).toLowerCase(java.util.Locale.ROOT);
                    if(data.contains("\nclass-path:")||data.contains("\nmulti-release: true"))throw new SecurityException("Манифест библиотеки содержит внешний classpath или режим multi-release");
                }
                if(!name.endsWith(".class"))continue;
                if(name.startsWith("java/")||name.startsWith("javax/")||name.startsWith("jdk/")||name.startsWith("sun/")||name.startsWith("ru/launcher/sdk/")||name.startsWith("com/sun/")||name.startsWith("org/w3c/")||name.startsWith("org/xml/"))throw new SecurityException("Библиотека пытается заменить платформенный SDK");
                if(!classes.add(name))throw new SecurityException("Повторяющийся класс хоста и библиотек: "+name);
                if(payload.length<8||payload[0]!=(byte)0xCA||payload[1]!=(byte)0xFE||payload[2]!=(byte)0xBA||payload[3]!=(byte)0xBE)throw new SecurityException("Некорректный файл класса: "+name);
                int major=((payload[6]&255)<<8)|(payload[7]&255);
                if(major<45||major>Runtime.version().feature()+44)throw new SecurityException("Несовместимый байткод библиотеки: "+name);
            }
        }
        if(count==0)throw new SecurityException("Пустой JAR библиотеки");
    }
    private static byte[] readEntryBounded(InputStream in,int max)throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buf=new byte[8192];int n;
        while((n=in.read(buf))!=-1){if(out.size()+n>max)throw new IOException("Слишком большой вложенный элемент JAR");out.write(buf,0,n);}
        return out.toByteArray();
    }
    private static void delete(Path path)throws IOException {
        try(var stream=Files.list(path)){for(Path entry:stream.toList())Files.deleteIfExists(entry);}
        Files.deleteIfExists(path);
    }
    @Override public void close()throws IOException {if(loader!=null)loader.close();if(directory!=null)delete(directory);}
}

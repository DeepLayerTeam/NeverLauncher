package ru.launcher.trusted;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/** Guard for loader implementation classes at their actual JVM definition point.
 * Only code from SHA-256 pinned, operator-authorized loader JARs can define
 * Fabric/Quilt/Forge/NeoForge launch and Mixin transformation infrastructure.
 * This DOES NOT claim to identify the author of each downstream Mixin edit.
 */
final class LoaderGuard0504 implements ClassFileTransformer {
    private final String loader;
    private final Map<String,String> sources;
    private final Map<String,String> classBytes;
    private final Set<String> verified = new HashSet<String>();

    private LoaderGuard0504(String loader, Map<String,String> sources, Map<String,String> classBytes) {
        this.loader=loader;
        this.sources=sources;
        this.classBytes=classBytes;
    }
    static LoaderGuard0504 from(Properties config) throws Exception {
        String loader=config.getProperty("loader.id");
        if (loader == null || !(loader.equals("vanilla") || loader.equals("fabric") ||
            loader.equals("quilt") || loader.equals("forge") || loader.equals("neoforge"))) {
            throw new SecurityException("Guard requires a known signed Minecraft loader identity");
        }
        int count;
        try { count=Integer.parseInt(config.getProperty("loader.count", "-1")); }
        catch (NumberFormatException ex) { throw new SecurityException("Guard loader source count invalid",ex); }
        if (count<0 || count>128 || (!loader.equals("vanilla") && count==0) || (loader.equals("vanilla") && count!=0))
            throw new SecurityException("Guard loader sources missing or inconsistent with loader identity");
        Map<String,String> sources=new HashMap<String,String>();
        for(int i=0;i<count;i++) {
            String value=config.getProperty("loader."+i+".path");
            String sha=config.getProperty("loader."+i+".sha256");
            if(value==null || value.length()>16384 || sha==null || !sha.matches("[0-9a-f]{64}"))
                throw new SecurityException("Guard loader source identity malformed");
            String path=new String(Base64.getDecoder().decode(value),"UTF-8");
            File file=new File(path);
            if(!file.isAbsolute() || !file.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".jar") ||
                !file.isFile() || Files.isSymbolicLink(file.toPath()))
                throw new SecurityException("Guard loader source must be an installed regular JAR");
            String canonical=file.getCanonicalPath();
            if(sources.put(canonical,sha)!=null) throw new SecurityException("Guard duplicate loader source");
            // Проверяйте заранее, до исполнения кода загрузчика, даже если маркерный класс не
            // загружен.
            if(!sha.equals(digest(file))) throw new SecurityException("Guard loader JAR digest changed: "+file.getName());
        }
        // Необязательные байты классов, закреплённые оператором, наблюдаются
        // трансформером JVM после получения определения от загрузчика, но до хуков
        // доверенных Java-плагинов. Это точные подписанные хеши, а не имена классов с
        // безусловным разрешением переписывания.
        int classes;
        try { classes=Integer.parseInt(config.getProperty("loader.class.count", "0")); }
        catch(NumberFormatException ex) { throw new SecurityException("Guard loader class count invalid",ex); }
        if(classes<0 || classes>4096) throw new SecurityException("Guard loader class limit exceeded");
        Map<String,String> classBytes=new HashMap<String,String>();
        for(int i=0;i<classes;i++) {
            String encoded=config.getProperty("loader.class."+i+".name");
            String hash=config.getProperty("loader.class."+i+".sha256");
            if(encoded==null || encoded.length()>2048 || hash==null || !hash.matches("[0-9a-f]{64}"))
                throw new SecurityException("Guard loader class binding malformed");
            String name=new String(Base64.getDecoder().decode(encoded),"UTF-8");
            if(name.length()>256 || !name.matches("[A-Za-z_$][\\w$]*(\\.[A-Za-z_$][\\w$]*)+"))
                throw new SecurityException("Guard loader class name invalid");
            if(classBytes.put(name,hash)!=null) throw new SecurityException("Guard duplicated loader class hash");
        }
        return new LoaderGuard0504(loader,sources,classBytes);
    }
    @Override
    public byte[] transform(ClassLoader classLoader,String name,Class<?> redefined,ProtectionDomain protection,byte[] original) {
        if(name==null) return null;
        String binary=name.replace('/','.');
        String expected=classBytes.get(binary);
        if(expected!=null) {
            if(original==null || !expected.equals(digestBytes(original)))
                reject("loader class-byte mismatch before Trusted hooks: "+binary);
        }
        String actual=classify(name);
        if(actual==null) return null;
        if(!permitted(actual)) reject("loader mismatch: expected "+loader+" but observed "+actual+" in "+name);
        try {
            CodeSource code=protection==null?null:protection.getCodeSource();
            URL url=code==null?null:code.getLocation();
            if(url==null || !"file".equalsIgnoreCase(url.getProtocol())) reject("loader code source missing: "+name);
            File file=new File(url.toURI());
            if(Files.isSymbolicLink(file.toPath()) || !Files.isRegularFile(file.toPath(),LinkOption.NOFOLLOW_LINKS))
                reject("loader code source is not a regular file: "+name);
            String canonical=file.getCanonicalPath();
            String sha=sources.get(canonical);
            if(sha==null) reject("loader implementation JAR is not operator-authorized: "+name);
            synchronized(verified) {
                if(!verified.contains(canonical)) {
                    if(!sha.equals(digest(file))) reject("loader JAR changed before class definition: "+name);
                    verified.add(canonical);
                }
            }
        } catch(Exception ex) { reject("loader evidence unavailable for "+name+": "+ex); }
        return null; // observe/authorize source; do not rewrite loader bytecode
    }
    private boolean permitted(String actual) {
        return actual.equals(loader) || (actual.equals("modlauncher") && (loader.equals("forge") || loader.equals("neoforge"))) ||
            (actual.equals("mixin") && !loader.equals("vanilla"));
    }
    private static String classify(String name) {
        if(name.startsWith("net/fabricmc/loader/impl/")) return "fabric";
        if(name.startsWith("org/quiltmc/loader/impl/")) return "quilt";
        if(name.startsWith("net/minecraftforge/fml/loading/")) return "forge";
        if(name.startsWith("net/neoforged/fml/loading/")) return "neoforge";
        if(name.startsWith("cpw/mods/modlauncher/")) return "modlauncher";
        if(name.startsWith("org/spongepowered/asm/mixin/") || name.startsWith("org/spongepowered/asm/launch/") ||
            name.startsWith("org/spongepowered/asm/service/")) return "mixin";
        return null;
    }
    private static String digestBytes(byte[] bytes) {
        try {return hex(MessageDigest.getInstance("SHA-256").digest(bytes));}
        catch(Exception ex) { reject("SHA-256 unavailable: "+ex); return ""; }
    }
    private static String hex(byte[] bytes) {
        StringBuilder out=new StringBuilder(64);
        for(byte b:bytes) out.append(String.format("%02x",b&255));
        return out.toString();
    }
    private static String digest(File file) throws Exception {
        MessageDigest sha=MessageDigest.getInstance("SHA-256");
        try(BufferedInputStream stream=new BufferedInputStream(new FileInputStream(file))) {
            byte[] buffer=new byte[65536];int n;
            while((n=stream.read(buffer))!=-1) sha.update(buffer,0,n);
        }
        return hex(sha.digest());
    }
    private static void reject(String message) {
        System.err.println("[Launcher Guard 0.50.4] "+message);
        // Инструментирование JVM может подавлять исключения трансформера. При ошибке
        // доступ должен отклоняться.
        Runtime.getRuntime().halt(79);
        throw new SecurityException(message);
    }
}

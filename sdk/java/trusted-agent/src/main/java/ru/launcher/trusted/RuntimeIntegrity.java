package ru.launcher.trusted;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.net.URL;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.ProtectionDomain;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/** Активное обеспечение целостности проверенного процесса Minecraft, а не только диагностический отчёт.
 * Доверенный запуск предоставляет точные закреплённые дайджесты из проверенного выпуска/политики Guard.
 * Внутрипроцессные проверки не защищают от полностью доверенного вредоносного нативного/JVM-кода.
 */
final class RuntimeIntegrity0505 implements ClassFileTransformer {
    private static final int LIMIT = 8192;
    private final Path root;
    private final Map<Path, String> digests;
    private final Map<Path, String> kinds;
    private final Map<Path, String> externalModules;
    private final boolean strictCode;
    private final boolean linuxProcessRequired;
    private final Set<Path> verifiedOrigins = new HashSet<Path>();
    private volatile long lastVerifiedNanos = System.nanoTime();

    private RuntimeIntegrity0505(Path root, Map<Path, String> digests, Map<Path, String> kinds,
                                 Map<Path,String> externalModules,
                                 boolean strictCode, boolean linuxProcessRequired) {
        this.root = root;
        this.digests = digests;
        this.kinds = kinds;
        this.externalModules = externalModules;
        this.strictCode = strictCode;
        this.linuxProcessRequired = linuxProcessRequired;
    }

    static RuntimeIntegrity0505 from(Properties props) throws Exception {
        if (!"true".equals(props.getProperty("integrity.required")))
            throw new SecurityException("Отсутствует конфигурация контроля целостности среды выполнения Guard");
        String encodedRoot = props.getProperty("integrity.root");
        if (encodedRoot == null) throw new SecurityException("Отсутствует корневой каталог контроля целостности среды выполнения Guard");
        Path root = new File(new String(Base64.getDecoder().decode(encodedRoot), "UTF-8")).getCanonicalFile().toPath();
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))
            throw new SecurityException("Корневой каталог контроля целостности среды выполнения Guard недоступен");
        int count;
        try { count = Integer.parseInt(props.getProperty("integrity.count", "-1")); }
        catch (NumberFormatException ex) { throw new SecurityException("Некорректное количество элементов контроля целостности среды выполнения Guard", ex); }
        if (count < 1 || count > LIMIT) throw new SecurityException("Список элементов контроля целостности среды выполнения Guard пуст или превышает лимит");
        Map<Path,String> digests = new HashMap<Path,String>();
        Map<Path,String> kinds = new HashMap<Path,String>();
        for (int i = 0; i < count; i++) {
            String raw = props.getProperty("integrity."+i+".path");
            String hash = props.getProperty("integrity."+i+".sha256");
            String kind = props.getProperty("integrity."+i+".kind");
            if (raw == null || hash == null || !hash.matches("[0-9a-f]{64}") ||
                    !("code".equals(kind) || "native".equals(kind)))
                throw new SecurityException("Некорректный элемент списка контроля целостности среды выполнения Guard: " + i);
            Path path = new File(new String(Base64.getDecoder().decode(raw), "UTF-8")).toPath().toAbsolutePath().normalize();
            if (!path.startsWith(root) || path.equals(root) || digests.put(path, hash) != null)
                throw new SecurityException("Файл контроля целостности среды выполнения Guard находится вне каталога или повторяется: " + i);
            kinds.put(path, kind);
        }
        int externalCount;
        try {externalCount = Integer.parseInt(props.getProperty("integrity.external.count","0"));}
        catch(NumberFormatException ex) {throw new SecurityException("Некорректное количество внешних оверлеев Guard",ex);}
        if (externalCount<0 || externalCount>64 || (externalCount!=0 && !System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux")))
            throw new SecurityException("Некорректное количество или платформа внешних оверлеев Guard");
        Map<Path,String> external = new HashMap<Path,String>();
        for(int i=0;i<externalCount;i++) {
            String raw=props.getProperty("integrity.external."+i+".path");
            String sha=props.getProperty("integrity.external."+i+".sha256");
            if(raw==null || sha==null || !sha.matches("[0-9a-f]{64}"))
                throw new SecurityException("Некорректная привязка внешнего оверлея Guard: "+i);
            Path path=new File(new String(Base64.getDecoder().decode(raw),"UTF-8")).toPath();
            if(!path.isAbsolute() || path.normalize().equals(root) || path.normalize().startsWith(root) ||
               !path.equals(path.normalize()) || !isNative(path) || external.put(path,sha)!=null)
                throw new SecurityException("Небезопасный или повторяющийся путь внешнего оверлея Guard: "+i);
        }
        RuntimeIntegrity0505 guard = new RuntimeIntegrity0505(root,digests,kinds,external,
            "true".equals(props.getProperty("integrity.code.strict")),
            "true".equals(props.getProperty("integrity.linux.process.required")));
        guard.scan();
        if (guard.strictCode) guard.verifyClasspath();
        return guard;
    }

    private void verifyClasspath() throws Exception {
        String cp = System.getProperty("java.class.path", "");
        if (cp.isEmpty()) throw new SecurityException("Путь к классам JVM Guard недоступен");
        for (String item : cp.split(java.util.regex.Pattern.quote(File.pathSeparator), -1)) {
            if (item.isEmpty() || item.endsWith("*") )
                throw new SecurityException("Guard запрещает пустой путь к классам JVM или шаблон со звёздочкой");
            Path path = new File(item).toPath().toAbsolutePath().normalize();
            if (!path.startsWith(root) || !"code".equals(kinds.get(path)))
                throw new SecurityException("Путь к классам JVM Guard не подписан: " + path);
            check(path);
        }
    }

    void start() {
        Thread watcher = new Thread(new Runnable() {
            @Override public void run() {
                for (;;) {
                    try {
                        Thread.sleep(4000);
                        scan();
                        lastVerifiedNanos = System.nanoTime();
                    } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                    catch (Throwable e) { reject("Непрерывная проверка: " + e); }
                }
            }
        }, "launcher-runtime-integrity-0505");
        watcher.setDaemon(true);
        watcher.start();
        // Второй наблюдатель обнаруживает сбой или прерывание проверяющего
        // целостность процесса. Guard не должен незаметно продолжать запущенную игру
        // без сканирования.
        Thread watchdog = new Thread(new Runnable() {
            @Override public void run() {
                for (;;) {
                    try { Thread.sleep(1000); }
                    catch (InterruptedException e) { reject("Проверка целостности прервана"); }
                    if (!watcher.isAlive()) reject("Контроль целостности остановился во время работы JVM");
                    // Допускайте медленные диски и большие модпаки, но отклоняйте постоянно
                    // зависшее сканирование по монотонным часам, а не по настенному времени.
                    if (System.nanoTime() - lastVerifiedNanos > 90_000_000_000L)
                        reject("Превышено время ожидания проверки целостности");
                }
            }
        }, "launcher-integrity-watchdog-0506");
        watchdog.setDaemon(true);
        watchdog.start();
    }

    private void check(Path path) throws Exception {
        Path absolute = path.toAbsolutePath().normalize();
        if (!absolute.startsWith(root) || absolute.equals(root)) throw new SecurityException("Путь вышел за пределы корневого каталога игры");
        Path cursor = root;
        Path relative = root.relativize(absolute);
        for (Path component : relative) {
            cursor = cursor.resolve(component);
            if (Files.isSymbolicLink(cursor)) throw new SecurityException("Символическая ссылка: " + cursor);
        }
        if (!Files.isRegularFile(absolute,LinkOption.NOFOLLOW_LINKS))
            throw new SecurityException("Исполняемый объект не является обычным файлом: " + absolute);
        String expected=digests.get(absolute);
        if (expected==null || !expected.equals(digest(absolute)))
            throw new SecurityException("Подписанный файл среды выполнения отсутствует или заменён: " + absolute);
    }

    private void scan() throws Exception {
        for (Path path : digests.keySet()) check(path);
        for (Path path : externalModules.keySet()) checkExternal(path);
        checkTree(root.resolve("mods"),true);
        checkTree(root.resolve("natives"),false);
        // Linux: проверяйте настоящие нативные модули, отображённые этой JVM, а не только
        // файлы на диске. В Windows используется отдельный постоянно активный нативный Module
        // Guard; для macOS на этом этапе нет переносимого эквивалента, и охват не заявляется.
        if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux")) {
            if (linuxProcessRequired) LinuxProcessGuard0508.verify();
            scanLinuxMaps();
        } else if (linuxProcessRequired) {
            throw new SecurityException("Требования к процессу Linux применены к JVM другой ОС");
        }
    }

    private void checkTree(Path dir, boolean jars) throws Exception {
        if (!Files.exists(dir,LinkOption.NOFOLLOW_LINKS)) return;
        if (Files.isSymbolicLink(dir) || !Files.isDirectory(dir,LinkOption.NOFOLLOW_LINKS))
            throw new SecurityException("Каталог исполняемого файла Guard подменён: " + dir);
        int[] remaining = new int[]{LIMIT};
        walk(dir,jars,remaining);
    }
    private void walk(Path dir, boolean jars, int[] remaining) throws Exception {
        try (DirectoryStream<Path> files = Files.newDirectoryStream(dir)) {
            for (Path path : files) {
                if (--remaining[0] < 0) throw new SecurityException("Превышен лимит сканирования каталога исполняемых файлов Guard");
                if (Files.isSymbolicLink(path)) throw new SecurityException("Символическая ссылка в дереве исполняемых файлов: "+path);
                if (Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS)) { walk(path,jars,remaining); continue; }
                String name=path.getFileName().toString().toLowerCase(Locale.ROOT);
                boolean executable = jars ? name.endsWith(".jar") :
                    (name.endsWith(".so") || name.contains(".so.") || name.endsWith(".dll") ||
                     name.endsWith(".dylib") || name.endsWith(".jnilib"));
                if (executable) {
                    Path normalized=path.toAbsolutePath().normalize();
                    if (!digests.containsKey(normalized)) throw new SecurityException("Неодобренный файл среды выполнения: "+path);
                }
            }
        }
    }
    private void scanLinuxMaps() throws Exception {
        Path maps = new File("/proc/self/maps").toPath();
        if (!Files.isReadable(maps)) throw new SecurityException("Guard не может прочитать отображения памяти процесса");
        try (java.io.BufferedReader reader=Files.newBufferedReader(maps)) {
            for (String line; (line=reader.readLine())!=null;) {
                String[] parts=line.trim().split("\\s+",6);
                if (parts.length<6 || !parts[1].contains("x")) continue;
                String pathname=parts[5];
                if (!pathname.startsWith("/")) continue;
                if (pathname.endsWith(" (deleted)")) {
                    String name=pathname.substring(0,pathname.length()-10);
                    if (new File(name).toPath().normalize().startsWith(root))
                        throw new SecurityException("Отображённая в память игровая библиотека удалена: "+name);
                    continue;
                }
                Path p = new File(pathname).toPath().normalize();
                // Выбранный дистрибутив Java независимо повторно проверяется Managed Java
                // перед запуском. Не путайте системные образы, принадлежащие JVM, с
                // собственным деревом нативных исполняемых файлов Minecraft.
                Path javaHome=new File(System.getProperty("java.home", "/__invalid_java_home__")).toPath().toAbsolutePath().normalize();
                if (p.startsWith(javaHome) && !p.startsWith(root.resolve("mods")) && !p.startsWith(root.resolve("natives"))) continue;
                if (p.startsWith(root) && isNative(p)) {
                    if (!"native".equals(kinds.get(p)))
                        throw new SecurityException("Неодобренный нативный модуль, отображённый в память: "+p);
                    check(p);
                } else if (isNative(p) && !p.startsWith(javaHome) && !trustedOSNative(p)) {
                    if (!externalModules.containsKey(p))
                        throw new SecurityException("Неодобренный внешний нативный модуль: "+p);
                    checkExternal(p);
                }
            }
        }
    }
    private static boolean trustedOSNative(Path path) throws Exception {
        String name=path.toString();
        if (!(name.startsWith("/usr/lib/") || name.startsWith("/usr/lib64/") ||
              name.startsWith("/lib/") || name.startsWith("/lib64/"))) return false;
        // Системной библиотеке доверяют только при цепочке каталогов, принадлежащих
        // root и недоступных для записи. Слои Vulkan в домашнем каталоге должны быть
        // закреплены явно.
        try {
            Path real=path.toRealPath();
            if (!real.toString().startsWith("/usr/lib/") && !real.toString().startsWith("/usr/lib64/")) return false;
            Path cursor=real;
            while(cursor!=null) {
                int uid=(Integer)Files.getAttribute(cursor,"unix:uid",LinkOption.NOFOLLOW_LINKS);
                Set<PosixFilePermission> perms=Files.getPosixFilePermissions(cursor,LinkOption.NOFOLLOW_LINKS);
                if(uid!=0 || perms.contains(PosixFilePermission.GROUP_WRITE) ||
                       perms.contains(PosixFilePermission.OTHERS_WRITE)) return false;
                cursor=cursor.getParent();
            }
            return true;
        } catch (IOException ex) {return false;}
    }
    private void checkExternal(Path path) throws Exception {
        if (!path.isAbsolute() || !isNative(path)) throw new SecurityException("Внешний нативный модуль не является библиотекой с абсолютным путём");
        Path cursor=path.getRoot();
        for(Path part:path) {
            cursor=cursor.resolve(part);
            if(Files.isSymbolicLink(cursor)) throw new SecurityException("Символическая ссылка на внешний нативный модуль: "+cursor);
        }
        if (!Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) || Files.size(path)>512L*1024*1024 ||
            !externalModules.get(path).equals(digest(path)))
            throw new SecurityException("Внешний нативный модуль изменён: "+path);
    }
    private static boolean isNative(Path file) {
        String s=file.getFileName().toString().toLowerCase(Locale.ROOT);
        return s.endsWith(".so") || s.contains(".so.") || s.endsWith(".dll") || s.endsWith(".dylib") || s.endsWith(".jnilib");
    }
    @Override
    public byte[] transform(ClassLoader loader,String name,Class<?> redefined,ProtectionDomain pd,byte[] original) {
        if (!strictCode || pd==null || pd.getCodeSource()==null) return null;
        try {
            URL url=pd.getCodeSource().getLocation();
            if (url==null || !"file".equalsIgnoreCase(url.getProtocol())) return null;
            Path path=new File(url.toURI()).toPath().toAbsolutePath().normalize();
            if (!path.startsWith(root)) return null;
            if (!"code".equals(kinds.get(path))) reject("Неодобренный источник класса: "+name+" from "+path);
            // Проверяйте при определении класса, а не только один раз в premain: это
            // выявляет замену мода/JAR между периодическими проверками ФС.
            synchronized (verifiedOrigins) {
                if (!verifiedOrigins.contains(path)) {check(path);verifiedOrigins.add(path);}
            }
        } catch (Throwable e) { reject("Проверка источника класса: "+e); }
        return null;
    }
    private static String digest(Path path) throws Exception {
        MessageDigest sha=MessageDigest.getInstance("SHA-256");
        try (BufferedInputStream in=new BufferedInputStream(new FileInputStream(path.toFile()))) {
            byte[] buf=new byte[65536]; int n;
            while ((n=in.read(buf))!=-1) sha.update(buf,0,n);
        }
        StringBuilder out=new StringBuilder(64);
        for (byte b:sha.digest()) {out.append(Character.forDigit((b>>4)&15,16));out.append(Character.forDigit(b&15,16));}
        return out.toString();
    }
    static void reject(String message) {
        System.err.println("[Launcher Guard 0.50.6] "+message);
        Runtime.getRuntime().halt(79);
        throw new SecurityException(message); // недостижимо в рабочей среде; используется для статического анализа
    }
}

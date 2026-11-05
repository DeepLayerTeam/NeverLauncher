package ported.compat;

import java.io.*;
import java.util.*;
import java.util.zip.*;
import ru.launcher.sdk.core.*;

/** Упаковщик библиотек и загрузчиков до подписания. Читает только хранилище с закреплённым SHA через настоящий брокер Go. */
public final class LegacyLibraries implements ContentProvider {
    private RuntimeServices runtime;
    @Override public void start(ProviderContext ctx) { runtime = ctx.runtime(); }
    @Override public void stop(ProviderContext ctx) { runtime = null; }
    private Map<String,Object> assets() throws Exception {
        return Json.object(runtime.config().get("legacy-assets", null).orElseThrow());
    }
    private ContentServices.Asset asset(String id,String path) throws Exception {
        Map<String,Object> entry=Json.object(assets().get(path));
        if (!id.equals(Json.string(entry,"projectId",true))) throw new SecurityException("Библиотека другого проекта");
        return new ContentServices.Asset(id,"storage",Json.string(entry,"version",true),path,
            Json.string(entry,"sha256",true),((Number)entry.get("size")).intValue());
    }
    public ContentServices.Asset source(String id,String path) throws Exception { return asset(id,path); }
    public ContentServices.Asset texture(String id,String profile,String kind) throws Exception {
        return asset(id,"textures/"+profile+"/"+kind+".png");
    }
    public ContentServices.Asset delivery(String id,String path) throws Exception { return asset(id,path); }
    public Map<String,Object> metadata(String id,String release,Map<String,Object> original) {
        Map<String,Object> out=new LinkedHashMap<>(original);
        out.put("x-ported-gravit", true);
        return out;
    }
    /** Вход должен быть неподписанным ZIP. Опубликованный или подписанный пакет здесь никогда не меняется. */
    public byte[] preparePackage(String id,String name,byte[] source) throws Exception {
        if (!name.endsWith(".zip") || source.length>256*1024) throw new IllegalArgumentException("Требуется неподписанный ZIP-архив");
        if(source.length<4 || source[0]!='P' || source[1]!='K' || source[2]!=3 || source[3]!=4)
            throw new IllegalArgumentException("Источник не является непустым ZIP-архивом");
        Map<String,Object> config=assets();
        Object selected=config.get("bundle:"+id);
        if (!(selected instanceof List<?> files) || files.size()>24) throw new IllegalArgumentException("Не выбрана библиотека");
        Map<String,byte[]> entries=new TreeMap<>();
        try(ZipInputStream zin=new ZipInputStream(new ByteArrayInputStream(source))) {
            ZipEntry e;
            while((e=zin.getNextEntry())!=null) {
                String path=e.getName();
                if(e.isDirectory()) { safe(path.substring(0,path.length()-1)); continue; }
                safe(path);
                byte[] data=zin.readNBytes(256*1024+1);
                if(data.length>256*1024 || entries.putIfAbsent(path,data)!=null || entries.size()>128)
                    throw new SecurityException("Небезопасный элемент ZIP-архива");
            }
        }
        if(entries.isEmpty())throw new IllegalArgumentException("Пустой пакет не содержит данных профиля");
        int count=0;
        for(Object raw:files) {
            if(!(raw instanceof String path)) throw new IllegalArgumentException("Недопустимый путь к библиотеке");
            safe(path);
            if(!path.startsWith("libraries/") && !path.startsWith("mods/") && !path.startsWith("optional/"))
                throw new SecurityException("Библиотека должна находиться в разрешённых каталогах содержимого");
            ContentServices.Asset sourceAsset=asset(id,path);
            byte[] data=runtime.content().readChecked(sourceAsset);
            if(entries.putIfAbsent(path,data)!=null)throw new SecurityException("Конфликт библиотек: "+path);
            if(++count>24)throw new IllegalArgumentException("Слишком много библиотек");
        }
        ByteArrayOutputStream bout=new ByteArrayOutputStream();
        try(ZipOutputStream zout=new ZipOutputStream(bout)) {
            for(var e:entries.entrySet()) {
                ZipEntry ze=new ZipEntry(e.getKey());ze.setTime(0);zout.putNextEntry(ze);
                zout.write(e.getValue());zout.closeEntry();
                if(bout.size()>512*1024)throw new IllegalArgumentException("Подготовленный пакет слишком велик");
            }
        }
        if(bout.size()>512*1024)throw new IllegalArgumentException("Подготовленный пакет слишком велик");
        return bout.toByteArray();
    }
    private static void safe(String path) {
        if(path==null || path.length()>512 || path.startsWith("/") || path.contains("\\") || path.contains("\0"))
            throw new SecurityException("Небезопасный путь в архиве");
        for(String part:path.split("/",-1))if(part.isEmpty()||part.equals(".")||part.equals(".."))
            throw new SecurityException("Выход за пределы каталога архива");
    }
}

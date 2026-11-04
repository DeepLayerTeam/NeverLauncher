package ru.launcher.sdk.core;

import java.util.Map;

/** Выбранный адаптер контента. Его результат недоверенный, пока ContentServices не проверит его.
 * Преобразования пакета выполняются до основного конвейера подписи и публикации; они не могут
 * самостоятельно публиковать, изменять подписанный манифест или выдавать разрешение на скачивание. */
public interface ContentProvider extends JavaProvider {
    ContentServices.Asset source(String projectId, String logicalPath) throws Exception;
    ContentServices.Asset texture(String projectId, String profileId, String kind) throws Exception;
    Map<String,Object> metadata(String projectId, String releaseId, Map<String,Object> original) throws Exception;
    byte[] preparePackage(String projectId, String name, byte[] source) throws Exception;
    ContentServices.Asset delivery(String projectId, String logicalPath) throws Exception;
}

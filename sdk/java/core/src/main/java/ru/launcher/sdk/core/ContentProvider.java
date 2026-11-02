package ru.launcher.sdk.core;

import java.util.Map;

/** Selected content adapter. Its output is untrusted until ContentServices validates it.
 * Package transformations run before the core signing/publish pipeline; they cannot
 * publish, alter a signed manifest or mint download authorization themselves. */
public interface ContentProvider extends JavaProvider {
    ContentServices.Asset source(String projectId, String logicalPath) throws Exception;
    ContentServices.Asset texture(String projectId, String profileId, String kind) throws Exception;
    Map<String,Object> metadata(String projectId, String releaseId, Map<String,Object> original) throws Exception;
    byte[] preparePackage(String projectId, String name, byte[] source) throws Exception;
    ContentServices.Asset delivery(String projectId, String logicalPath) throws Exception;
}

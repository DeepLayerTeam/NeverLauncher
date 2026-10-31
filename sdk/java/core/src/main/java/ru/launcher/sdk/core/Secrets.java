package ru.launcher.sdk.core;

import java.io.IOException;
import java.util.*;
import java.util.Base64;

/** Secret access always goes through the existing permission-checked Go secrets broker. */
public final class Secrets {
    @FunctionalInterface public interface SecretConsumer<T>{T use(byte[] secret)throws Exception;}
    private final HostSession host;
    Secrets(HostSession host){this.host=host;}
    public <T> T withSecret(String name,String projectId,SecretConsumer<T> callback)throws Exception {
        Objects.requireNonNull(callback);
        Map<String,Object> req=new HashMap<>();req.put("name",name);if(projectId!=null&&!projectId.isBlank())req.put("projectId",projectId);
        Map<String,Object> response=host.capability("secret.get",req);
        String b64=Json.string(response,"valueBase64",true);byte[] bytes=Base64.getDecoder().decode(b64);
        try{return callback.use(bytes);}finally{Arrays.fill(bytes,(byte)0);}
    }
}

package ru.launcher.sdk.core;

import java.io.IOException;
import java.util.*;

/** Постоянные документы, изолированные по расширению и области действия, обслуживаются аутентифицированным Go-брокером. */
public final class RuntimeDocuments {
    private final HostSession host;private final String kind;
    RuntimeDocuments(HostSession host,String kind){this.host=host;this.kind=kind;}
    public Optional<Object> get(String key,JsonSchema schema)throws IOException,InterruptedException {
        try {Object value=host.capability("runtime."+kind+".get",Map.of("key",key)).get("value");if(schema!=null)schema.validate(value);return Optional.ofNullable(value);}
        catch(HostSession.HostError e){if(e.status()==404)return Optional.empty();throw e;}
    }
    public void put(String key,Object value,JsonSchema schema)throws IOException,InterruptedException {
        Objects.requireNonNull(value,"Документы с JSON null не поддерживаются");if(schema!=null)schema.validate(value);
        host.capability("runtime."+kind+".put",Map.of("key",key,"value",value));
    }
    public void delete(String key)throws IOException,InterruptedException {host.capability("runtime."+kind+".delete",Map.of("key",key));}
}

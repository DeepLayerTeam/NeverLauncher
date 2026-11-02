package example.content;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import ru.launcher.sdk.core.*;

/** Executable sample: chooses an extension-local provider, retrieves a pinned
 * storage object through Go capability checks, and performs a pre-sign transform. */
public final class ContentExtension implements Extension {
    @Override public void start(ExtensionContext ctx) throws Exception {
        ctx.providers().register(new ProviderDescriptor<>(ContentServices.CONTRACT,"sample",SemVer.parse("1.0.0"),"^1.0.0","^1.0.0",SampleProvider::new));
        ctx.providers().select(ContentServices.CONTRACT.id(),"sample",Duration.ofSeconds(2));
        ctx.runtime().commands().register("content-check",null,payload->payload,payload->{
            ContentServices api=ctx.runtime().content();
            String text=new String(api.preparePackage("demo-project","demo.json","hello".getBytes(StandardCharsets.UTF_8)).bytes(),StandardCharsets.UTF_8);
            byte[] checked=api.readChecked(api.source("demo-project","demo.json"));
            var out=new LinkedHashMap<String,Object>();out.put("prepared",text);out.put("requiresSigning",true);out.put("sourceVerified",new String(checked,StandardCharsets.UTF_8).equals("data"));
            return out;
        });
    }
    @Override public void stop(ExtensionContext context) {}
    public static final class SampleProvider implements ContentProvider {
        public void start(ProviderContext ctx) {}
        public void stop(ProviderContext ctx) {}
        public ContentServices.Asset source(String id,String path){return new ContentServices.Asset(id,"storage","release-1",path,ContentServices.sha("data".getBytes(StandardCharsets.UTF_8)),4);}
        public ContentServices.Asset texture(String id,String profile,String kind){return source(id,"textures/"+profile+"/"+kind+".png");}
        public Map<String,Object> metadata(String id,String release,Map<String,Object> original){
            var copy=new LinkedHashMap<>(original);copy.put("x-content-label","sample");return copy;
        }
        public byte[] preparePackage(String id,String filename,byte[] bytes){return (new String(bytes,StandardCharsets.UTF_8)+"-processed").getBytes(StandardCharsets.UTF_8);}
        public ContentServices.Asset delivery(String id,String path){return source(id,path);}
    }
}

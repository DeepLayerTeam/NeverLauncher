package ru.neverlauncher.api;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;

/** Genuine installed HTTPS API exercised through the published Java SDK. */
public final class LiveAcceptance {
    private static String required(String name) {
        var v = System.getenv(name);
        if(v == null || v.isBlank()) throw new IllegalArgumentException("missing live configuration "+name);
        return v;
    }
    public static void main(String[] args) throws Exception {
        try {
            var c = new NeverLauncherAPI(required("NL_GA_ORIGIN"),required("NL_GA_BEARER"));
            c.checkCompatibility();
            var body=c.request("GET",required("NL_GA_JSON_PATH"),Map.of(),null,null,null);
            if(!(body instanceof Map<?,?> map) || map.isEmpty()) throw new IOException("empty real JSON API response");
            var text = new ByteArrayOutputStream();
            var textSize=c.requestStream("GET",required("NL_GA_TEXT_PATH"),Map.of(),null,null,text,1<<20,"");
            if(textSize < 10 || new String(text.toByteArray(),StandardCharsets.UTF_8).contains("\u0000"))
                throw new IOException("real HTTP text/metrics stream invalid");
            var sha=MessageDigest.getInstance("SHA-256");
            OutputStream checksum=new OutputStream() {
                @Override public void write(int b) { sha.update((byte)b); }
                @Override public void write(byte[] b,int off,int len) { sha.update(b,off,len); }
            };
            var size=c.requestStream("GET",required("NL_GA_BINARY_PATH"),Map.of(),null,null,checksum,1L<<30,"");
            var hash=HexFormat.of().formatHex(sha.digest());
            if(size<8 || !hash.equals(required("NL_GA_BINARY_SHA256")))
                throw new IOException("real streamed binary SHA-256 mismatch");
            try { c.requestStream("GET","https://untrusted.invalid",Map.of(),null,null,
                                  OutputStream.nullOutputStream(),1024,"");
                throw new IOException("unsafe external origin accepted");
            } catch(IllegalArgumentException expected) { }
            System.out.println("PASS sdk=java checks=3 binaryBytes="+size+" binarySha256="+hash);
        } catch(Exception ex) {
            System.err.println("BLOCKED SDK Java: "+ex.getClass().getSimpleName());
            System.exit(2);
        }
    }
}

package ru.launcher.sdk.core;

import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.*;

/** Реальный выбранный SPI, аутентифицированный JVM HTTP-колбэк и отзыв сеанса провайдера. */
public final class IdentitySpi0485Tests {
    private static int checks;
    private static void ok(boolean pass,String why){checks++;if(!pass)throw new AssertionError(why);}
    private static void fail(Class<? extends Throwable> kind,Throwing call) throws Exception {
        checks++;
        try{call.run();throw new AssertionError("expected "+kind.getSimpleName());}
        catch(Throwable e){if(!kind.isInstance(e))throw new AssertionError("неверная ошибка",e);}
    }
    @FunctionalInterface interface Throwing{void run()throws Exception;}
    private static final ExtensionManifest M=ExtensionManifest.parse("{\"schemaVersion\":\"2.0\",\"id\":\"example.identity\",\"name\":\"Identity SPI\",\"publisher\":\"test\",\"version\":\"0.48.5\",\"api\":\"1.0\",\"permissions\":[\"auth:provider\"],\"targets\":[{\"kind\":\"backend\",\"entrypoint\":\"backend/main.jar\"}]}");
    private static final AtomicBoolean tokenRevoked=new AtomicBoolean();
    private static final AtomicInteger started=new AtomicInteger(), stopped=new AtomicInteger();
    private static final VerifiedIdentity ID=new VerifiedIdentity("https://identity.example","immutable-user-1","user@example.org","member","Member");
    private static class Provider implements IdentityProvider {
        public void start(ProviderContext context){started.incrementAndGet();}
        public void stop(ProviderContext context){stopped.incrementAndGet();}
        public IdentityProof authenticatePassword(String username,String secret)throws IdentityFailure{
            if(!username.equals("member")||!secret.equals("correct"))throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
            return new IdentityProof(ID,List.of("pwd"),"session-1",java.time.Instant.now().plusSeconds(900).getEpochSecond());
        }
        public VerifiedIdentity resolveIdentity(String subject)throws IdentityFailure{
            if(!subject.equals(ID.subject()))throw new IdentityFailure(IdentityFailure.Code.IDENTITY_NOT_FOUND);
            return ID;
        }
        public IdentityProof verifyProviderSession(String token)throws IdentityFailure{
            if(tokenRevoked.get()||!token.equals("session-1"))throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
            return new IdentityProof(ID,List.of("session"),token,java.time.Instant.now().plusSeconds(900).getEpochSecond());
        }
        public void revokeProviderSession(String subject,String token)throws IdentityFailure{
            if(!subject.equals(ID.subject())||!token.equals("session-1"))throw new IdentityFailure(IdentityFailure.Code.INVALID_CREDENTIALS);
            tokenRevoked.set(true);
        }
    }
    private static Map<String,Object> rpc(HttpClient http,RuntimeCallbackServer callback,String token,String method,Map<String,Object> params)throws Exception {
        Map<String,Object> msg=Map.of("protocolVersion","1.0","requestId","test-id","method",method,"deadlineMs",1000,"params",params);
        HttpRequest request=HttpRequest.newBuilder(URI.create(callback.url()+"/v1/rpc"))
            .header("Authorization","Bearer "+token).header("Content-Type","application/json")
            .POST(HttpRequest.BodyPublishers.ofString(Json.encode(msg))).timeout(Duration.ofSeconds(2)).build();
        HttpResponse<String> response=http.send(request,HttpResponse.BodyHandlers.ofString());
        ok(response.statusCode()==(token.equals("callback-secret")?200:401),"authenticated callback status");
        return Json.object(Json.parse(response.body()));
    }
    public static void main(String[] args)throws Exception {
        fail(IllegalArgumentException.class,()->new VerifiedIdentity("issuer","","","",""));
        fail(IllegalArgumentException.class,()->new IdentityProof(ID,List.of(),"",0));
        Map<String,String> env=Map.of("LAUNCHER_EXTENSION_HOST_URL","http://127.0.0.1:7","LAUNCHER_EXTENSION_ID",M.id(),"LAUNCHER_EXTENSION_VERSION",M.versionText(),"LAUNCHER_EXTENSION_HOST_PROTOCOL","1.0","LAUNCHER_EXTENSION_API_VERSION","1.0","LAUNCHER_EXTENSION_HOST_TOKEN","unused","LAUNCHER_EXTENSION_INSTANCE_ID","test-instance");
        try(var host=HostSession.fromEnvironment(env,M);var services=new RuntimeServices(host,Set.of())){
            Extension ext=new Extension(){
                public void start(ExtensionContext ctx)throws Exception{
                    ctx.providers().register(new ProviderDescriptor<>(IdentityServices.CONTRACT,"selected",SemVer.parse("1.0.0"),"^1.0.0","^1.0.0",Provider::new));
                    ctx.providers().select(IdentityServices.CONTRACT.id(),"selected",Duration.ofSeconds(2));
                }
                public void stop(ExtensionContext ctx){}
            };
            try(var lifecycle=new ExtensionLifecycle(ext,M,services);
                var callback=new RuntimeCallbackServer("callback-secret",services,()->lifecycle.state().name())) {
                lifecycle.start(Duration.ofSeconds(2));
                ok(started.get()==1,"provider started by real lifecycle");
                var http=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
                Map<String,Object> info=rpc(http,callback,"callback-secret","auth.health",Map.of());
                ok(Boolean.TRUE.equals(Json.object(info.get("result")).get("available")),"real RPC health selected provider");
                var good=rpc(http,callback,"callback-secret","auth.password",Map.of("identifier","member","secret","correct"));
                var result=Json.object(Json.object(good.get("result")).get("authentication"));
                ok(Json.object(result.get("identity")).get("subject").equals(ID.subject()),"real password proof immutable subject");
                ok(result.get("providerToken").equals("session-1"),"external provider session token returned");
                var bad=rpc(http,callback,"callback-secret","auth.password",Map.of("identifier","member","secret","bad"));
                ok(Json.object(bad.get("result")).get("errorCode").equals("invalid_credentials"),"invalid password stable error");
                var lookup=rpc(http,callback,"callback-secret","auth.resolve",Map.of("subject",ID.subject()));
                ok(Json.object(Json.object(lookup.get("result")).get("identity")).get("subject").equals(ID.subject()),"resolve linked subject");
                var invalid=rpc(http,callback,"callback-secret","auth.resolve",Map.of("subject","different"));
                ok(Json.object(invalid.get("result")).get("errorCode").equals("identity_not_found"),"unknown subject denied");
                var session=rpc(http,callback,"callback-secret","auth.session.verify",Map.of("providerToken","session-1"));
                ok(Json.object(session.get("result")).containsKey("authentication"),"real provider session introspection");
                var revoked=rpc(http,callback,"callback-secret","auth.session.revoke",Map.of("providerToken","session-1","subject",ID.subject()));
                ok(Boolean.TRUE.equals(Json.object(revoked.get("result")).get("revoked")),"provider revocation confirmed");
                var after=rpc(http,callback,"callback-secret","auth.session.verify",Map.of("providerToken","session-1"));
                ok(Json.object(after.get("result")).get("errorCode").equals("invalid_credentials"),"revoked provider token rejected");
                rpc(http,callback,"bad-token","auth.password",Map.of("identifier","member","secret","correct"));
                lifecycle.stop(Duration.ofSeconds(2));
                ok(stopped.get()==1,"provider stopped at lifecycle shutdown");
                fail(IdentityFailure.class,()->services.identity().authenticatePassword("member","correct"));
            }
        }
        System.out.println("PASS: "+checks+" JVM identity SPI lifecycle, authenticated callback, identity and session checks");
    }
}

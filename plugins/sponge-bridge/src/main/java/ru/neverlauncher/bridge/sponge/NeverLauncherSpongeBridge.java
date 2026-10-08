package ru.neverlauncher.bridge.sponge;

import com.google.inject.Inject;
import net.kyori.adventure.text.Component;
import org.apache.logging.log4j.Logger;
import org.spongepowered.api.Server;
import org.spongepowered.api.event.Listener;
import org.spongepowered.api.event.Order;
import org.spongepowered.api.event.lifecycle.StartedEngineEvent;
import org.spongepowered.api.event.lifecycle.StoppingEngineEvent;
import org.spongepowered.api.event.network.ServerSideConnectionEvent;
import org.spongepowered.api.event.network.ServerSideConnectionEvent.Auth;
import org.spongepowered.api.event.network.ServerSideConnectionEvent.Join;
import org.spongepowered.api.event.network.ServerSideConnectionEvent.Disconnect;
import org.spongepowered.plugin.PluginContainer;
import org.spongepowered.plugin.builtin.jvm.Plugin;
import ru.neverlauncher.bridge.common.*;

import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Нативный SpongeAPI адаптер; reflection является restricted к optional/version-varying метрики. */
@Plugin("neverlauncher_sponge_bridge")
public final class NeverLauncherSpongeBridge {
    private final PluginContainer container;
    private final Logger logger;
    private final ScheduledExecutorService workers = Executors.newSingleThreadScheduledExecutor(r -> { Thread t=new Thread(r,"neverlauncher-sponge-heartbeat");t.setDaemon(true);return t; });
    private final AtomicBoolean stopping = new AtomicBoolean();
    private final AtomicBoolean maintenance = new AtomicBoolean();
    private final AtomicBoolean draining = new AtomicBoolean();
    private final AtomicInteger online = new AtomicInteger();
    private volatile Server server;
    private volatile BridgeConfig config;
    private volatile NeverLauncherApiClient api;

    @Inject
    public NeverLauncherSpongeBridge(PluginContainer container, Logger logger) {
        this.container = container; this.logger = logger;
    }

    @Listener
    public void onStarted(StartedEngineEvent<Server> event) {
        this.server = event.engine();
        try {
            Path configPath = Path.of(System.getProperty("user.dir", "."), "config", "neverlauncher-sponge-bridge", "config.yml").toAbsolutePath().normalize();
            config = BridgeConfig.load(configPath, "sponge-main");
            String sha = BridgeIntegrity.artifactSha256(getClass());
            if (config.requireIntegrity && !BridgeIntegrity.isSha256(sha)) throw new IllegalStateException("cannot measure running Sponge bridge JAR SHA-256");
            NodeIdentity identity = NodeIdentity.loadOrCreate(config.identityFile);
            String spongeVersion = BridgeRuntimeProbe.packageVersion("org.spongepowered.api.Sponge");
            String minecraftVersion = BridgeRuntimeProbe.minecraftVersion();
            BridgeRuntimeDescriptor descriptor = BridgeRuntimeDescriptor.of(minecraftVersion, "sponge", "SpongeAPI", spongeVersion,
                "Sponge " + spongeVersion, List.of("heartbeat.signed","join.sponge-auth-gate","artifact.sha256","runtime.discovery","runtime.ed25519-attestation","telemetry.server-v1","events.ordered-stream-v1","control.secure-channel-v1","loader.sponge"));
            BridgeAdapterProfiles.rejectUncertifiedHybrid("sponge", descriptor.serverBrand());
            api = new NeverLauncherApiClient(config, identity, "sponge", BridgeDefaults.VERSION, sha, descriptor);
            api.setRoutingModes(false,false);
            api.startControlChannel(this::executeControl);
            api.publishEvent("server.startup", Map.of("platform","sponge"));
            api.publishEvent("server.ready", Map.of("platform","sponge"));
            workers.scheduleWithFixedDelay(this::sampleAndHeartbeat, 0, Math.max(5, Math.min(config.heartbeatIntervalSeconds, config.telemetrySampleIntervalSeconds)), TimeUnit.SECONDS);
            logger.info("NeverLauncher Sponge ServerBridge {} ready; serverId={}; runtimeId={}", BridgeDefaults.VERSION, config.serverId, api.runtimeId());
        } catch (Exception e) {
            throw new IllegalStateException("NeverLauncher Sponge ServerBridge initialization failed", e);
        }
    }

    @Listener(order = Order.FIRST)
    public void onAuth(Auth event) {
        NeverLauncherApiClient current=api;
        if(current==null || stopping.get()){ deny(event,"NeverLauncher ServerBridge unavailable"); return; }
        if(maintenance.get() || draining.get()){ deny(event, maintenance.get()?"Server is in maintenance mode":"Server is draining"); return; }
        String username = profileString(event.profile(), "name");
        String uuid = profileString(event.profile(), "uniqueId");
        String ip = remoteIp(event);
        JoinValidationResult result = current.validateJoin(username, uuid, ip);
        current.publishEvent("player.login", Map.of("username",username,"uuid",uuid,"allowed",Boolean.toString(result.allowed),"reason",String.valueOf(result.reason)));
        if(!result.allowed) deny(event,result.userMessage());
    }

    @Listener public void onJoin(Join event) {
        online.incrementAndGet();
        Object player = invokeNoArg(event,"player");
        if(api!=null) api.publishEvent("player.join", Map.of("username", profileString(player,"name"), "uuid", profileString(player,"uniqueId")));
    }
    @Listener public void onDisconnect(Disconnect event) {
        online.updateAndGet(v->Math.max(0,v-1));
        Object profile = invokeNoArg(event,"profile"); if(profile instanceof Optional<?> opt) profile=opt.orElse(null);
        if(api!=null) api.publishEvent("player.quit", Map.of("username", profileString(profile,"name"), "uuid", profileString(profile,"uniqueId")));
    }

    @Listener public void onStopping(StoppingEngineEvent<Server> event) { close(); }

    private void sampleAndHeartbeat() {
        NeverLauncherApiClient current=api; Server s=server; if(current==null||s==null||stopping.get()) return;
        try {
            int players = collectionSize(invokeNoArg(s,"onlinePlayers"), online.get());
            int max = intValue(invokeNoArg(s,"maxPlayers"), Math.max(players,players));
            Double tps = doubleValue(invokeNoArg(s,"ticksPerSecond"));
            Double mspt = doubleValue(invokeNoArg(s,"averageTickTime"));
            Integer worlds = collectionSizeNullable(invokeNoArg(invokeNoArg(s,"worldManager"),"worlds"));
            List<String> metrics=new ArrayList<>(); metrics.add("players"); if(tps!=null)metrics.add("tps"); if(mspt!=null)metrics.add("mspt"); if(worlds!=null){metrics.add("worlds");metrics.add("dimensions");}
            current.recordPlatformTelemetry(BridgePlatformTelemetry.server(tps,mspt,players,max,worlds,worlds,null,null,false,metrics));
            current.heartbeat("sponge",BridgeDefaults.VERSION);
        } catch (RuntimeException e) { current.publishEvent("server.error",Map.of("component","sponge-telemetry","message",safe(e.getMessage(),512))); }
    }

    private BridgeControlResult executeControl(BridgeControlCommand command) throws Exception {
        if("server.maintenance".equals(command.type())) { boolean v=Boolean.parseBoolean(command.payload().getOrDefault("enabled","false")); maintenance.set(v); route(); return BridgeControlResult.ok(Map.of("enabled",Boolean.toString(v))); }
        if("server.drain".equals(command.type())) { boolean v=Boolean.parseBoolean(command.payload().getOrDefault("enabled","false")); draining.set(v); route(); return BridgeControlResult.ok(Map.of("enabled",Boolean.toString(v))); }
        Future<BridgeControlResult> f = server.scheduler().executor(container).submit(() -> executeOnServer(command));
        try { return f.get(10,TimeUnit.SECONDS); } catch (TimeoutException e) { return BridgeControlResult.indeterminate("platform_control_timeout"); }
    }

    private BridgeControlResult executeOnServer(BridgeControlCommand command) {
        Map<String,String> p=command.payload();
        switch(command.type()) {
            case "player.kick" -> {
                Object player=findPlayer(p.get("username")); if(player==null)return BridgeControlResult.failed("player_not_online");
                if(!invokeComponent(player,"kick",Component.text(safe(p.getOrDefault("reason","Disconnected by server operator"),512)))) return BridgeControlResult.unsupported("sponge_kick_api_unavailable");
                return BridgeControlResult.ok(Map.of("username",safe(p.get("username"),16)));
            }
            case "message.broadcast" -> {
                Component c=Component.text(safe(p.getOrDefault("message",""),1024));
                Object players=invokeNoArg(server,"onlinePlayers"); if(players instanceof Iterable<?> it) for(Object pl:it) invokeComponent(pl,"sendMessage",c);
                return BridgeControlResult.ok(Map.of("broadcast","true"));
            }
            case "whitelist.enable", "whitelist.disable" -> {
                boolean enabled=command.type().endsWith("enable");
                try { Method m=server.getClass().getMethod("setHasWhitelist",boolean.class); m.invoke(server,enabled); return BridgeControlResult.ok(Map.of("enabled",Boolean.toString(enabled))); }
                catch(Exception e){return BridgeControlResult.unsupported("sponge_whitelist_api_unavailable");}
            }
            case "server.shutdown" -> {
                try { server.shutdown(); return BridgeControlResult.ok(Map.of("scheduled","true")); }
                catch(RuntimeException e){return BridgeControlResult.failed("sponge_shutdown_failed");}
            }
            case "whitelist.add","whitelist.remove","ban.add","ban.remove","server.save","server.console" -> { return BridgeControlResult.unsupported("operation_not_exposed_by_universal_sponge_adapter"); }
            default -> { return BridgeControlResult.unsupported("unsupported_control_type"); }
        }
    }

    private Object findPlayer(String username){ Object players=invokeNoArg(server,"onlinePlayers"); if(players instanceof Iterable<?> it)for(Object p:it)if(profileString(p,"name").equalsIgnoreCase(safe(username,16)))return p; return null; }
    private void route(){ if(api!=null){api.setRoutingModes(maintenance.get(),draining.get());api.heartbeat("sponge",BridgeDefaults.VERSION);} }
    private void deny(Auth event,String message){ event.setCancelled(true); event.setMessage(Component.text(safe(message,512))); }
    private String remoteIp(ServerSideConnectionEvent event){ Object c=invokeNoArg(event,"connection"); Object a=invokeNoArg(c,"address"); if(a instanceof InetSocketAddress i)return i.getAddress()==null?i.getHostString():i.getAddress().getHostAddress(); return ""; }
    private static Object invokeNoArg(Object target,String name){ if(target==null)return null; try{return target.getClass().getMethod(name).invoke(target);}catch(Exception e){return null;} }
    private static String profileString(Object o,String method){ Object v=invokeNoArg(o,method); if(v instanceof Optional<?> x)v=x.orElse(null); return v==null?"":safe(String.valueOf(v),128); }
    private static int collectionSize(Object o,int fallback){return o instanceof Collection<?> c?c.size():fallback;}
    private static Integer collectionSizeNullable(Object o){return o instanceof Collection<?> c?c.size():null;}
    private static int intValue(Object o,int d){return o instanceof Number n?n.intValue():d;}
    private static Double doubleValue(Object o){return o instanceof Number n&&Double.isFinite(n.doubleValue())?n.doubleValue():null;}
    private static boolean invokeComponent(Object target,String method,Component c){try{target.getClass().getMethod(method,Component.class).invoke(target,c);return true;}catch(Exception e){return false;}}
    private static String safe(String s,int max){String v=s==null?"":s.replace('\r',' ').replace('\n',' ').trim();return v.length()>max?v.substring(0,max):v;}

    private void close(){ if(!stopping.compareAndSet(false,true))return; NeverLauncherApiClient current=api; if(current!=null){current.publishEvent("server.shutdown",Map.of("platform","sponge"));current.flushEventsNow();current.closeEventStreamCleanly();} workers.shutdownNow(); }
}

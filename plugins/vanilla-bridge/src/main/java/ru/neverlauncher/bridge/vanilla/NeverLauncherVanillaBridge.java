package ru.neverlauncher.bridge.vanilla;

import ru.neverlauncher.bridge.common.*;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Production sidecar for stock Mojang dedicated servers. Vanilla has no plugin
 * lifecycle/login API, therefore this adapter deliberately exposes no LOGIN_GATE
 * capability. It integrates via local RCON + bounded latest.log tailing and the
 * same signed ServerBridge v3 runtime/control/event transport as native adapters.
 */
public final class NeverLauncherVanillaBridge implements AutoCloseable {
    private static final Pattern LIST = Pattern.compile("There are (\\d+) of a max of (\\d+) players online", Pattern.CASE_INSENSITIVE);
    private static final Pattern JOIN = Pattern.compile("(?:\\]: )?([A-Za-z0-9_]{1,16}) joined the game");
    private static final Pattern QUIT = Pattern.compile("(?:\\]: )?([A-Za-z0-9_]{1,16}) left the game");
    private static final Pattern LOST = Pattern.compile("(?:\\]: )?([A-Za-z0-9_]{1,16}) lost connection: (.+)");
    private static final Pattern VERSION = Pattern.compile("Starting minecraft server version ([^\\s]+)", Pattern.CASE_INSENSITIVE);

    private final AtomicBoolean stopping = new AtomicBoolean();
    private final AtomicBoolean maintenance = new AtomicBoolean();
    private final AtomicBoolean draining = new AtomicBoolean();
    private final ScheduledExecutorService workers = Executors.newScheduledThreadPool(2, r -> daemon(r, "worker"));
    private final Path serverDir;
    private final Properties serverProperties;
    private final BridgeConfig config;
    private final NeverLauncherApiClient api;
    private final String artifactSha256;
    private final String rconHost;
    private final int rconPort;
    private final String rconPassword;
    private volatile long logOffset;

    public static void main(String[] args) throws Exception {
        NeverLauncherVanillaBridge bridge = new NeverLauncherVanillaBridge(args);
        Runtime.getRuntime().addShutdownHook(new Thread(bridge::close, "neverlauncher-vanilla-shutdown"));
        bridge.start();
        new CountDownLatch(1).await();
    }

    NeverLauncherVanillaBridge(String[] args) throws Exception {
        Map<String,String> cli = parseArgs(args);
        serverDir = Path.of(first(cli.get("server-dir"), System.getenv("NEVERLAUNCHER_VANILLA_SERVER_DIR"), ".")).toAbsolutePath().normalize();
        Path configPath = Path.of(first(cli.get("config"), System.getenv("NEVERLAUNCHER_VANILLA_CONFIG"), serverDir.resolve("config/neverlauncher-vanilla-bridge/config.yml").toString())).toAbsolutePath().normalize();
        config = BridgeConfig.load(configPath, "vanilla-main");
        serverProperties = loadProperties(serverDir.resolve("server.properties"));
        if (!Boolean.parseBoolean(serverProperties.getProperty("enable-rcon", "false"))) {
            throw new IllegalStateException("Vanilla adapter requires enable-rcon=true; bind RCON to a protected local/private interface");
        }
        rconHost = first(System.getenv("NEVERLAUNCHER_VANILLA_RCON_HOST"), "127.0.0.1");
        rconPort = parseInt(first(System.getenv("NEVERLAUNCHER_VANILLA_RCON_PORT"), serverProperties.getProperty("rcon.port"), "25575"), 25575);
        rconPassword = first(System.getenv("NEVERLAUNCHER_VANILLA_RCON_PASSWORD"), serverProperties.getProperty("rcon.password"), "");
        if (rconPassword.isBlank()) throw new IllegalStateException("Vanilla RCON password is empty");

        artifactSha256 = BridgeIntegrity.artifactSha256(getClass());
        if (config.requireIntegrity && !BridgeIntegrity.isSha256(artifactSha256)) throw new IllegalStateException("cannot measure running Vanilla bridge JAR SHA-256");
        NodeIdentity identity = NodeIdentity.loadOrCreate(config.identityFile);
        BridgeRuntimeDescriptor descriptor = BridgeRuntimeDescriptor.of(
            discoverMinecraftVersion(), "vanilla", "Mojang Dedicated Server", "", "Vanilla dedicated server",
            List.of("heartbeat.signed", "artifact.sha256", "runtime.discovery", "runtime.ed25519-attestation", "telemetry.server-v1", "events.ordered-stream-v1", "control.secure-channel-v1", "sidecar.rcon", "sidecar.log-tail")
        );
        BridgeAdapterProfiles.rejectUncertifiedHybrid("vanilla", descriptor.serverBrand());
        api = new NeverLauncherApiClient(config, identity, "vanilla", BridgeDefaults.VERSION, artifactSha256, descriptor);
    }

    void start() throws Exception {
        // Verify credentials before publishing ready.
        rcon("list");
        api.setRoutingModes(false, false);
        api.startControlChannel(this::executeControl);
        api.publishEvent("server.startup", Map.of("platform", "vanilla", "adapter", "sidecar"));
        api.publishEvent("server.ready", Map.of("platform", "vanilla", "adapter", "sidecar"));
        workers.scheduleWithFixedDelay(this::heartbeatSafe, 0, Math.max(10, config.heartbeatIntervalSeconds), TimeUnit.SECONDS);
        workers.scheduleWithFixedDelay(this::telemetrySafe, 0, Math.max(5, config.telemetrySampleIntervalSeconds), TimeUnit.SECONDS);
        Thread tail = daemon(this::tailLog, "log-tail"); tail.start();
        System.out.println("NeverLauncher Vanilla ServerBridge " + BridgeDefaults.VERSION + " ready; serverId=" + config.serverId + "; runtimeId=" + api.runtimeId());
    }

    private BridgeControlResult executeControl(BridgeControlCommand command) throws Exception {
        Map<String,String> p = command.payload();
        return switch (command.type()) {
            case "player.kick" -> okRcon("kick " + username(p.get("username")) + " " + text(p.getOrDefault("reason", "Disconnected by server operator"), 512));
            case "message.broadcast" -> okRcon("tellraw @a " + jsonText(text(p.getOrDefault("message", ""), 1024)));
            case "whitelist.add" -> okRcon("whitelist add " + username(p.get("username")));
            case "whitelist.remove" -> okRcon("whitelist remove " + username(p.get("username")));
            case "whitelist.enable" -> okRcon("whitelist on");
            case "whitelist.disable" -> okRcon("whitelist off");
            case "ban.add" -> okRcon("ban " + username(p.get("username")) + " " + text(p.getOrDefault("reason", "Banned by server operator"), 512));
            case "ban.remove" -> okRcon("pardon " + username(p.get("username")));
            case "server.save" -> okRcon("save-all flush");
            case "server.maintenance" -> setRouteMode(true, Boolean.parseBoolean(p.getOrDefault("enabled", "false")));
            case "server.drain" -> setRouteMode(false, Boolean.parseBoolean(p.getOrDefault("enabled", "false")));
            case "server.shutdown" -> okRcon("stop");
            case "server.console" -> executeAllowlistedConsole(p.get("command"));
            default -> BridgeControlResult.unsupported("unsupported_control_type");
        };
    }

    private BridgeControlResult setRouteMode(boolean maintenanceMode, boolean enabled) {
        if (maintenanceMode) maintenance.set(enabled); else draining.set(enabled);
        api.setRoutingModes(maintenance.get(), draining.get());
        api.heartbeat("vanilla", BridgeDefaults.VERSION);
        return BridgeControlResult.ok(Map.of("enabled", Boolean.toString(enabled), "mode", maintenanceMode ? "maintenance" : "drain"));
    }
    private BridgeControlResult executeAllowlistedConsole(String command) throws Exception {
        if (!config.isConsoleCommandAllowed(command)) return BridgeControlResult.failed("console_command_not_allowlisted");
        return okRcon(text(command, 8192));
    }
    private BridgeControlResult okRcon(String command) throws Exception {
        String result = rcon(command);
        return BridgeControlResult.ok(Map.of("response", text(result, 1024)));
    }

    private void heartbeatSafe() { if (!stopping.get()) api.heartbeat("vanilla", BridgeDefaults.VERSION); }
    private void telemetrySafe() {
        if (stopping.get()) return;
        try {
            Matcher m = LIST.matcher(rcon("list"));
            if (!m.find()) return;
            int online = Integer.parseInt(m.group(1)); int max = Integer.parseInt(m.group(2));
            api.recordPlatformTelemetry(BridgePlatformTelemetry.server(null, null, online, max, null, null, null, null, false, List.of("players", "vanilla.rcon")));
        } catch (Exception e) { api.publishEvent("server.error", Map.of("component", "vanilla-rcon-telemetry", "message", text(e.getMessage(), 512))); }
    }
    private String rcon(String command) throws IOException {
        try (VanillaRconClient c = new VanillaRconClient(rconHost, rconPort, rconPassword, config.timeoutMs)) { return c.command(command); }
    }

    private void tailLog() {
        Path log = serverDir.resolve("logs/latest.log");
        while (!stopping.get()) {
            try {
                if (!Files.isRegularFile(log)) { Thread.sleep(1000); continue; }
                long size = Files.size(log); if (size < logOffset) logOffset = 0;
                try (RandomAccessFile raf = new RandomAccessFile(log.toFile(), "r")) {
                    raf.seek(logOffset); String raw;
                    while (!stopping.get() && (raw = raf.readLine()) != null) {
                        logOffset = raf.getFilePointer(); handleLogLine(new String(raw.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8));
                    }
                }
                Thread.sleep(500);
            } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
            catch (Exception e) { try { Thread.sleep(1000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return; } }
        }
    }
    private void handleLogLine(String line) {
        Matcher m = JOIN.matcher(line); if (m.find()) { api.publishEvent("player.join", Map.of("username", m.group(1), "source", "vanilla-log")); return; }
        m = QUIT.matcher(line); if (m.find()) { api.publishEvent("player.quit", Map.of("username", m.group(1), "source", "vanilla-log")); return; }
        m = LOST.matcher(line); if (m.find()) { api.publishEvent("player.kick", Map.of("username", m.group(1), "reason", text(m.group(2), 512), "source", "vanilla-log")); }
    }
    private String discoverMinecraftVersion() {
        Path log = serverDir.resolve("logs/latest.log");
        try {
            if (Files.isRegularFile(log)) {
                List<String> lines = Files.readAllLines(log, StandardCharsets.UTF_8);
                for (int i=Math.max(0,lines.size()-2000);i<lines.size();i++) { Matcher m=VERSION.matcher(lines.get(i)); if(m.find()) return m.group(1); }
            }
        } catch (IOException ignored) {}
        return BridgeRuntimeProbe.minecraftVersion();
    }

    @Override public void close() {
        if (!stopping.compareAndSet(false,true)) return;
        try { api.publishEvent("server.shutdown", Map.of("platform","vanilla","adapter","sidecar")); api.flushEventsNow(); } catch (RuntimeException ignored) {}
        api.closeEventStreamCleanly(); workers.shutdownNow();
    }

    private static Properties loadProperties(Path p) throws IOException { Properties x=new Properties(); try(var in=Files.newInputStream(p)){x.load(in);} return x; }
    private static Map<String,String> parseArgs(String[] args){ Map<String,String> out=new HashMap<>(); for(int i=0;args!=null&&i<args.length;i++){String a=args[i]; if(a.startsWith("--")&&i+1<args.length)out.put(a.substring(2),args[++i]);}return out;}
    private static int parseInt(String v,int d){try{return Integer.parseInt(v);}catch(Exception e){return d;}}
    private static String first(String... values){for(String v:values)if(v!=null&&!v.isBlank())return v.trim();return "";}
    private static String username(String s){String v=text(s,16);if(!v.matches("[A-Za-z0-9_]{1,16}"))throw new IllegalArgumentException("invalid_username");return v;}
    private static String text(String s,int max){String v=s==null?"":s.replace('\r',' ').replace('\n',' ').trim();return v.length()>max?v.substring(0,max):v;}
    private static String jsonText(String s){return "{\"text\":\""+text(s,1024).replace("\\","\\\\").replace("\"","\\\"")+"\"}";}
    private static Thread daemon(Runnable r,String role){Thread t=new Thread(r,"neverlauncher-vanilla-"+role);t.setDaemon(true);return t;}
}

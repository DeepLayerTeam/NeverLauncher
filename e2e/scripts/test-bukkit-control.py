#!/usr/bin/env python3
"""Run the shipping Bukkit/Folia command handlers against a deterministic API simulator.

This is an offline concurrency/command regression test, NOT a substitute for real
Paper/Purpur/Spigot/Folia server certification. Uses Java 21 with no network.
"""

import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCES = {
    "org/bukkit/Bukkit.java": r"""
package org.bukkit;
import java.util.*;
import org.bukkit.command.*;
import org.bukkit.entity.Player;
import org.bukkit.plugin.*;
public final class Bukkit {
 public static String brand="Paper";
 public static final List<Player> players=new ArrayList<>();
 public static final Map<String,OfflinePlayer> offline=new HashMap<>();
 public static boolean whitelist=false, commandHasEffect=true, commandAccepted=true, shutdownCalled=false;
 public static final org.bukkit.scheduler.BukkitScheduler scheduler=new org.bukkit.scheduler.BukkitScheduler();
 public static final org.bukkit.scheduler.GlobalRegionScheduler global=new org.bukkit.scheduler.GlobalRegionScheduler();
 public static final PluginManager manager=new PluginManager();
 public static String getName(){return brand;}
 public static String getVersion(){return "Test " + brand;}
 public static String getBukkitVersion(){return "1.21.1-R0.1";}
 public static PluginManager getPluginManager(){return manager;}
 public static boolean getOnlineMode(){return false;}
 public static List<Player> getOnlinePlayers(){return players;}
 public static int getMaxPlayers(){return 100;}
 public static List<World> getWorlds(){return List.of();}
 public static org.bukkit.scheduler.BukkitScheduler getScheduler(){return scheduler;}
 public static org.bukkit.scheduler.GlobalRegionScheduler getGlobalRegionScheduler(){return global;}
 public static Player getPlayerExact(String name){return players.stream().filter(p->p.getName().equals(name)).findFirst().orElse(null);}
 public static CommandSender getConsoleSender(){return new CommandSender(){};}
 public static OfflinePlayer getOfflinePlayer(String name){return offline.computeIfAbsent(name,n->new OfflinePlayer());}
 public static boolean hasWhitelist(){return whitelist;}
 public static int broadcasts=0;
 public static int broadcastMessage(String msg){broadcasts++;return players.size();}
 public static void shutdown(){shutdownCalled=true;}
 public static boolean dispatchCommand(CommandSender s,String raw){
   if (!commandAccepted) return false;
   if (commandHasEffect) {
    String[] parts=raw.split(" ");
    if (raw.startsWith("whitelist add ")) getOfflinePlayer(parts[2]).whitelisted=true;
    if (raw.startsWith("whitelist remove ")) getOfflinePlayer(parts[2]).whitelisted=false;
    if (raw.equals("whitelist on")) whitelist=true;
    if (raw.equals("whitelist off")) whitelist=false;
    if (raw.startsWith("ban ")) getOfflinePlayer(parts[1]).banned=true;
    if (raw.startsWith("pardon ")) getOfflinePlayer(parts[1]).banned=false;
   }
   return true;
 }
}
""",
    "org/bukkit/OfflinePlayer.java": "package org.bukkit; public class OfflinePlayer { public boolean whitelisted,banned; public boolean isWhitelisted(){return whitelisted;} public boolean isBanned(){return banned;} }",
    "org/bukkit/World.java": 'package org.bukkit; import java.util.UUID; public class World {public String getName(){return "world";} public UUID getUID(){return UUID.randomUUID();}}',
    "org/bukkit/Server.java": "package org.bukkit; import org.bukkit.plugin.PluginManager; public class Server {public PluginManager getPluginManager(){return Bukkit.manager;}}",
    "org/bukkit/command/Command.java": "package org.bukkit.command; public class Command {public void setExecutor(CommandExecutor e){} }",
    "org/bukkit/command/CommandSender.java": "package org.bukkit.command; public interface CommandSender {default boolean hasPermission(String name){return true;} default void sendMessage(String msg){} }",
    "org/bukkit/command/CommandExecutor.java": "package org.bukkit.command; public interface CommandExecutor {boolean onCommand(CommandSender s,Command c,String label,String[] args);}",
    "org/bukkit/event/Listener.java": "package org.bukkit.event; public interface Listener {}",
    "org/bukkit/event/EventHandler.java": "package org.bukkit.event; import java.lang.annotation.*; @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD) public @interface EventHandler {}",
    "org/bukkit/event/player/AsyncPlayerPreLoginEvent.java": 'package org.bukkit.event.player; import java.util.UUID; import java.net.InetAddress; public class AsyncPlayerPreLoginEvent {public enum Result{KICK_OTHER} public InetAddress getAddress(){return null;} public String getName(){return "Steve";} public UUID getUniqueId(){return UUID.randomUUID();} public void disallow(Result r,String m){} }',
    "org/bukkit/event/player/PlayerJoinEvent.java": "package org.bukkit.event.player; import org.bukkit.entity.Player; public record PlayerJoinEvent(Player getPlayer){}",
    "org/bukkit/event/player/PlayerQuitEvent.java": "package org.bukkit.event.player; import org.bukkit.entity.Player; public record PlayerQuitEvent(Player getPlayer){}",
    "org/bukkit/event/player/PlayerKickEvent.java": 'package org.bukkit.event.player; import org.bukkit.entity.Player; public record PlayerKickEvent(Player getPlayer){public String getReason(){return "reason";}}',
    "org/bukkit/event/world/WorldLoadEvent.java": "package org.bukkit.event.world; import org.bukkit.World; public record WorldLoadEvent(World getWorld){}",
    "org/bukkit/event/world/WorldUnloadEvent.java": "package org.bukkit.event.world; import org.bukkit.World; public record WorldUnloadEvent(World getWorld){}",
    "org/bukkit/plugin/Plugin.java": "package org.bukkit.plugin; public interface Plugin {}",
    "org/bukkit/plugin/PluginManager.java": "package org.bukkit.plugin; import org.bukkit.event.Listener; public class PluginManager { public Listener listener; public void registerEvents(Listener l,Plugin p){listener=l;} public void disablePlugin(Plugin p){ } }",
    "org/bukkit/plugin/java/JavaPlugin.java": """package org.bukkit.plugin.java;
import org.bukkit.*; import org.bukkit.command.*; import org.bukkit.plugin.*;
public class JavaPlugin implements Plugin {
 public void onEnable(){} public void onDisable(){}
 public org.bukkit.Server getServer(){return new Server();}
 public Command getCommand(String name){return new Command();}
 public java.util.logging.Logger getLogger(){return java.util.logging.Logger.getLogger("simulator");}
 public java.io.File getDataFolder(){return new java.io.File(System.getProperty("java.io.tmpdir"));}
}""",
    "org/bukkit/entity/Player.java": """package org.bukkit.entity;
import java.util.UUID; import org.bukkit.Bukkit; import org.bukkit.event.player.PlayerQuitEvent;
public class Player {
 public final String name; public UUID id=UUID.randomUUID(); public boolean emitQuit=true,failSend=false; public int kicks=0, messages=0;
 public Player(String name){this.name=name;}
 public String getName(){return name;} public UUID getUniqueId(){return id;}
 public void kickPlayer(String msg){kicks++; if(emitQuit){ Bukkit.players.remove(this); if(Bukkit.manager.listener instanceof ru.launcher.bridge.bukkit.BukkitFamilyBridgePlugin l) l.onPlayerQuit(new PlayerQuitEvent(this)); }}
 public void sendMessage(String msg){ if(failSend)throw new IllegalStateException("send failed"); messages++; }
 public org.bukkit.scheduler.EntityScheduler getScheduler(){return new org.bukkit.scheduler.EntityScheduler();}
}""",
    "org/bukkit/scheduler/BukkitScheduler.java": """package org.bukkit.scheduler;
import org.bukkit.plugin.Plugin;
public class BukkitScheduler {
 public Object runTask(Plugin p,Runnable r){r.run();return new BukkitTask();}
 public Object runTaskTimer(Plugin p,Runnable r,long first,long period){return new BukkitTask();}
}""",
    "org/bukkit/scheduler/GlobalRegionScheduler.java": """package org.bukkit.scheduler;
import org.bukkit.plugin.Plugin; import java.util.function.Consumer;
public class GlobalRegionScheduler {
 public void execute(Plugin p,Runnable r){r.run();}
 public BukkitTask runAtFixedRate(Plugin p,Consumer<Object> task,long first,long period){return new BukkitTask();}
}""",
    "org/bukkit/scheduler/EntityScheduler.java": """package org.bukkit.scheduler;
import org.bukkit.plugin.Plugin;
public class EntityScheduler {public static boolean retire=false; public boolean execute(Plugin p,Runnable task,Runnable retired,long delay){if(retire){retired.run();return true;} task.run();return true;}}
""",
    "org/bukkit/scheduler/BukkitTask.java": "package org.bukkit.scheduler; public class BukkitTask {public void cancel(){}}",
    "ru/launcher/bridge/common/BridgeAdapterCapability.java": """package ru.launcher.bridge.common; public enum BridgeAdapterCapability {REGION_SAFE_SCHEDULER,PAPER_API_FAMILY,TELEMETRY_BOUNDED_WORLD_COUNTERS}""",
    "ru/launcher/bridge/common/BridgeAdapterProfile.java": """package ru.launcher.bridge.common; public class BridgeAdapterProfile {private String id;public BridgeAdapterProfile(String id){this.id=id;} public boolean supports(BridgeAdapterCapability c){return (id.equals("folia")&&c==BridgeAdapterCapability.REGION_SAFE_SCHEDULER) || ((id.equals("paper")||id.equals("purpur")) && c!=BridgeAdapterCapability.REGION_SAFE_SCHEDULER);}}""",
    "ru/launcher/bridge/common/BridgeAdapterProfiles.java": "package ru.launcher.bridge.common; public class BridgeAdapterProfiles {public static BridgeAdapterProfile require(String id){return new BridgeAdapterProfile(id);} public static void rejectUncertifiedHybrid(String id,String brand){} }",
    "ru/launcher/bridge/common/BridgeControlCommand.java": "package ru.launcher.bridge.common; import java.util.Map; public record BridgeControlCommand(String type,Map<String,String> payload){}",
    "ru/launcher/bridge/common/BridgeDefaults.java": 'package ru.launcher.bridge.common; public class BridgeDefaults {public static final String VERSION="0.41.5";}',
    "ru/launcher/bridge/common/BridgeIntegrity.java": 'package ru.launcher.bridge.common; public class BridgeIntegrity {public static String artifactSha256(Class<?> c){return "a".repeat(64);} public static boolean isSha256(String h){return h != null && h.matches("[0-9a-f]{64}");}}',
    "ru/launcher/bridge/common/BridgeRuntimeDescriptor.java": "package ru.launcher.bridge.common; import java.util.List; public record BridgeRuntimeDescriptor(String serverBrand){public static BridgeRuntimeDescriptor of(String a,String b,String c,String d,String e,List<String> f){return new BridgeRuntimeDescriptor(e);}}",
    "ru/launcher/bridge/common/BridgePlatformTelemetry.java": "package ru.launcher.bridge.common; import java.util.List; public class BridgePlatformTelemetry { public static BridgePlatformTelemetry server(Double t,Double m,int o,int max,Integer w,Integer d,Long c,Long e,boolean b,List<String> s){return new BridgePlatformTelemetry();}}",
    "ru/launcher/bridge/common/JoinValidationResult.java": 'package ru.launcher.bridge.common; public class JoinValidationResult { public boolean allowed=true;public String reason=""; public String userMessage(){return "";}}',
    "ru/launcher/bridge/common/NodeIdentity.java": 'package ru.launcher.bridge.common; import java.nio.file.Path; public class NodeIdentity { public static NodeIdentity loadOrCreate(Path p){return new NodeIdentity();} public String fingerprint(){return "fake";}}',
    "ru/launcher/bridge/common/BridgeConfig.java": """package ru.launcher.bridge.common;
import java.nio.file.Path;
public class BridgeConfig {public String serverId="simulation", backendUrl="local",failMode="deny",projectId="p",profileId="q",channel="stable";public boolean requireIntegrity=false,requireLauncherSession=false; public int heartbeatIntervalSeconds=30,telemetrySampleIntervalSeconds=60,telemetrySamplingBudgetMs=100;
public Path identityFile=Path.of("/tmp/test-id");
public static BridgeConfig load(Path path,String name){return new BridgeConfig();}
public boolean isConsoleCommandAllowed(String cmd){return cmd.startsWith("say ");}
}""",
    "ru/launcher/bridge/common/LauncherApiClient.java": """package ru.launcher.bridge.common;
import java.util.Map;
public class LauncherApiClient { public LauncherApiClient(BridgeConfig c,NodeIdentity i,String a,String b,String d,BridgeRuntimeDescriptor e){}
public JoinValidationResult validateJoin(String name,String id,String ip,boolean online){return new JoinValidationResult();}
public void startControlChannel(ControlExecutor e){} public void publishEvent(String name,Map<String,String> payload){}
public String runtimeId(){return "runtime";}
public void flushEventsNow(){} public void closeEventStreamCleanly(){} public void setRoutingModes(boolean a,boolean b){}
public boolean heartbeat(String a,String b){return true;} public void recordPlatformTelemetry(BridgePlatformTelemetry m){}
public interface ControlExecutor {BridgeControlResult execute(BridgeControlCommand c) throws Exception;}
}""",
    "test/Control0415Harness.java": r"""
package test;
import java.lang.reflect.*; import java.util.*;
import org.bukkit.Bukkit; import org.bukkit.entity.Player;
import ru.launcher.bridge.bukkit.*;
import ru.launcher.bridge.common.*;
public final class Control0415Harness {
 static int assertions;
 static void check(boolean valid,String why) {assertions++;if(!valid)throw new AssertionError(why);}
 static BridgeControlResult call(BukkitFamilyBridgePlugin plugin,String name,Map<String,String> payload)throws Exception {
  Method method=BukkitFamilyBridgePlugin.class.getDeclaredMethod("executeControl",BridgeControlCommand.class);
  method.setAccessible(true);
  try{return (BridgeControlResult)method.invoke(plugin,new BridgeControlCommand(name,payload));}
  catch(InvocationTargetException e){throw new RuntimeException(e.getCause());}
 }
 static void status(BridgeControlResult r,String expected) {check(expected.equals(r.status()),"expected "+expected+" got "+r);}
 static BukkitFamilyBridgePlugin newPlugin(String brand) {
  Bukkit.brand=brand;
  Bukkit.players.clear(); Bukkit.offline.clear(); Bukkit.whitelist=false;
  Bukkit.commandAccepted=true; Bukkit.commandHasEffect=true;
  BukkitFamilyBridgePlugin plugin=switch(brand) {
   case "Spigot" -> new ru.launcher.bridge.spigot.LauncherSpigotBridge();
   case "Paper" -> new ru.launcher.bridge.paper.LauncherPaperBridge();
   case "Purpur" -> new ru.launcher.bridge.purpur.LauncherPurpurBridge();
   case "Folia" -> new ru.launcher.bridge.folia.LauncherFoliaBridge();
   default -> throw new IllegalArgumentException(brand);
  };
  plugin.onEnable(); return plugin;
 }
 static void test(String brand) throws Exception {
  BukkitFamilyBridgePlugin plugin=newPlugin(brand);
  try {
   status(call(plugin,"whitelist.add",Map.of("username","Steve")),"succeeded");
   check(Bukkit.getOfflinePlayer("Steve").isWhitelisted(),"whitelist was not applied");
   status(call(plugin,"whitelist.remove",Map.of("username","Steve")),"succeeded");
   status(call(plugin,"whitelist.enable",Map.of()),"succeeded");
   check(Bukkit.hasWhitelist(),"whitelist not enabled");
   status(call(plugin,"whitelist.disable",Map.of()),"succeeded");
   status(call(plugin,"ban.add",Map.of("username","Steve")),"succeeded");
   check(Bukkit.getOfflinePlayer("Steve").isBanned(),"ban not applied");
   status(call(plugin,"ban.remove",Map.of("username","Steve")),"succeeded");
   check(!Bukkit.getOfflinePlayer("Steve").isBanned(),"ban not removed");
   Bukkit.commandHasEffect=false;
   status(call(plugin,"ban.add",Map.of("username","Steve")),"indeterminate");
   status(call(plugin,"whitelist.add",Map.of("username","Steve")),"indeterminate");
   Bukkit.commandHasEffect=true;
   Bukkit.commandAccepted=false;
   status(call(plugin,"ban.add",Map.of("username","Steve")),"failed");
   Bukkit.commandAccepted=true;
   status(call(plugin,"server.save",Map.of()),"executed");
   status(call(plugin,"server.console",Map.of("command","say hello")),"executed");
   status(call(plugin,"server.console",Map.of("command","op Steve")),"failed");
   status(call(plugin,"server.maintenance",Map.of("enabled","true")),"succeeded");
   status(call(plugin,"server.drain",Map.of("enabled","true")),"succeeded");
   status(call(plugin,"player.kick",Map.of("username","Unknown")),"failed");
   Player steve=new Player("Steve"); Bukkit.players.add(steve);
   BridgeControlResult kicked=call(plugin,"player.kick",Map.of("username","Steve"));
   status(kicked,"succeeded");
   check(kicked.result().get("verification").equals("player-quit-event"),"missing quit evidence");
   check(steve.kicks==1,"kick invoked twice");
   if (brand.equals("Folia")) {
    Player alex=new Player("Alex"); Player bob=new Player("Bob");
    Bukkit.players.add(alex); Bukkit.players.add(bob);
    status(call(plugin,"message.broadcast",Map.of("message","hi")),"executed");
    check(alex.messages==1 && bob.messages==1,"Folia per-entity delivery failed");
    bob.failSend=true;
    status(call(plugin,"message.broadcast",Map.of("message","hi")),"indeterminate");
    org.bukkit.scheduler.EntityScheduler.retire=true;
    status(call(plugin,"message.broadcast",Map.of("message","retired")),"indeterminate");
    Player retired=new Player("Retired"); Bukkit.players.add(retired);
    status(call(plugin,"player.kick",Map.of("username","Retired")),"indeterminate");
    check(retired.kicks==0,"retired entity was kicked");
    org.bukkit.scheduler.EntityScheduler.retire=false;
   } else {
    status(call(plugin,"message.broadcast",Map.of("message","hi")),"executed");
   }
   status(call(plugin,"server.shutdown",Map.of()),"accepted");
   // A command awaiting a real quit must not receive optimistic success.
   Player ghost=new Player("Ghost"); ghost.emitQuit=false; Bukkit.players.add(ghost);
   java.util.concurrent.CompletableFuture<BridgeControlResult> waiting=java.util.concurrent.CompletableFuture.supplyAsync(() -> {
     try {return call(plugin,"player.kick",Map.of("username","Ghost"));}
     catch(Exception e){throw new RuntimeException(e);}
   });
   for(int i=0;i<100 && ghost.kicks==0;i++) Thread.sleep(5L);
   check(ghost.kicks==1,"first kick not scheduled");
   status(call(plugin,"player.kick",Map.of("username","Ghost")),"failed");
   check(ghost.kicks==1,"duplicate kick was physically repeated");
   plugin.onDisable();
   status(waiting.get(2,java.util.concurrent.TimeUnit.SECONDS),"indeterminate");
  } finally {plugin.onDisable();}
 }
 public static void main(String[] args)throws Exception {
  for(String brand:List.of("Spigot","Paper","Purpur","Folia")){test(brand);System.out.println(brand+" command-path PASS");}
  System.out.println("Bukkit-family offline test PASS ("+assertions+" assertions)");
 }
}
""",
}

with tempfile.TemporaryDirectory(prefix="launcher-bukkit-0415-") as tmp:
    source = pathlib.Path(tmp) / "sources"
    output = pathlib.Path(tmp) / "classes"
    output.mkdir()
    for name, body in SOURCES.items():
        dest = source / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding="utf-8")
    production = [
        ROOT
        / "plugins/bridge-common/src/main/java/ru/launcher/bridge/common/BridgeControlResult.java",
        ROOT
        / "plugins/bukkit-family-common/src/main/java/ru/launcher/bridge/bukkit/BukkitFamilyPlatform.java",
        ROOT
        / "plugins/bukkit-family-common/src/main/java/ru/launcher/bridge/bukkit/BukkitFamilyBridgePlugin.java",
    ]
    for platform in ("spigot", "paper", "purpur", "folia"):
        production.extend(
            (ROOT / f"plugins/{platform}-bridge/src/main/java").rglob("*.java")
        )
    cmd = (
        ["javac", "--release", "21", "-d", str(output)]
        + [str(p) for p in source.rglob("*.java")]
        + [str(p) for p in production]
    )
    subprocess.run(cmd, check=True)
    subprocess.run(["java", "-cp", str(output), "test.Control0415Harness"], check=True)

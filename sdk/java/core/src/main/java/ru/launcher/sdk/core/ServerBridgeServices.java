package ru.launcher.sdk.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;

/** Permission-scoped ServerBridge v3 integration over the existing Go Host broker.
 * Read methods never expose node public/private credentials. Operational commands
 * enter the durable ServerBridge queue; an accepted command is not an executed one.
 */
public final class ServerBridgeServices {
    private final HostSession host;
    private final RuntimeEvents events;
    ServerBridgeServices(HostSession host, RuntimeEvents events) {
        this.host = Objects.requireNonNull(host); this.events = Objects.requireNonNull(events);
    }
    public record Server(String id,String projectId,String profileId,String name,String kind,String status,
                         int protocolVersion,long runtimeEpoch,boolean runtimeActive,String lastHeartbeatAt,
                         int playersOnline,String serverBrand,String minecraftVersion) {}
    public record Page<T>(List<T> items,Integer nextOffset) {
        public Page { items=List.copyOf(items); }
    }
    public record Command(String id,String serverId,String type,String status,int attempt,long runtimeEpoch,
                          String createdAt,String updatedAt,String expiresAt,String completedAt) {}
    public record Receipt(Command command,boolean idempotentReplay) {}
    public record ServerEvent(String serverId,String runtimeId,long sequence,String eventId,String type,
                              long occurredAtUnixMillis,Map<String,String> payload) {
        public ServerEvent { payload=Map.copyOf(payload); }
    }
    private static String id(String value,String name) {
        if(value==null||!value.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"))
            throw new IllegalArgumentException("invalid " + name);
        return value;
    }
    private static String str(Map<String,Object> m,String k){
        Object v=m.get(k);
        if(v==null)return "";
        if(!(v instanceof String s))throw new IllegalArgumentException("invalid "+k);
        return s;
    }
    private static String required(Map<String,Object> m,String k){return id(str(m,k),k);}
    private static long numeric(Map<String,Object> m,String k){
        Object v=m.get(k);
        if(!(v instanceof Number n)||n.doubleValue()!=n.longValue()||n.longValue()<0)
            throw new IllegalArgumentException("invalid "+k);
        return n.longValue();
    }
    private static int integer(Map<String,Object> m,String k){
        long n=numeric(m,k);if(n>Integer.MAX_VALUE)throw new IllegalArgumentException("overflow "+k);
        return (int)n;
    }
    private static Server decodeServer(Map<String,Object> m){
        Object raw=m.get("runtimeActive");if(!(raw instanceof Boolean active))throw new IllegalArgumentException("invalid runtimeActive");
        return new Server(required(m,"id"),required(m,"projectId"),str(m,"profileId"),str(m,"name"),str(m,"kind"),
                str(m,"status"),integer(m,"protocolVersion"),numeric(m,"runtimeEpoch"),active,str(m,"lastHeartbeatAt"),
                integer(m,"playersOnline"),str(m,"serverBrand"),str(m,"minecraftVersion"));
    }
    private static Command decodeCommand(Map<String,Object> m){
        return new Command(required(m,"id"),required(m,"serverId"),required(m,"type"),required(m,"status"),
                integer(m,"attempt"),numeric(m,"runtimeEpoch"),str(m,"createdAt"),str(m,"updatedAt"),
                str(m,"expiresAt"),str(m,"completedAt"));
    }
    private static Map<String,Object> scope(String projectId){return Map.of("projectId",id(projectId,"projectId"));}
    private Map<String,Object> call(String method, Map<String,Object> payload)throws IOException,InterruptedException {
        return host.capability(method,payload);
    }
    /** Live status; serverbridge:read on this project. */
    public Server server(String projectId,String serverId)throws IOException,InterruptedException {
        Map<String,Object> req=new LinkedHashMap<>(scope(projectId));req.put("serverId",id(serverId,"serverId"));
        Server result=decodeServer(Json.object(call("bridge.server",req).get("server")));
        if(!projectId.equals(result.projectId())||!serverId.equals(result.id()))throw new SecurityException("server scope changed");
        return result;
    }
    /** Bounded, stable ID-ordered project-scoped list. */
    public Page<Server> servers(String projectId,int offset,int limit)throws IOException,InterruptedException {
        if(offset<0||offset>1_000_000||limit<1||limit>50)throw new IllegalArgumentException("invalid page");
        Map<String,Object> req=new LinkedHashMap<>(scope(projectId));req.put("offset",offset);req.put("limit",limit);
        Map<String,Object> result=call("bridge.servers",req);
        if(!(result.get("items") instanceof List<?> items)||items.size()>limit)throw new IllegalArgumentException("invalid server page");
        List<Server> servers=new ArrayList<>();
        for(Object raw:items) {
            Server server=decodeServer(Json.object(raw));
            if(!projectId.equals(server.projectId()))throw new SecurityException("cross-project ServerBridge result");
            servers.add(server);
        }
        Integer next=null;
        if(result.containsKey("nextOffset")) {
            long value=numeric(result,"nextOffset");
            if(value<=offset||value>1_000_000)throw new IllegalArgumentException("invalid server cursor");
            next=(int)value;
        }
        return new Page<>(servers,next);
    }
    /** Advisory existing join-ticket check, never a Minecraft login/admission authorization.
     * Official session validation and atomic ticket redemption remain exclusively in ServerBridge.
     * Requires both serverbridge:read and project:read.
     */
    public boolean pendingJoinTicket(String projectId,String serverId,String username)throws IOException,InterruptedException {
        if(username==null||!username.matches("[A-Za-z0-9_]{3,16}"))throw new IllegalArgumentException("invalid Minecraft username");
        Map<String,Object> req=new LinkedHashMap<>(scope(projectId));
        req.put("serverId",id(serverId,"serverId"));req.put("username",username);
        Object pending=call("bridge.access.ticket",req).get("pendingTicket");
        if(!(pending instanceof Boolean result))throw new IllegalArgumentException("invalid join-ticket response");
        return result;
    }
    /** Commands are persisted for delivery to the authenticated runtime. They are NOT executed synchronously.
     * Requires serverbridge:read plus the command's game-server permission. Console/shutdown are not supported.
     */
    public Receipt command(String projectId,String serverId,String type,Map<String,String> payload,
                           String idempotencyKey,int expiresInSeconds)throws IOException,InterruptedException {
        id(projectId,"projectId");id(serverId,"serverId");
        if(type==null||!Set.of("message.broadcast","player.kick","whitelist.add","whitelist.remove","whitelist.enable",
                "whitelist.disable","ban.add","ban.remove","server.save","server.maintenance","server.drain").contains(type))
            throw new IllegalArgumentException("unsupported command");
        if(payload==null||payload.size()>16)throw new IllegalArgumentException("invalid payload");
        if(idempotencyKey==null||idempotencyKey.length()<8||idempotencyKey.length()>128||
                idempotencyKey.indexOf('\n')>=0||idempotencyKey.indexOf('\r')>=0)
            throw new IllegalArgumentException("invalid idempotencyKey");
        if(expiresInSeconds!=0&&(expiresInSeconds<10||expiresInSeconds>600))throw new IllegalArgumentException("invalid expiry");
        Map<String,Object> req=new LinkedHashMap<>(scope(projectId));
        req.put("serverId",serverId);req.put("commandType",type);req.put("payload",Map.copyOf(payload));
        req.put("idempotencyKey",idempotencyKey);req.put("expiresInSeconds",expiresInSeconds);
        Map<String,Object> result=call("bridge.command.create",req);
        Command command=decodeCommand(Json.object(result.get("command")));
        if(!serverId.equals(command.serverId())||!type.equals(command.type()))throw new SecurityException("command result mismatch");
        if(!(result.get("idempotentReplay") instanceof Boolean replay))throw new IllegalArgumentException("missing replay state");
        return new Receipt(command,replay);
    }
    /** Recheck a durable command's state; pending/leased is not successful completion. */
    public Command commandStatus(String projectId,String serverId,String commandId)throws IOException,InterruptedException {
        Map<String,Object> req=new LinkedHashMap<>(scope(projectId));
        req.put("serverId",id(serverId,"serverId"));req.put("commandId",id(commandId,"commandId"));
        Command cmd=decodeCommand(Json.object(call("bridge.command.get",req).get("command")));
        if(!serverId.equals(cmd.serverId())||!commandId.equals(cmd.id()))throw new SecurityException("command scope changed");
        return cmd;
    }
    private static ServerEvent decodeEvent(Object value){
        Map<String,Object> m=Json.object(value);
        Map<String,Object> event=Json.object(m.get("event"));
        Map<String,Object> raw=Json.object(event.get("payload"));
        if(raw.size()>32)throw new IllegalArgumentException("too many event fields");
        Map<String,String> values=new LinkedHashMap<>();
        for(var item:raw.entrySet()) {
            if(!(item.getValue() instanceof String s)||s.length()>4096)throw new IllegalArgumentException("invalid event field");
            values.put(item.getKey(),s);
        }
        return new ServerEvent(required(m,"serverId"),required(m,"runtimeId"),numeric(event,"sequence"),
                required(event,"eventId"),required(event,"type"),numeric(event,"occurredAtUnixMillis"),values);
    }
    /** Existing signed ServerBridge event stream -> durable Go EventBus -> Java callback.
     * Delivery remains at-least-once, ordered by the event bus aggregate key.
     */
    public long subscribeEvents(RuntimeEvents.DetailedListener<ServerEvent> listener)throws IOException,InterruptedException {
        Objects.requireNonNull(listener);
        return events.subscribeDetailed("serverbridge.event.received","async",null,ServerBridgeServices::decodeEvent,listener);
    }
}

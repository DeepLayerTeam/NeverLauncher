package ru.neverlauncher.bridge.common;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

final class BridgeControlJournal {
    record State(String digest,String phase,BridgeControlResult result) {}
    private final Path path;
    private final Properties props = new Properties();

    BridgeControlJournal(Path path) throws IOException {
        this.path=path.toAbsolutePath().normalize();
        if(Files.exists(this.path)){try(var in=Files.newInputStream(this.path)){props.load(in);}}
    }

    synchronized String channelId(String runtimeId) throws IOException {
        String normalizedRuntime = runtimeId == null ? "" : runtimeId.trim().toLowerCase(java.util.Locale.ROOT);
        String currentRuntime = props.getProperty("_channel.runtimeId", "");
        String currentId = props.getProperty("_channel.id", "");
        if (!normalizedRuntime.isBlank() && normalizedRuntime.equals(currentRuntime) && currentId.matches("[a-f0-9]{32}")) return currentId;
        String id = java.util.UUID.randomUUID().toString().replace("-", "").toLowerCase(java.util.Locale.ROOT);
        props.setProperty("_channel.runtimeId", normalizedRuntime);
        props.setProperty("_channel.id", id);
        props.setProperty("_channel.ackedSequence", "0");
        persist();
        return id;
    }

    synchronized long acknowledgedSequence() {
        try { return Math.max(0L, Long.parseLong(props.getProperty("_channel.ackedSequence", "0"))); }
        catch (NumberFormatException ignored) { return 0L; }
    }

    synchronized void acknowledgeSequence(long sequence) throws IOException {
        if (sequence <= acknowledgedSequence()) return;
        props.setProperty("_channel.ackedSequence", Long.toString(sequence));
        persist();
    }

    synchronized State state(BridgeControlCommand command) {
        String prefix=command.commandId()+"."; String digest=props.getProperty(prefix+"digest","");
        if(digest.isBlank()) return null;
        if(!digest.equals(command.digest())) throw new IllegalStateException("control command id reused with different signed digest");
        String phase=props.getProperty(prefix+"phase","");
        if("done".equals(phase)) {
            String status=props.getProperty(prefix+"status","failed");
            Map<String,String> result=BridgeControlCommand.decodePayload(props.getProperty(prefix+"result",""));
            String error=decode(props.getProperty(prefix+"error",""));
            return new State(digest,phase,new BridgeControlResult(status,result,error));
        }
        return new State(digest,phase,null);
    }

    synchronized void begin(BridgeControlCommand command) throws IOException {
        String prefix=command.commandId()+"."; String existing=props.getProperty(prefix+"digest","");
        if(!existing.isBlank()&&!existing.equals(command.digest()))throw new IOException("control command digest conflict");
        props.setProperty(prefix+"digest",command.digest()); props.setProperty(prefix+"phase","executing"); props.setProperty(prefix+"updated",Long.toString(System.currentTimeMillis())); persist();
    }

    synchronized void complete(BridgeControlCommand command,BridgeControlResult result)throws IOException{
        String prefix=command.commandId()+"."; props.setProperty(prefix+"digest",command.digest()); props.setProperty(prefix+"phase","done"); props.setProperty(prefix+"status",result.status()); props.setProperty(prefix+"result",BridgeControlCommand.encodeMap(result.result())); props.setProperty(prefix+"error",encode(result.error())); props.setProperty(prefix+"updated",Long.toString(System.currentTimeMillis())); compact(); persist();
    }

    private void compact(){
        if(props.size()<2048)return;
        Map<String,Long> ids=new LinkedHashMap<>(); for(String k:props.stringPropertyNames()){int dot=k.indexOf('.');if(dot>0&&k.endsWith(".updated")){try{ids.put(k.substring(0,dot),Long.parseLong(props.getProperty(k,"0")));}catch(Exception ignored){}}}
        if(ids.size()<=256)return; var sorted=ids.entrySet().stream().sorted(Map.Entry.comparingByValue()).toList(); int remove=Math.max(0,sorted.size()-256); for(int i=0;i<remove;i++){String id=sorted.get(i).getKey(); for(String suffix:new String[]{"digest","phase","status","result","error","updated"})props.remove(id+"."+suffix);}
    }

    private void persist() throws IOException {
        Path parent=path.getParent(); if(parent!=null)Files.createDirectories(parent); Path tmp=path.resolveSibling(path.getFileName()+".tmp");
        try(var out=Files.newOutputStream(tmp,StandardOpenOption.CREATE,StandardOpenOption.TRUNCATE_EXISTING,StandardOpenOption.WRITE)){props.store(out,"NeverLauncher ServerBridge control journal");}
        try(var ch=FileChannel.open(tmp,StandardOpenOption.WRITE)){ch.force(true);} setOwnerOnly(tmp); try { Files.move(tmp,path,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE); } catch (java.nio.file.AtomicMoveNotSupportedException e) { Files.move(tmp,path,StandardCopyOption.REPLACE_EXISTING); } setOwnerOnly(path);
    }
    private static String encode(String v){return Base64.getUrlEncoder().withoutPadding().encodeToString((v==null?"":v).getBytes(StandardCharsets.UTF_8));}
    private static String decode(String v){try{return new String(Base64.getUrlDecoder().decode(v),StandardCharsets.UTF_8);}catch(Exception e){return "";}}
    private static void setOwnerOnly(Path p){try{Files.setPosixFilePermissions(p,java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));}catch(Exception ignored){}}
}

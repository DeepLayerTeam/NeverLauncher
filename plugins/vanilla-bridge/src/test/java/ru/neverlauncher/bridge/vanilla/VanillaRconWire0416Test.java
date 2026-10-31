package ru.launcher.bridge.vanilla;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;

/** Real localhost TCP/RCON wire exchange; does not pretend to run a Minecraft server. */
public final class VanillaRconWire0416Test {
    private record Packet(int id, int type, String body) {}
    private static int readInt(InputStream in) throws IOException {
        int a=in.read(),b=in.read(),c=in.read(),d=in.read();
        if ((a|b|c|d)<0) throw new EOFException();
        return a|(b<<8)|(c<<16)|(d<<24);
    }
    private static void writeInt(OutputStream out,int n)throws IOException{
        out.write(n);out.write(n>>8);out.write(n>>16);out.write(n>>24);
    }
    private static Packet read(InputStream stream)throws IOException{
        int size=readInt(stream);
        if(size<10||size>65536)throw new IOException("bad request packet");
        byte[] b=stream.readNBytes(size);
        if(b.length!=size)throw new EOFException();
        int id=(b[0]&255)|((b[1]&255)<<8)|((b[2]&255)<<16)|((b[3]&255)<<24);
        int type=(b[4]&255)|((b[5]&255)<<8)|((b[6]&255)<<16)|((b[7]&255)<<24);
        return new Packet(id,type,new String(b,8,size-10,StandardCharsets.UTF_8));
    }
    private static void reply(OutputStream out,int id,int type,String body)throws IOException{
        byte[] value=body.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream buffer=new ByteArrayOutputStream();
        writeInt(buffer,value.length+10);writeInt(buffer,id);writeInt(buffer,type);buffer.write(value);buffer.write(0);buffer.write(0);
        byte[] bytes=buffer.toByteArray();
        // Split packets to ensure the Java side handles real TCP fragmentation.
        out.write(bytes,0,3);out.flush();out.write(bytes,3,bytes.length-3);out.flush();
    }
    public static void main(String[] args)throws Exception{
        try(ServerSocket listener=new ServerSocket(0,1,InetAddress.getLoopbackAddress())){
            var exec=Executors.newSingleThreadExecutor();
            Future<?> server=exec.submit(()->{
                try(Socket client=listener.accept()){
                    client.setSoTimeout(3000);
                    Packet auth=read(client.getInputStream());
                    if(auth.type()!=3||!auth.body().equals("secret"))throw new AssertionError("RCON auth");
                    reply(client.getOutputStream(),auth.id(),2,"");
                    Packet command=read(client.getInputStream());
                    if(command.type()!=2||!command.body().equals("whitelist list"))throw new AssertionError("RCON command");
                    reply(client.getOutputStream(),command.id(),0,"There are 2 whitelisted player(s): Steve, Alex");
                }catch(Exception e){throw new RuntimeException(e);}
            });
            try(VanillaRconClient client=new VanillaRconClient("127.0.0.1",listener.getLocalPort(),"secret",1000)){
                String reply=client.command("whitelist list");
                if(!Boolean.TRUE.equals(VanillaRconReadback.membership("whitelist.add","Steve",reply)))throw new AssertionError("RCON readback");
            }
            server.get(3,TimeUnit.SECONDS);
            exec.shutdownNow();
        }
        System.out.println("VanillaRconWire0416Test: TCP auth, command, split-packet readback PASS");
    }
}

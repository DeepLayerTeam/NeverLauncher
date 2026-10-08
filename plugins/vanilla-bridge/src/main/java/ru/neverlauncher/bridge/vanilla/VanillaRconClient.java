package ru.neverlauncher.bridge.vanilla;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/** Minimal bounded implementation of the Minecraft Source-RCON wire protocol. */
final class VanillaRconClient implements AutoCloseable {
    private static final int MAX_PACKET = 1024 * 1024;
    private final Socket socket = new Socket();
    private final DataInputStream in;
    private final DataOutputStream out;
    private final AtomicInteger ids = new AtomicInteger(10);

    VanillaRconClient(String host, int port, String password, int timeoutMs) throws IOException {
        socket.connect(new InetSocketAddress(host, port), Math.max(500, timeoutMs));
        socket.setSoTimeout(Math.max(500, timeoutMs));
        in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
        int id = ids.incrementAndGet();
        send(id, 3, password == null ? "" : password);
        Packet response = read();
        if (response.id == -1 || response.id != id) throw new IOException("Minecraft RCON authentication failed");
    }

    synchronized String command(String command) throws IOException {
        String value = command == null ? "" : command.replace('\r', ' ').replace('\n', ' ').trim();
        if (value.isBlank() || value.length() > 8192) throw new IOException("invalid RCON command length");
        int id = ids.incrementAndGet();
        send(id, 2, value);
        Packet response = read();
        if (response.id != id) throw new IOException("RCON response id mismatch");
        return response.body;
    }

    private void send(int id, int type, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        int length = 4 + 4 + payload.length + 2;
        if (length > MAX_PACKET) throw new IOException("RCON packet too large");
        writeLEInt(out, length); writeLEInt(out, id); writeLEInt(out, type);
        out.write(payload); out.writeByte(0); out.writeByte(0); out.flush();
    }

    private Packet read() throws IOException {
        int length = readLEInt(in);
        if (length < 10 || length > MAX_PACKET) throw new IOException("invalid RCON packet length");
        byte[] packet = in.readNBytes(length);
        if (packet.length != length) throw new EOFException("truncated RCON packet");
        int id = leInt(packet, 0); int type = leInt(packet, 4);
        int bodyLen = length - 10;
        if (packet[length - 2] != 0 || packet[length - 1] != 0) throw new IOException("invalid RCON terminator");
        return new Packet(id, type, new String(packet, 8, bodyLen, StandardCharsets.UTF_8));
    }

    private static void writeLEInt(DataOutputStream out, int v) throws IOException {
        out.writeByte(v); out.writeByte(v >>> 8); out.writeByte(v >>> 16); out.writeByte(v >>> 24);
    }
    private static int readLEInt(DataInputStream in) throws IOException {
        return (in.readUnsignedByte()) | (in.readUnsignedByte() << 8) | (in.readUnsignedByte() << 16) | (in.readUnsignedByte() << 24);
    }
    private static int leInt(byte[] b, int o) { return (b[o]&255)|((b[o+1]&255)<<8)|((b[o+2]&255)<<16)|((b[o+3]&255)<<24); }
    private record Packet(int id, int type, String body) {}
    @Override public void close() throws IOException { socket.close(); }
}

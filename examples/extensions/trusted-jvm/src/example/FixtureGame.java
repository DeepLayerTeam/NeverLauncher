package example;
public final class FixtureGame {
    public static void main(String[] args) throws Exception {
        Class.forName("net.minecraft.client.Minecraft");
        if (args.length != 2 || !args[0].equals("hello world")) throw new IllegalStateException("Аргументы Minecraft изменились");
        if (args[1].equals("fail")) throw new IllegalStateException("Имитация аварийного завершения Minecraft");
        java.nio.file.Files.write(java.nio.file.Paths.get(System.getProperty("launcher.trusted.game.log")), "game-started".getBytes("UTF-8"));
    }
}

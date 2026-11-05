package net.minecraft.client.main;
public final class Main {
    public static void main(String[] args) {
        if (!"MIGRATED".equals("ORIGINAL")) throw new IllegalStateException("Байты класса не были преобразованы");
        System.out.println("GAME_HOOK_TRANSFORMED");
    }
}

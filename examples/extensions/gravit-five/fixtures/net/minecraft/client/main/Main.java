package net.minecraft.client.main;
public final class Main {
    public static void main(String[] args) {
        if (!"MIGRATED".equals("ORIGINAL")) throw new IllegalStateException("class bytes were not transformed");
        System.out.println("GAME_HOOK_TRANSFORMED");
    }
}

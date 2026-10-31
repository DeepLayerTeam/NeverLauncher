package ru.launcher.bridge.vanilla;

public final class VanillaRconReadback0416Test {
    private static void check(boolean result,String name) {if(!result)throw new AssertionError(name);}
    public static void main(String[] args) {
        check(Boolean.TRUE.equals(VanillaRconReadback.membership("whitelist.add","Steve","There are 2 whitelisted players: Steve, Alex")),"positive whitelist");
        check(Boolean.FALSE.equals(VanillaRconReadback.membership("whitelist.remove","Steve","There are 1 whitelisted player(s): Alex")),"negative whitelist");
        check(Boolean.TRUE.equals(VanillaRconReadback.membership("ban.add","Griefer","There are 1 ban(s): Griefer")),"positive ban");
        check(Boolean.FALSE.equals(VanillaRconReadback.membership("ban.remove","Griefer","There are no bans")),"empty bans");
        check(VanillaRconReadback.membership("ban.add","Steve","There are 2 bans: Steve") == null,"truncated list inconclusive");
        check(VanillaRconReadback.membership("ban.add","Steve","Response incomplete") == null,"unknown locale inconclusive");
        check(VanillaRconReadback.membership("ban.add","Steve","There are 2 bans: Alex, Steve, Another") == null,"ambiguous count");
        check(VanillaRconReadback.rejected("Unknown or incomplete command, see below for error"),"reject unknown");
        check(!VanillaRconReadback.rejected("Added Steve to the whitelist"),"normal response");
        System.out.println("VanillaRconReadback0416Test: 9 assertions passed");
    }
}

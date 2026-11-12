package ru.launcher.bridge.vanilla;

public final class VanillaRconReadback0416Test {
    private static void check(boolean result,String name) {if(!result)throw new AssertionError(name);}
    public static void main(String[] args) {
        check(Boolean.TRUE.equals(VanillaRconReadback.membership("whitelist.add","Steve","There are 2 whitelisted players: Steve, Alex")),"игрок есть в списке разрешённых");
        check(Boolean.FALSE.equals(VanillaRconReadback.membership("whitelist.remove","Steve","There are 1 whitelisted player(s): Alex")),"игрок отсутствует в списке разрешённых");
        check(Boolean.TRUE.equals(VanillaRconReadback.membership("ban.add","Griefer","There are 1 ban(s): Griefer")),"игрок заблокирован");
        check(Boolean.FALSE.equals(VanillaRconReadback.membership("ban.remove","Griefer","There are no bans")),"список блокировок пуст");
        check(VanillaRconReadback.membership("ban.add","Steve","There are 2 bans: Steve") == null,"по обрезанному списку нельзя сделать вывод");
        check(VanillaRconReadback.membership("ban.add","Steve","Response incomplete") == null,"ответ на неизвестном языке не позволяет сделать вывод");
        check(VanillaRconReadback.membership("ban.add","Steve","There are 2 bans: Alex, Steve, Another") == null,"неоднозначное количество игроков");
        check(VanillaRconReadback.rejected("Unknown or incomplete command, see below for error"),"Неизвестная команда отклонена");
        check(!VanillaRconReadback.rejected("Added Steve to the whitelist"),"Обычный ответ");
        System.out.println("VanillaRconReadback0416Test: 9 проверок пройдено");
    }
}

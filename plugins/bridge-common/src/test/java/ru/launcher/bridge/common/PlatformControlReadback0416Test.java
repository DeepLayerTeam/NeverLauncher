package ru.launcher.bridge.common;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;

public final class PlatformControlReadback0416Test {
    public static final class Server {
        final PlayerList list = new PlayerList();
        public PlayerList getPlayerList() { return list; }
    }
    public static final class PlayerList {
        public boolean isUsingWhitelist() { return true; }
        public Names getWhiteList() { return new Names(new String[]{"Steve", "Alex"}); }
        public Names getBannedPlayers() { return new Names(new String[]{"Griefer"}); }
    }
    public static final class Names {
        private final String[] names;
        Names(String[] names) {this.names=names;}
        public String[] getUserList() {return names;}
    }
    public static final class UnknownServer {
        public Object getPlayerList() {return new Object();}
    }
    static void check(boolean pass, String description) {
        if (!pass) throw new AssertionError(description);
    }
    public static void main(String[] args) throws Exception {
        var server = new Server();
        check(PlatformControlReadback.whitelistEntry(server,"Steve",true).status().equals("succeeded"), "положительное чтение списка разрешённых игроков");
        check(PlatformControlReadback.whitelistEntry(server,"Steve",false).status().equals("failed"), "несоответствие списка разрешённых игроков");
        check(PlatformControlReadback.whitelistEntry(server,"Other",false).status().equals("succeeded"), "отрицательное чтение списка разрешённых игроков");
        check(PlatformControlReadback.banEntry(server,"Griefer",true).status().equals("succeeded"), "запрет подтверждён");
        check(PlatformControlReadback.banEntry(server,"Alex",false).status().equals("succeeded"), "запрет не подтверждён");
        check(PlatformControlReadback.whitelistMode(server,true).status().equals("succeeded"), "режим списка разрешённых игроков включён");
        check(PlatformControlReadback.whitelistMode(server,false).status().equals("failed"), "несоответствие режима списка разрешённых игроков");
        check(PlatformControlReadback.whitelistEntry(new UnknownServer(),"Steve",true).status().equals("executed"), "неизвестный API не должен проходить проверку");
        check(PlatformControlReadback.banEntry(null,"Steve",true).status().equals("executed"), "отсутствующий сервер не должен проходить проверку");
        var tracker = new KickConfirmations();
        UUID session = UUID.randomUUID();
        check(tracker.begin("Steve",session), "начало отслеживания");
        check(!tracker.begin("steve",session), "повторное начало отклонено");
        tracker.observedQuit("Steve",UUID.randomUUID().toString());
        var pool = Executors.newSingleThreadExecutor();
        try {
            var proof = pool.submit(() -> tracker.await("steve",session.toString(),500));
            Thread.sleep(40);
            tracker.observedQuit("STEVE",session.toString());
            var result=proof.get(2,TimeUnit.SECONDS);
            check(result.status().equals("succeeded") && result.result().get("uuid").equals(session.toString()) && result.result().get("verification").equals("player-quit-event"),"session-bound quit evidence");
            check(tracker.begin("Steve",session),"отслеживание после завершения");
            check(tracker.await("Steve",session.toString(),25).status().equals("executed"),"отсутствие выхода не подтверждено");
            check(tracker.begin("Steve",session),"отслеживание перед завершением работы");
            tracker.close();
            check(tracker.await("Steve",session.toString(),25).status().equals("executed"),"завершение работы не подтверждено");
            check(!tracker.begin("Steve",session),"закрытый модуль отслеживания отклоняет запрос");
        } finally { pool.shutdownNow(); }
        System.out.println("PlatformControlReadback0416Test: 19 проверок пройдено");
    }
}

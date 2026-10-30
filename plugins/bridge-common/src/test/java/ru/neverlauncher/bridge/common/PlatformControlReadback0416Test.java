package ru.neverlauncher.bridge.common;

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
        check(PlatformControlReadback.whitelistEntry(server,"Steve",true).status().equals("succeeded"), "whitelist positive readback");
        check(PlatformControlReadback.whitelistEntry(server,"Steve",false).status().equals("failed"), "whitelist mismatch");
        check(PlatformControlReadback.whitelistEntry(server,"Other",false).status().equals("succeeded"), "whitelist negative readback");
        check(PlatformControlReadback.banEntry(server,"Griefer",true).status().equals("succeeded"), "ban positive");
        check(PlatformControlReadback.banEntry(server,"Alex",false).status().equals("succeeded"), "ban negative");
        check(PlatformControlReadback.whitelistMode(server,true).status().equals("succeeded"), "whitelist mode true");
        check(PlatformControlReadback.whitelistMode(server,false).status().equals("failed"), "whitelist mode mismatch");
        check(PlatformControlReadback.whitelistEntry(new UnknownServer(),"Steve",true).status().equals("executed"), "unknown API must not verify");
        check(PlatformControlReadback.banEntry(null,"Steve",true).status().equals("executed"), "null server must not verify");
        var tracker = new KickConfirmations();
        UUID session = UUID.randomUUID();
        check(tracker.begin("Steve",session), "begin tracking");
        check(!tracker.begin("steve",session), "duplicate begin denied");
        tracker.observedQuit("Steve",UUID.randomUUID().toString());
        var pool = Executors.newSingleThreadExecutor();
        try {
            var proof = pool.submit(() -> tracker.await("steve",session.toString(),500));
            Thread.sleep(40);
            tracker.observedQuit("STEVE",session.toString());
            var result=proof.get(2,TimeUnit.SECONDS);
            check(result.status().equals("succeeded") && result.result().get("uuid").equals(session.toString()) && result.result().get("verification").equals("player-quit-event"),"session-bound quit evidence");
            check(tracker.begin("Steve",session),"track after completion");
            check(tracker.await("Steve",session.toString(),25).status().equals("executed"),"no quit not verified");
            check(tracker.begin("Steve",session),"track before shutdown");
            tracker.close();
            check(tracker.await("Steve",session.toString(),25).status().equals("executed"),"close not verified");
            check(!tracker.begin("Steve",session),"closed tracker rejects");
        } finally { pool.shutdownNow(); }
        System.out.println("PlatformControlReadback0416Test: 19 assertions passed");
    }
}

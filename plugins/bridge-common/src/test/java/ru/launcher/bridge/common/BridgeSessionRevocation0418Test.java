package ru.launcher.bridge.common;

/** Исполняемая регрессионная проверка ограждения сеансов без зависимости Minecraft/JUnit. */
public final class BridgeSessionRevocation0418Test {
    private static int checks;
    private static final String OLD = "a".repeat(64);
    private static final String NEW = "b".repeat(64);

    private static void check(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        BridgePlayerSessionRegistry sessions = new BridgePlayerSessionRegistry();
        check(!sessions.matches("Player", OLD), "неизвестный игрок не должен соответствовать сеансу");
        check(!sessions.bind("Player", "weak"), "слабые идентификаторы сеанса должны отклоняться");
        check(sessions.bind("Player", OLD), "действительный билет привязан");
        check(sessions.matches("player", OLD), "username lookup is case-insensitive");
        check(!sessions.matches("Player", NEW), "старый вход не может разрешить удаление другого игрока");
        check(!sessions.matches("Player", ""), "пустая привязка сеанса не должна обходить ограничение доступа");
        check(!sessions.matches("Player", "not-a-token"), "некорректная привязка не должна обходить ограничение доступа");
        check(!sessions.matches("Other", OLD), "другой пользователь не может повторно использовать тот же билет");
        check(sessions.bind("PLAYER", NEW), "повторный вход заменяет привязанный сеанс");
        check(!sessions.matches("Player", OLD), "задержанный отзыв не должен отключать новый сеанс");
        check(sessions.matches("player", NEW), "текущее соединение остаётся доступным для действия");
        sessions.clear("Player");
        check(!sessions.matches("player", NEW), "отключение удаляет активный сеанс");
        System.out.println("BridgeSessionRevocation0418: " + checks + " passed");
    }
}

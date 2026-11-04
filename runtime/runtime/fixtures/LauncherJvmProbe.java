/**Проверка байткода для приёмки Managed Runtime с
 * совместимостью Java 8. Воспроизводимая компиляция:
 * javac --release 8 LauncherJvmProbe.java. Выполняется
 * на устанавливаемом Runtime без javac и системного JDK.
 */ */
public final class LauncherJvmProbe {
    private LauncherJvmProbe() { }

    public static void main(String[] args) {
        if (args.length != 1 || args[0].length() == 0) {
            System.exit(64);
        }
        System.out.print("LAUNCHER_JVM_PROBE|" + args[0] + "|"
            + System.getProperty("java.specification.version") + "|"
            + System.getProperty("java.home"));
    }
}

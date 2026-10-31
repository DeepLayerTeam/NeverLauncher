/**
 * Java 8-compatible bytecode probe for managed runtime acceptance.
 * Compile reproducibly with: javac --release 8 LauncherJvmProbe.java
 * Runs on the runtime being installed, without javac or the system JDK.
 */
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

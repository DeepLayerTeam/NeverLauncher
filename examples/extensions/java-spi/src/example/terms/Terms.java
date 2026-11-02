package example.terms;

/** This class is deliberately compiled into a distinct pinned nested library JAR. */
public final class Terms {
    private Terms() {}
    public static String friendly(String name) { return "Hello, " + name + " (locked-spi-lib-0483)"; }
    public static String formal(String name) { return "Good day, " + name + " (locked-spi-lib-0483)"; }
}

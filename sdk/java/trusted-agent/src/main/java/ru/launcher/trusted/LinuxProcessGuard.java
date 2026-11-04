package ru.launcher.trusted;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** User-mode checks inside the real Linux game JVM. The parent Rust Guard
 * independently monitors /proc/<pid>, so this class is not the trust root. */
final class LinuxProcessGuard0508 {
    private LinuxProcessGuard0508() { }

    static void verify() throws IOException {
        if (!System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("linux"))
            throw new SecurityException("Linux process policy requested on another platform");
        String tracer = null, nnp = null;
        Path status = Paths.get("/proc/self/status");
        try (BufferedReader reader = Files.newBufferedReader(status, StandardCharsets.UTF_8)) {
            for (String line; (line = reader.readLine()) != null;) {
                if (line.startsWith("TracerPid:")) tracer = line.substring(10).trim();
                else if (line.startsWith("NoNewPrivs:")) nnp = line.substring(11).trim();
            }
        }
        if (!"0".equals(tracer)) throw new SecurityException("Guard Linux JVM tracer detected or unreadable");
        if (!"1".equals(nnp)) throw new SecurityException("Guard Linux JVM NoNewPrivs not enforced");
        String stat = new String(Files.readAllBytes(Paths.get("/proc/self/stat")), StandardCharsets.UTF_8);
        int end = stat.lastIndexOf(") ");
        if (end < 0) throw new SecurityException("Guard Linux JVM stat unavailable");
        String[] fields = stat.substring(end + 2).trim().split("\\s+");
        if (fields.length < 3) throw new SecurityException("Guard Linux JVM stat incomplete");
        // fields after comm: state, ppid, pgrp. Runtime sets pgrp == pid.
        String pid = stat.substring(0, stat.indexOf(' '));
        if (!pid.equals(fields[2])) throw new SecurityException("Guard Linux JVM process group changed");
        if ("1".equals(fields[1])) throw new SecurityException("Guard Linux JVM launcher exited");
        Path limits = Paths.get("/proc/self/limits");
        boolean coreDisabled = false;
        try (BufferedReader reader = Files.newBufferedReader(limits, StandardCharsets.UTF_8)) {
            for (String line; (line = reader.readLine()) != null;) {
                if (line.startsWith("Max core file size")) {
                    coreDisabled = line.substring("Max core file size".length()).trim().startsWith("0 ");
                    break;
                }
            }
        }
        if (!coreDisabled) throw new SecurityException("Guard Linux JVM core dumps not disabled");
    }
}

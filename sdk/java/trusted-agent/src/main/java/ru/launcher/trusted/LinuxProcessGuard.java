package ru.launcher.trusted;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Пользовательские проверки внутри настоящей Linux JVM игры. Родительский Rust Guard
 * независимо отслеживает /proc/<pid>, поэтому этот класс не является корнем доверия. */
final class LinuxProcessGuard0508 {
    private LinuxProcessGuard0508() { }

    static void verify() throws IOException {
        if (!System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("linux"))
            throw new SecurityException("Политика процессов Linux запрошена на другой платформе");
        String tracer = null, nnp = null;
        Path status = Paths.get("/proc/self/status");
        try (BufferedReader reader = Files.newBufferedReader(status, StandardCharsets.UTF_8)) {
            for (String line; (line = reader.readLine()) != null;) {
                if (line.startsWith("TracerPid:")) tracer = line.substring(10).trim();
                else if (line.startsWith("NoNewPrivs:")) nnp = line.substring(11).trim();
            }
        }
        if (!"0".equals(tracer)) throw new SecurityException("Guard Linux JVM: обнаружен трассировщик или сведения о нём недоступны");
        if (!"1".equals(nnp)) throw new SecurityException("Guard Linux JVM: ограничение NoNewPrivs не применяется");
        String stat = new String(Files.readAllBytes(Paths.get("/proc/self/stat")), StandardCharsets.UTF_8);
        int end = stat.lastIndexOf(") ");
        if (end < 0) throw new SecurityException("Guard Linux JVM: данные stat недоступны");
        String[] fields = stat.substring(end + 2).trim().split("\\s+");
        if (fields.length < 3) throw new SecurityException("Guard Linux JVM: данные stat неполны");
        // Поля после comm: state, ppid, pgrp. Runtime задаёт pgrp == pid.
        String pid = stat.substring(0, stat.indexOf(' '));
        if (!pid.equals(fields[2])) throw new SecurityException("Guard Linux JVM: группа процессов изменилась");
        if ("1".equals(fields[1])) throw new SecurityException("Guard Linux JVM: лаунчер завершился");
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
        if (!coreDisabled) throw new SecurityException("Guard Linux JVM: дампы памяти процесса не отключены");
    }
}

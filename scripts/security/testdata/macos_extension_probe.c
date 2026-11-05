#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

// Реальный дочерний процесс подписанного помощника App Sandbox, а не имитация проверки разрешений.
int main(int argc, char **argv) {
    if (argc < 2) return 42;
    if (!strcmp(argv[1], "sandbox")) {
        int fd = open("/Users/Shared/neverlauncher-sandbox-04311-denied", O_WRONLY | O_CREAT, 0600);
        if (fd >= 0) { close(fd); unlink("/Users/Shared/neverlauncher-sandbox-04311-denied"); return 43; }
        usleep(500000); // Parent must have time to verify actual PID and sandbox.
        return 0;
    }
    if (!strcmp(argv[1], "fork") || !strcmp(argv[1], "detach")) {
        pid_t pid = fork();
        if (pid == 0) {
            if (!strcmp(argv[1], "detach")) (void)setsid();
            sleep(3);
            _exit(0);
        }
        if (pid < 0) return 44; // Kernel refusal is a valid negative outcome.
        sleep(3); // Supervisor must kill the process and refuse success.
        return 45;
    }
    if (!strcmp(argv[1], "stay")) { sleep(10); return 0; }
    return 46;
}

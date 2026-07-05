/**
 * Universal Network Harness for AFL++ Firmware Fuzzing
 *
 * Uses LD_PRELOAD hook + pipe to feed AFL input into firmware daemons
 * running under QEMU user-mode. Works with ANY firmware/arch/daemon.
 *
 * Architecture:
 *   AFL stdin ──→ [Harness parent] ──pipe──→ [QEMU child + hook.so]
 *                                              │
 *                                              ├─ accept() → returns fake fd
 *                                              ├─ recv(fake_fd) → reads from pipe
 *                                              └─ process input → 💥 or exit
 *
 * Compile:
 *   gcc -O2 -o net_harness net_harness.c
 *   afl-clang-fast -O2 -o net_harness_inst net_harness.c
 *
 * Pre-compiled hooks:
 *   hook_arm.so    — for ARM 32-bit firmware (arm-linux-gnueabihf-gcc)
 *   hook_mipsel.so — for MIPS LE 32-bit firmware (mipsel-linux-gnu-gcc)
 *
 * Usage:
 *   ./net_harness <qemu> <hook.so> <rootfs> <binary> [qemu_args...]
 *
 * Examples:
 *   ./net_harness qemu-arm hook_arm.so /ac9/squashfs-root /bin/httpd
 *   ./net_harness qemu-mipsel hook_mipsel.so /dvrf/squashfs-root /pwnable/socket_bof
 *
 * With AFL:
 *   AFL_CRASH_EXITCODE=86 afl-fuzz -i seeds -o out -m none -- ./net_harness ...
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/select.h>

#define AFL_CRASH_EXITCODE   86
#define MAX_INPUT_SIZE       65536
#define CRASH_WAIT_SEC       3       // Wait up to 3s after injection for crash
#define GUEST_BOOT_SEC       5       // Max wait for daemon to start

/* ---- Harness main ---- */
int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
            "Universal Network Harness for AFL++ Firmware Fuzzing\n\n"
            "Usage: %s <qemu> <hook.so> <rootfs> <binary> [qemu_args...]\n\n"
            "  qemu:      qemu-arm, qemu-mipsel-static, etc.\n"
            "  hook.so:   hook_arm.so or hook_mipsel.so\n"
            "  rootfs:    Extracted squashfs root path (use \"\" for none)\n"
            "  binary:    Path to daemon inside rootfs\n"
            "  qemu_args: Extra QEMU args (e.g. daemon CLI arguments)\n\n"
            "Examples:\n"
            "  %s qemu-arm hook_arm.so /ac9/squashfs-root /bin/httpd\n"
            "  %s qemu-mipsel hook_mipsel.so /dvrf/squashfs-root /pwnable/socket_bof\n\n"
            "AFL:\n"
            "  AFL_CRASH_EXITCODE=86 afl-fuzz -i seeds -o out -m none -- %s ...\n",
            argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *qemu    = argv[1];
    const char *hook_so = argv[2];
    const char *rootfs  = argv[3];
    const char *binary  = argv[4];

    /* ---- Step 1: Create pipe for AFL input injection ---- */
    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        perror("pipe");
        return 1;
    }
    int pipe_read  = pipe_fd[0];   // Child reads from here (via hook)
    int pipe_write = pipe_fd[1];   // Parent writes AFL input here

    /* ---- Step 2: Read AFL input (non-blocking: read what's available) ---- */
    unsigned char input[MAX_INPUT_SIZE];
    ssize_t input_len = 0;

    // Check if stdin has data (AFL feeds via pipe, so use select)
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };  // 100ms

    if (select(1, &rfds, NULL, NULL, &tv) > 0) {
        input_len = read(0, input, sizeof(input) - 1);
    }
    if (input_len <= 0) {
        input_len = 4;
        memcpy(input, "AAAA", 4);  // Default stimulus
    }
    input[input_len] = '\0';

    fprintf(stderr, "[harness] QEMU=%s hook=%s binary=%s input=%zdB\n",
            qemu, hook_so, binary, input_len);

    /* ---- Step 3: Fork and start QEMU ---- */
    pid_t child = fork();
    if (child == 0) {
        // --- Child: QEMU + daemon + hook ---

        // Close write end (only parent writes)
        close(pipe_write);

        // Set pipe fd for the hook
        char pipe_fd_str[32];
        snprintf(pipe_fd_str, sizeof(pipe_fd_str), "%d", pipe_read);

        // Build QEMU arguments
        int qemu_argc = 0;
        char *qemu_argv[64];

        qemu_argv[qemu_argc++] = (char *)qemu;

        // Rootfs
        if (rootfs[0] != '\0') {
            qemu_argv[qemu_argc++] = "-L";
            qemu_argv[qemu_argc++] = (char *)rootfs;
        }

        // Environment variables for the hook
        char ld_preload[512];
        snprintf(ld_preload, sizeof(ld_preload), "LD_PRELOAD=%s", hook_so);
        qemu_argv[qemu_argc++] = "-E";
        qemu_argv[qemu_argc++] = ld_preload;

        qemu_argv[qemu_argc++] = "-E";
        char pipe_env[64];
        snprintf(pipe_env, sizeof(pipe_env), "AFL_HOOK_PIPE_FD=%s", pipe_fd_str);
        qemu_argv[qemu_argc++] = pipe_env;

        // Strace for crash diagnostics (optional, enable with caution - slows execution)
        // qemu_argv[qemu_argc++] = "-strace";

        // Target binary
        qemu_argv[qemu_argc++] = (char *)binary;

        // Extra QEMU args (remaining arguments)
        for (int i = 5; i < argc && qemu_argc < 60; i++) {
            qemu_argv[qemu_argc++] = argv[i];
        }

        qemu_argv[qemu_argc] = NULL;

        // Redirect stderr (QEMU -strace output goes here)
        // Keep stderr for crash diagnostics

        execvp(qemu_argv[0], qemu_argv);
        fprintf(stderr, "[harness] FATAL: exec(%s) failed: %s\n",
                qemu_argv[0], strerror(errno));
        _exit(127);
    }

    // --- Parent: feed AFL input and monitor crash ---

    // Close read end (only child reads)
    close(pipe_read);

    /* ---- Step 4: Wait for daemon to boot ---- */
    fprintf(stderr, "[harness] waiting for daemon to boot (max %ds)...\n", GUEST_BOOT_SEC);
    sleep(2);  // Give QEMU + daemon time to start

    /* ---- Step 5: Write AFL input to pipe ---- */
    fprintf(stderr, "[harness] injecting %zd bytes via pipe\n", input_len);
    ssize_t written = write(pipe_write, input, input_len);
    if (written < 0) {
        fprintf(stderr, "[harness] pipe write failed: %s\n", strerror(errno));
    }
    close(pipe_write);  // Signal EOF to daemon

    /* ---- Step 6: Wait for crash ---- */
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += CRASH_WAIT_SEC;

    int status;
    pid_t result = waitpid(child, &status, WNOHANG);
    int waited_ms = 0;

    while (result == 0) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec >= deadline.tv_sec) break;

        usleep(50000);  // 50ms
        waited_ms += 50;
        result = waitpid(child, &status, WNOHANG);
    }

    if (result == 0) {
        // Still running — normal (daemon processed input and kept running)
        fprintf(stderr, "[harness] daemon alive after %dms — OK (no crash)\n",
                waited_ms);
        kill(child, SIGTERM);
        waitpid(child, &status, 0);
        return 0;  // AFL: no crash
    }

    /* ---- Step 7: Crash detection ---- */
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        fprintf(stderr, "[harness] CRASH (signal %d: %s) after %dms\n",
                sig, strsignal(sig), waited_ms);
        return AFL_CRASH_EXITCODE;  // Signal AFL: crash found!
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 0 && exit_code != 127) {
            fprintf(stderr, "[harness] daemon exited with code %d (potential crash)\n",
                    exit_code);
            return AFL_CRASH_EXITCODE;
        }
        fprintf(stderr, "[harness] daemon exited normally (code %d)\n", exit_code);
    }

    return 0;
}

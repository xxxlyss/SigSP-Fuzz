/**
 * Universal Network Harness for AFL++ Firmware Fuzzing
 *
 * Bridges AFL to firmware network daemons running under QEMU user-mode.
 * Works with ANY firmware binary — just change the command-line arguments.
 *
 * Architecture:
 *   AFL stdin → [Harness parent] → TCP socket → [QEMU child] → daemon
 *                                                         ↑
 *                                                    LD_PRELOAD=hook.so
 *                                                    (fakes bind/recv if needed)
 *
 * Compile:
 *   gcc -O2 -o net_harness network_harness.c
 *   afl-clang-fast -O2 -o net_harness_inst network_harness.c
 *
 * Usage (any firmware, any daemon):
 *   ./net_harness <qemu> <rootfs> <binary> <port> [protocol]
 *
 * Examples:
 *   # AC9 httpd
 *   ./net_harness qemu-arm /ac9/squashfs-root /bin/httpd 80
 *
 *   # DVRF socket_bof
 *   ./net_harness qemu-mipsel /dvrf/squashfs-root /pwnable/socket_bof 8888
 *
 *   # D-Link dnsmasq
 *   ./net_harness qemu-arm /dlink/squashfs-root /usr/sbin/dnsmasq 53 udp
 *
 *   # Any firmware telnetd
 *   ./net_harness qemu-mipsel /fw/squashfs-root /usr/sbin/telnetd 23 tcp
 *
 *   # With AFL:
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
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

/* ---- AFL Configuration ---- */
#define AFL_CRASH_EXITCODE    86       // Signal to AFL: "this was a crash"
#define PORT_POLL_TIMEOUT_MS  15000    // Max wait for daemon to bind port
#define PORT_POLL_INTERVAL_US 100000   // 100ms between poll attempts
#define RECV_TIMEOUT_SEC      3        // How long to wait for daemon response
#define MAX_INPUT_SIZE        65536    // 64KB max AFL input
#define RESPONSE_BUF_SIZE     32768    // Capture daemon's response

/* ---- Preload Hook Library (embedded, written to temp file at startup) ---- */
static const char HOOK_SOURCE[] =
"/* LD_PRELOAD hook for embedded daemon compatibility */\n"
"#define _GNU_SOURCE\n"
"#include <stdio.h>\n"
"#include <stdlib.h>\n"
"#include <string.h>\n"
"#include <unistd.h>\n"
"#include <dlfcn.h>\n"
"#include <errno.h>\n"
"#include <sys/socket.h>\n"
"#include <sys/types.h>\n"
"#include <netinet/in.h>\n"
"#include <stdarg.h>\n"
"\n"
"/* Original libc functions */\n"
"static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;\n"
"static int (*real_setsockopt)(int, int, int, const void *, socklen_t) = NULL;\n"
"static int (*real_fcntl)(int, int, ...) = NULL;\n"
"static int (*real_ioctl)(int, unsigned long, ...) = NULL;\n"
"static int (*real_open)(const char *, int, ...) = NULL;\n"
"static FILE *(*real_fopen)(const char *, const char *) = NULL;\n"
"\n"
"__attribute__((constructor)) static void init(void) {\n"
"    real_bind      = dlsym(RTLD_NEXT, \"bind\");\n"
"    real_setsockopt = dlsym(RTLD_NEXT, \"setsockopt\");\n"
"    real_fcntl     = dlsym(RTLD_NEXT, \"fcntl\");\n"
"    real_ioctl     = dlsym(RTLD_NEXT, \"ioctl\");\n"
"    real_open      = dlsym(RTLD_NEXT, \"open\");\n"
"    real_fopen     = dlsym(RTLD_NEXT, \"fopen\");\n"
"}\n"
"\n"
"/* bind(): always succeed, even on privileged ports or reused addresses */\n"
"int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {\n"
"    if (!real_bind) init();\n"
"    int ret = real_bind(sockfd, addr, addrlen);\n"
"    if (ret < 0) {\n"
"        /* Common failures in QEMU user-mode:\n"
"         *   EADDRINUSE  → port already used (ignore, fake success)\n"
"         *   EACCES      → privileged port < 1024 (ignore)\n"
"         *   EADDRNOTAVAIL → interface doesn't exist (ignore)\n"
"         */\n"
"        if (errno == EADDRINUSE || errno == EACCES || errno == EADDRNOTAVAIL\n"
"            || errno == EINVAL || errno == ENOPROTOOPT) {\n"
"            fprintf(stderr, \"[hook] bind() failed (%s) → faking success\\n\",\n"
"                    strerror(errno));\n"
"            return 0;\n"
"        }\n"
"    }\n"
"    return ret;\n"
"}\n"
"\n"
"/* setsockopt(): silently ignore unsupported options */\n"
"int setsockopt(int s, int level, int optname,\n"
"               const void *optval, socklen_t optlen) {\n"
"    if (!real_setsockopt) init();\n"
"    int ret = real_setsockopt(s, level, optname, optval, optlen);\n"
"    if (ret < 0) {\n"
"        /* SO_REUSEPORT, TCP_FASTOPEN, etc may not be supported in QEMU */\n"
"        if (errno == ENOPROTOOPT || errno == EINVAL) {\n"
"            return 0;  // Silently succeed\n"
"        }\n"
"    }\n"
"    return ret;\n"
"}\n"
"\n"
"/* fcntl(): succeed on unsupported ops (e.g. setting O_NONBLOCK on sockets) */\n"
"int fcntl(int fd, int cmd, ...) {\n"
"    va_list ap;\n"
"    va_start(ap, cmd);\n"
"    long arg = va_arg(ap, long);\n"
"    va_end(ap);\n"
"    if (!real_fcntl) init();\n"
"    int ret = real_fcntl(fd, cmd, arg);\n"
"    if (ret < 0 && (errno == EINVAL || errno == ENOTTY)) {\n"
"        return 0;  // F_SETFL O_NONBLOCK on non-socket fd\n"
"    }\n"
"    return ret;\n"
"}\n"
"\n"
"/* open(): fake success for nonexistent device files */\n"
"int open(const char *path, int flags, ...) {\n"
"    va_list ap;\n"
"    va_start(ap, flags);\n"
"    mode_t mode = va_arg(ap, mode_t);\n"
"    va_end(ap);\n"
"    if (!real_open) init();\n"
"    int ret = real_open(path, flags, mode);\n"
"    if (ret < 0) {\n"
"        /* Fake /dev/null, /dev/urandom, /dev/random */\n"
"        if (strstr(path, \"/dev/null\"))    { return open(\"/dev/null\", flags, mode); }\n"
"        if (strstr(path, \"/dev/urandom\")) { return open(\"/dev/urandom\", flags, mode); }\n"
"        if (strstr(path, \"/dev/random\"))  { return open(\"/dev/urandom\", flags, mode); }\n"
"        /* Fake /dev entries that don't exist in QEMU user-mode */\n"
"        if (strncmp(path, \"/dev/\", 5) == 0) {\n"
"            return fileno(fopen(\"/dev/null\", \"r+\"));  // Return a valid fd\n"
"        }\n"
"    }\n"
"    return ret;\n"
"}\n"
"";

/* ---- Port Polling ---- */
static int tcp_connect(const char *host, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    // Non-blocking connect
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((unsigned short)port),
    };
    inet_pton(AF_INET, host, &addr.sin_addr);

    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    // Wait for connection
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    struct timeval tv = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    ret = select(sock + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) { close(sock); return -1; }

    // Check for error
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) { close(sock); return -1; }

    // Restore blocking
    fcntl(sock, F_SETFL, flags);
    return sock;
}

static int wait_for_port(const char *host, int port, int timeout_ms) {
    int deadline = (int)time(NULL) + (timeout_ms / 1000);
    while ((int)time(NULL) < deadline) {
        int sock = tcp_connect(host, port, 500);
        if (sock >= 0) {
            close(sock);
            return 0;
        }
        usleep(PORT_POLL_INTERVAL_US);
    }
    return -1;
}

/* ---- Hook Source Management ---- */
static char *write_hook_source(void) {
    char tmp_path[] = "/tmp/net_harness_hook_XXXXXX.c";
    int fd = mkstemps(tmp_path, 2);  // .c suffix
    if (fd < 0) return NULL;

    FILE *f = fdopen(fd, "w");
    if (!f) return NULL;
    fwrite(HOOK_SOURCE, 1, sizeof(HOOK_SOURCE) - 1, f);
    fclose(f);
    return strdup(tmp_path);
}

static char *compile_hook(const char *src_path) {
    char *so_path = strdup("/tmp/net_harness_hook_XXXXXX.so");
    int fd = mkstemps(so_path, 3);  // .so suffix
    if (fd < 0) { free(so_path); return NULL; }
    close(fd);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "gcc -shared -fPIC -O2 -o %s %s -ldl 2>/dev/null", so_path, src_path);
    int ret = system(cmd);
    if (ret != 0) {
        // Try cc as fallback
        snprintf(cmd, sizeof(cmd),
            "cc -shared -fPIC -O2 -o %s %s -ldl 2>/dev/null", so_path, src_path);
        ret = system(cmd);
    }
    if (ret != 0) { free(so_path); return NULL; }
    return so_path;
}

/* ---- Main Harness ---- */
int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
            "Universal Network Harness for AFL++ Firmware Fuzzing\n\n"
            "Usage: %s <qemu> <rootfs> <binary> <port> [protocol] [qemu_args...]\n\n"
            "  qemu:     qemu-arm, qemu-mipsel-static, etc.\n"
            "  rootfs:   Path to extracted squashfs root (or \"\" for none)\n"
            "  binary:   Path to daemon inside rootfs\n"
            "  port:     TCP port the daemon listens on\n"
            "  protocol: 'tcp' (default) or 'udp'\n"
            "  qemu_args: Extra args passed to QEMU (e.g., -strace)\n\n"
            "Examples:\n"
            "  %s qemu-arm /ac9/squashfs-root /bin/httpd 80\n"
            "  %s qemu-mipsel /dvrf/squashfs-root /pwnable/socket_bof 8888\n"
            "  %s qemu-arm /fw/rootfs /usr/sbin/dnsmasq 53 udp\n\n"
            "AFL usage:\n"
            "  AFL_CRASH_EXITCODE=86 afl-fuzz -i seeds -o out -m none -- %s ...\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    const char *qemu    = argv[1];
    const char *rootfs  = argv[2];
    const char *binary  = argv[3];
    int         port    = atoi(argv[4]);
    const char *proto   = (argc > 5) ? argv[5] : "tcp";
    int         use_udp = (strcmp(proto, "udp") == 0);

    fprintf(stderr, "[harness] QEMU=%s rootfs=%s binary=%s port=%d proto=%s\n",
            qemu, rootfs[0] ? rootfs : "(none)", binary, port, proto);

    /* Step 1: Compile LD_PRELOAD hook library */
    char *hook_src = write_hook_source();
    char *hook_so = hook_src ? compile_hook(hook_src) : NULL;
    if (hook_so) {
        fprintf(stderr, "[harness] LD_PRELOAD hook: %s\n", hook_so);
    } else {
        fprintf(stderr, "[harness] LD_PRELOAD hook not available (daemon may fail)\n");
    }

    /* Step 2: Build QEMU command arguments */
    int qemu_argc = 0;
    char *qemu_argv[64];

    qemu_argv[qemu_argc++] = (char *)qemu;

    // Rootfs
    if (rootfs[0] != '\0') {
        qemu_argv[qemu_argc++] = "-L";
        qemu_argv[qemu_argc++] = (char *)rootfs;
    }

    // Environment: LD_PRELOAD
    if (hook_so) {
        qemu_argv[qemu_argc++] = "-E";
        char env_buf[512];
        snprintf(env_buf, sizeof(env_buf), "LD_PRELOAD=%s", hook_so);
        qemu_argv[qemu_argc++] = strdup(env_buf);
    }

    // Strace for crash diagnostics
    qemu_argv[qemu_argc++] = "-strace";

    // Target binary
    qemu_argv[qemu_argc++] = (char *)binary;

    // Extra QEMU args (remaining arguments)
    for (int i = 6; i < argc && qemu_argc < 60; i++) {
        qemu_argv[qemu_argc++] = argv[i];
    }

    qemu_argv[qemu_argc] = NULL;

    /* Step 3: Fork and start QEMU + daemon */
    pid_t child = fork();
    if (child == 0) {
        // Child: run QEMU with the daemon binary
        execvp(qemu_argv[0], qemu_argv);
        // exec failed
        fprintf(stderr, "[harness] FATAL: exec(%s) failed: %s\n",
                qemu_argv[0], strerror(errno));
        _exit(127);
    }

    /* Step 4: Wait for daemon to bind its port */
    fprintf(stderr, "[harness] waiting for daemon on port %d (max %dms)...\n",
            port, PORT_POLL_TIMEOUT_MS);

    int port_ready = wait_for_port("127.0.0.1", port, PORT_POLL_TIMEOUT_MS);
    if (port_ready < 0) {
        fprintf(stderr, "[harness] daemon didn't bind port %d within %dms\n",
                port, PORT_POLL_TIMEOUT_MS);
        // Daemon might have exited — check if it crashed
        int status;
        if (waitpid(child, &status, WNOHANG) > 0) {
            if (WIFSIGNALED(status)) {
                fprintf(stderr, "[harness] daemon crashed on startup (signal %d)!\n",
                        WTERMSIG(status));
                raise(WTERMSIG(status));
            }
            fprintf(stderr, "[harness] daemon exited with code %d\n",
                    WEXITSTATUS(status));
        }
        // Send some data anyway — daemon might be slow, or port-poll missed
        fprintf(stderr, "[harness] proceeding without port confirmation...\n");
    } else {
        fprintf(stderr, "[harness] daemon ready on port %d\n", port);
    }

    /* Step 5: Read AFL input from stdin */
    static unsigned char input[MAX_INPUT_SIZE];
    ssize_t input_len = read(0, input, sizeof(input) - 1);
    if (input_len <= 0) {
        input_len = 0;
        input[0] = '\0';
    }
    input[input_len] = '\0';

    fprintf(stderr, "[harness] injecting %zd bytes to port %d (%s)\n",
            input_len, port, proto);

    /* Step 6: Inject into daemon */
    int sock = -1;
    if (use_udp) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            struct sockaddr_in addr = {
                .sin_family = AF_INET,
                .sin_port = htons((unsigned short)port),
            };
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            sendto(sock, input, input_len, 0,
                   (struct sockaddr *)&addr, sizeof(addr));
            close(sock);
        }
    } else {
        sock = tcp_connect("127.0.0.1", port, 2000);
        if (sock >= 0) {
            send(sock, input, input_len, 0);

            // Read response (with timeout)
            struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC, .tv_usec = 0 };
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            unsigned char response[RESPONSE_BUF_SIZE];
            ssize_t n = recv(sock, response, sizeof(response) - 1, 0);
            if (n > 0) {
                response[n] = '\0';
                fprintf(stderr, "[harness] response: %zd bytes\n", n);
            }
            close(sock);
        }
    }

    /* Step 7: Wait for daemon to crash or finish processing */
    int status;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 3;  // Wait up to 3 seconds for crash

    pid_t result = waitpid(child, &status, WNOHANG);
    int waited = 0;

    while (result == 0) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        if (now.tv_sec >= deadline.tv_sec) break;
        usleep(50000);  // 50ms
        waited++;
        result = waitpid(child, &status, WNOHANG);
    }

    // If still running after timeout, kill it
    if (result == 0) {
        fprintf(stderr, "[harness] daemon still alive after injection — OK\n");
        kill(child, SIGTERM);
        waitpid(child, &status, 0);
        return 0;
    }

    // Daemon exited — check for crash
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        fprintf(stderr, "[harness] 🔴 DAEMON CRASHED (signal %d: %s)!\n",
                sig, strsignal(sig));

        // Show crash details from QEMU stderr
        fprintf(stderr, "[harness] crash detected — propagating to AFL\n");

        // Propagate crash to AFL via exit code
        return AFL_CRASH_EXITCODE;
    }

    int exit_code = WEXITSTATUS(status);
    fprintf(stderr, "[harness] daemon exited normally (code %d)\n", exit_code);
    return 0;
}

/*
 * hook.c — Minimal LD_PRELOAD for firmware daemon fuzzing
 *
 * Only ONE intercepted function: accept() returns dup(pipe_fd).
 * The daemon then reads AFL input directly from the pipe.
 * No recv/read/bind/socket interception needed.
 *
 * Pipe fd passed via AFL_HOOK_PIPE_FD env var.
 * Works with ANY libc (glibc, uClibc, musl).
 *
 * Compile:
 *   arm-linux-gnueabihf-gcc -shared -fPIC -O2 -o hook_arm.so hook.c
 *   mipsel-linux-gnu-gcc   -shared -fPIC -O2 -o hook_mipsel.so hook.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>

static int pipe_fd = -1;
static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int) = NULL;
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;

__attribute__((constructor)) static void init(void) {
    const char *fd_str = getenv("AFL_HOOK_PIPE_FD");
    if (fd_str) {
        pipe_fd = atoi(fd_str);
        fprintf(stderr, "[hook] pipe_fd=%d ready\n", pipe_fd);
    }
    real_accept  = dlsym(RTLD_NEXT, "accept");
    real_accept4 = dlsym(RTLD_NEXT, "accept4");
    real_bind    = dlsym(RTLD_NEXT, "bind");
}

/* The ONLY critical interception: accept() returns the pipe fd.
 * The daemon thinks it's a client socket, but it's really our AFL pipe. */
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    if (pipe_fd < 0) {
        if (!real_accept) init();
        return real_accept ? real_accept(sockfd, addr, addrlen) : -1;
    }

    // Only intercept the FIRST accept call (main daemon loop)
    // Return a dup of the pipe so each "client" gets its own fd offset
    static int intercept_count = 0;
    if (intercept_count < 100) {
        intercept_count++;
        int client_fd = dup(pipe_fd);
        if (client_fd >= 0) {
            fprintf(stderr, "[hook] accept() → pipe dup fd=%d (#%d)\n",
                    client_fd, intercept_count);
            return client_fd;
        }
    }

    // Fallback: real accept
    if (!real_accept) init();
    return real_accept ? real_accept(sockfd, addr, addrlen) : -1;
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
    if (pipe_fd < 0) {
        if (!real_accept4) init();
        return real_accept4 ? real_accept4(sockfd, addr, addrlen, flags) : -1;
    }
    return accept(sockfd, addr, addrlen);
}

/* bind(): force success on common QEMU failures */
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_bind) init();
    if (real_bind) {
        int ret = real_bind(sockfd, addr, addrlen);
        if (ret < 0 && (errno == EADDRINUSE || errno == EACCES || errno == EADDRNOTAVAIL)) {
            fprintf(stderr, "[hook] bind() failed (%s) → faking success\n", strerror(errno));
            return 0;
        }
        return ret;
    }
    return 0;
}

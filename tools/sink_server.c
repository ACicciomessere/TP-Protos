// Simple HTTP "sink" server used for stress tests.
//
// Purpose: accept HTTP POST requests and read/discard the request body
// (Content-Length bytes). Responds with a minimal 200 OK.
//
// This replaces tools/sink_server.py so the test harness can be fully in C.

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SINK_BIND_ADDR
#define SINK_BIND_ADDR "127.0.0.1"
#endif

#ifndef SINK_PORT
#define SINK_PORT 8888
#endif

#define MAX_HEADER_BYTES (64 * 1024)

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int signo) {
    (void)signo;
    g_stop = 1;
}

static ssize_t read_some(int fd, void *buf, size_t len) {
    for (;;) {
        ssize_t n = recv(fd, buf, len, 0);
        if (n < 0 && errno == EINTR) continue;
        return n;
    }
}

static ssize_t write_some(int fd, const void *buf, size_t len) {
    for (;;) {
        ssize_t n = send(fd, buf, len, 0);
        if (n < 0 && errno == EINTR) continue;
        return n;
    }
}

static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write_some(fd, p + off, len - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static long parse_content_length(const char *headers) {
    // Very small/robust parser for Content-Length.
    // Returns -1 if missing/invalid.
    const char *p = headers;
    while (*p) {
        // Find end of line
        const char *eol = strstr(p, "\r\n");
        if (!eol) break;
        size_t line_len = (size_t)(eol - p);
        if (line_len >= 15) {
            // case-insensitive match "Content-Length:"
            const char *k = "content-length:";
            bool match = true;
            for (size_t i = 0; i < 15; i++) {
                char c = p[i];
                if ('A' <= c && c <= 'Z') c = (char)(c - 'A' + 'a');
                if (c != k[i]) { match = false; break; }
            }
            if (match) {
                const char *v = p + 15;
                while (*v == ' ' || *v == '\t') v++;
                char *endp = NULL;
                long val = strtol(v, &endp, 10);
                if (endp == v || val < 0) return -1;
                return val;
            }
        }
        p = eol + 2;
        if (p[0] == '\r' && p[1] == '\n') break;
    }
    return -1;
}

static void respond_simple(int fd, int code, const char *msg) {
    char body[64];
    snprintf(body, sizeof(body), "%s", msg ? msg : "");
    char hdr[256];
    int body_len = (int)strlen(body);
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\n"
                     "Content-Length: %d\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     code, (code == 200 ? "OK" : "ERROR"), body_len);
    if (n > 0) {
        (void)write_all(fd, hdr, (size_t)n);
        if (body_len > 0) (void)write_all(fd, body, (size_t)body_len);
    }
}

static void *client_thread(void *arg) {
    int fd = *(int *)arg;
    free(arg);

    // Read headers up to CRLFCRLF
    char *hdr = calloc(1, MAX_HEADER_BYTES + 1);
    if (!hdr) {
        close(fd);
        return NULL;
    }

    size_t used = 0;
    bool got_end = false;
    while (used < MAX_HEADER_BYTES) {
        ssize_t n = read_some(fd, hdr + used, MAX_HEADER_BYTES - used);
        if (n <= 0) {
            free(hdr);
            close(fd);
            return NULL;
        }
        used += (size_t)n;
        hdr[used] = '\0';
        char *end = strstr(hdr, "\r\n\r\n");
        if (end) {
            got_end = true;
            // Any extra bytes after headers are part of body.
            size_t header_len = (size_t)(end - hdr) + 4;
            long cl = parse_content_length(hdr);

            // Basic method check
            if (strncmp(hdr, "POST ", 5) != 0) {
                respond_simple(fd, 405, "");
                free(hdr);
                close(fd);
                return NULL;
            }

            if (cl < 0) {
                respond_simple(fd, 411, "");
                free(hdr);
                close(fd);
                return NULL;
            }

            size_t already = used - header_len;
            size_t remaining = (already >= (size_t)cl) ? 0 : ((size_t)cl - already);

            // Drain the remaining body bytes.
            uint8_t buf[64 * 1024];
            while (remaining > 0) {
                size_t want = remaining < sizeof(buf) ? remaining : sizeof(buf);
                ssize_t bn = read_some(fd, buf, want);
                if (bn <= 0) break;
                remaining -= (size_t)bn;
            }

            respond_simple(fd, 200, "OK");
            free(hdr);
            close(fd);
            return NULL;
        }
    }

    if (!got_end) {
        respond_simple(fd, 431, ""); // Request Header Fields Too Large
    }
    free(hdr);
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SINK_PORT);
    if (inet_pton(AF_INET, SINK_BIND_ADDR, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid bind addr: %s\n", SINK_BIND_ADDR);
        close(s);
        return 1;
    }

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(s);
        return 1;
    }

    if (listen(s, 1024) != 0) {
        perror("listen");
        close(s);
        return 1;
    }

    fprintf(stdout, "Sink server listening on %s:%d\n", SINK_BIND_ADDR, SINK_PORT);
    fflush(stdout);

    while (!g_stop) {
        struct sockaddr_in cli;
        socklen_t cl = sizeof(cli);
        int c = accept(s, (struct sockaddr *)&cli, &cl);
        if (c < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        int *fdp = malloc(sizeof(int));
        if (!fdp) {
            close(c);
            continue;
        }
        *fdp = c;

        pthread_t th;
        if (pthread_create(&th, NULL, client_thread, fdp) != 0) {
            free(fdp);
            close(c);
            continue;
        }
        pthread_detach(th);
    }

    close(s);
    return 0;
}

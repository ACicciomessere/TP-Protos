// Uso:
//    ./bin/stress_socks5 --host 127.0.0.1 --port 1080 --total 20000 --concurrency 1000
//
// Exit status is 0 if every handshake succeeded, 1 otherwise.

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef DEFAULT_TOTAL
#define DEFAULT_TOTAL 10000
#endif
#ifndef DEFAULT_CONCURRENCY
#define DEFAULT_CONCURRENCY 500
#endif

static const uint8_t GREETING_REQ[3] = {0x05, 0x01, 0x00};

struct worker_ctx {
    const struct addrinfo *ai_list;
    int iterations;
    atomic_int *successes;
};

static int perform_handshake(const struct addrinfo *ai) {
    int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) return 0;

    if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
        close(sock);
        return 0;
    }
    // send greeting
    ssize_t n = send(sock, GREETING_REQ, sizeof(GREETING_REQ), 0);
    if (n != (ssize_t)sizeof(GREETING_REQ)) {
        close(sock);
        return 0;
    }
    uint8_t resp[2];
    n = recv(sock, resp, sizeof(resp), MSG_WAITALL);
    close(sock);
    if (n == 2 && resp[0] == 0x05) {
        return 1;
    }
    return 0;
}

static void *worker_thread(void *arg) {
    struct worker_ctx *ctx = (struct worker_ctx *)arg;
    const struct addrinfo *ai = ctx->ai_list;

    for (int i = 0; i < ctx->iterations; i++) {
        // iterate over addrinfo list until connect succeeds or list ends
        const struct addrinfo *cur;
        int ok = 0;
        for (cur = ai; cur != NULL; cur = cur->ai_next) {
            if (perform_handshake(cur)) {
                ok = 1;
                break;
            }
        }
        if (ok) {
            atomic_fetch_add(ctx->successes, 1);
        }
    }
    return NULL;
}

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char *argv[]) {
    const char *host = "127.0.0.1";
    const char *port = "1080";
    int total = DEFAULT_TOTAL;
    int concurrency = DEFAULT_CONCURRENCY;

    // parse simple args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = argv[++i];
        } else if (strcmp(argv[i], "--total") == 0 && i + 1 < argc) {
            total = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--concurrency") == 0 && i + 1 < argc) {
            concurrency = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--host H] [--port P] [--total N] [--concurrency M]\n", argv[0]);
            return 0;
        }
    }

    if (total <= 0 || concurrency <= 0) {
        fprintf(stderr, "total and concurrency must be > 0\n");
        return 1;
    }

    // resolve host once
    struct addrinfo hints = {0}, *ai_list;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(host, port, &hints, &ai_list);
    if (gai != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        return 1;
    }

    atomic_int successes = 0;

    pthread_t *threads = calloc(concurrency, sizeof(pthread_t));
    struct worker_ctx *ctxs = calloc(concurrency, sizeof(struct worker_ctx));

    int per_thread = total / concurrency;
    int remainder = total % concurrency;

    double start = now_seconds();

    for (int i = 0; i < concurrency; i++) {
        ctxs[i].ai_list = ai_list;
        ctxs[i].iterations = per_thread + (i < remainder ? 1 : 0);
        ctxs[i].successes = &successes;
        pthread_create(&threads[i], NULL, worker_thread, &ctxs[i]);
    }

    for (int i = 0; i < concurrency; i++) {
        pthread_join(threads[i], NULL);
    }

    double end = now_seconds();

    int succ = atomic_load(&successes);
    printf("Total attempted: %d\n", total);
    printf("Successful handshakes: %d\n", succ);
    printf("Duration: %.2f s\n", end - start);
    if (end > start) {
        printf("Throughput: %.2f connections/sec\n", succ / (end - start));
    }
    printf("Failures: %d\n", total - succ);

    free(threads);
    free(ctxs);
    freeaddrinfo(ai_list);

    return (succ == total) ? 0 : 1;
} 
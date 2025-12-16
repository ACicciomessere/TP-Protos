// Uso:
//    ./bin/stress_socks5 --host 127.0.0.1 --port 1080 --user pepe --pass 1234 \
//                        --target-host example.org --target-port 80 --total 20000
//
// La herramienta ahora recorre todo el pipeline: greeting, autenticación,
// CONNECT al origen solicitado y transferencia de datos (un GET HTTP).
// Cuenta como éxito sólo si se recibe al menos `--min-response` bytes.

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

struct stress_options {
    const struct addrinfo *proxy_ai;
    const char *username;
    const char *password;
    const char *target_host;
    const char *request_path;
    int target_port;
    size_t min_response_bytes;
};

struct worker_ctx {
    int iterations;
    atomic_int *successes;
    const struct stress_options *opts;
};

static int send_all(int sock, const void *buffer, size_t len) {
    const uint8_t *ptr = buffer;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t sent = send(sock, ptr, remaining, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        ptr += sent;
        remaining -= sent;
    }
    return 0;
}

static int recv_all(int sock, void *buffer, size_t len) {
    uint8_t *ptr = buffer;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t recvd = recv(sock, ptr, remaining, 0);
        if (recvd <= 0) {
            if (recvd < 0 && errno == EINTR) continue;
            return -1;
        }
        ptr += recvd;
        remaining -= recvd;
    }
    return 0;
}

static int socks5_send_greeting(int sock) {
    uint8_t req[3] = {0x05, 0x01, 0x02};
    uint8_t resp[2];
    if (send_all(sock, req, sizeof(req)) < 0) return -1;
    if (recv_all(sock, resp, sizeof(resp)) < 0) return -1;
    if (resp[0] != 0x05 || resp[1] != 0x02) return -1;
    return 0;
}

static int socks5_send_auth(int sock, const char *user, const char *pass) {
    size_t ulen = strlen(user);
    size_t plen = strlen(pass);
    if (ulen == 0 || ulen > 255 || plen > 255) {
        fprintf(stderr, "username/password length must be 1..255 bytes\n");
        return -1;
    }

    uint8_t req[514];
    size_t idx = 0;
    req[idx++] = 0x01; // subnegotiation version
    req[idx++] = (uint8_t)ulen;
    memcpy(&req[idx], user, ulen);
    idx += ulen;
    req[idx++] = (uint8_t)plen;
    memcpy(&req[idx], pass, plen);
    idx += plen;

    uint8_t resp[2];
    if (send_all(sock, req, idx) < 0) return -1;
    if (recv_all(sock, resp, sizeof(resp)) < 0) return -1;
    if (resp[1] != 0x00) return -1;
    return 0;
}

static int encode_target_address(const char *host, uint8_t *buffer, size_t *len_out) {
    struct in_addr ipv4;
    struct in6_addr ipv6;
    if (inet_pton(AF_INET, host, &ipv4) == 1) {
        buffer[0] = 0x01;
        memcpy(&buffer[1], &ipv4, sizeof(ipv4));
        *len_out = 1 + sizeof(ipv4);
        return 0;
    }
    if (inet_pton(AF_INET6, host, &ipv6) == 1) {
        buffer[0] = 0x04;
        memcpy(&buffer[1], &ipv6, sizeof(ipv6));
        *len_out = 1 + sizeof(ipv6);
        return 0;
    }

    size_t name_len = strlen(host);
    if (name_len == 0 || name_len > 255) {
        fprintf(stderr, "domain must be 1..255 bytes\n");
        return -1;
    }
    buffer[0] = 0x03;
    buffer[1] = (uint8_t)name_len;
    memcpy(&buffer[2], host, name_len);
    *len_out = 2 + name_len;
    return 0;
}

static int socks5_send_connect(int sock, const char *host, int port) {
    uint8_t addr_buf[1 + 1 + 255];
    size_t addr_len = 0;
    if (encode_target_address(host, addr_buf, &addr_len) < 0) return -1;

    uint8_t req[4 + sizeof(addr_buf) + 2];
    size_t idx = 0;
    req[idx++] = 0x05;
    req[idx++] = 0x01; // CONNECT
    req[idx++] = 0x00; // reserved
    memcpy(&req[idx], addr_buf, addr_len);
    idx += addr_len;
    uint16_t port_n = htons((uint16_t)port);
    memcpy(&req[idx], &port_n, sizeof(port_n));
    idx += sizeof(port_n);

    if (send_all(sock, req, idx) < 0) return -1;

    uint8_t header[4];
    if (recv_all(sock, header, sizeof(header)) < 0) return -1;
    if (header[1] != 0x00) return -1;

    size_t to_read = 0;
    if (header[3] == 0x01) {
        to_read = 4 + 2;
    } else if (header[3] == 0x03) {
        uint8_t len = 0;
        if (recv_all(sock, &len, 1) < 0) return -1;
        uint8_t discard[255 + 2];
        to_read = len + 2;
        if (recv_all(sock, discard, to_read) < 0) return -1;
        return 0;
    } else if (header[3] == 0x04) {
        to_read = 16 + 2;
    } else {
        return -1;
    }

    uint8_t discard[18];
    if (to_read > 0) {
        if (recv_all(sock, discard, to_read) < 0) return -1;
    }
    return 0;
}

static int transfer_http_request(int sock, const struct stress_options *opts) {
    char request[512];
    int len = snprintf(request, sizeof(request),
                       "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                       opts->request_path, opts->target_host);
    if (len <= 0 || (size_t)len >= sizeof(request)) {
        fprintf(stderr, "request buffer too small\n");
        return -1;
    }

    if (send_all(sock, request, (size_t)len) < 0) return -1;

    size_t total = 0;
    char buffer[4096];
    while (1) {
        ssize_t n = recv(sock, buffer, sizeof(buffer), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
        if (total >= opts->min_response_bytes) {
            return 0;
        }
    }
    return (total >= opts->min_response_bytes) ? 0 : -1;
}

static int run_session(const struct stress_options *opts) {
    for (const struct addrinfo *ai = opts->proxy_ai; ai != NULL; ai = ai->ai_next) {
        int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
            close(sock);
            continue;
        }

        int ok = 0;
        if (socks5_send_greeting(sock) == 0 &&
            socks5_send_auth(sock, opts->username, opts->password) == 0 &&
            socks5_send_connect(sock, opts->target_host, opts->target_port) == 0 &&
            transfer_http_request(sock, opts) == 0) {
            ok = 1;
        }

        close(sock);
        if (ok) return 1;
    }
    return 0;
}

static void *worker_thread(void *arg) {
    struct worker_ctx *ctx = arg;
    for (int i = 0; i < ctx->iterations; i++) {
        if (run_session(ctx->opts)) {
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

static void print_usage(const char *prog) {
    printf("Usage: %s [--host H] [--port P] [--total N] [--concurrency M]\\n"
           "           --user U --pass P --target-host HOST [--target-port PORT]\\n"
           "           [--path /resource] [--min-response BYTES]\n",
           prog);
}

int main(int argc, char *argv[]) {
    const char *proxy_host = "127.0.0.1";
    const char *proxy_port = "1080";
    int total = DEFAULT_TOTAL;
    int concurrency = DEFAULT_CONCURRENCY;
    const char *username = NULL;
    const char *password = NULL;
    const char *target_host = "example.org";
    int target_port = 80;
    const char *request_path = "/";
    size_t min_response = 1024;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            proxy_host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            proxy_port = argv[++i];
        } else if (strcmp(argv[i], "--total") == 0 && i + 1 < argc) {
            total = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--concurrency") == 0 && i + 1 < argc) {
            concurrency = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            username = argv[++i];
        } else if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) {
            password = argv[++i];
        } else if (strcmp(argv[i], "--target-host") == 0 && i + 1 < argc) {
            target_host = argv[++i];
        } else if (strcmp(argv[i], "--target-port") == 0 && i + 1 < argc) {
            target_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            request_path = argv[++i];
        } else if (strcmp(argv[i], "--min-response") == 0 && i + 1 < argc) {
            min_response = (size_t)atol(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!username || !password) {
        fprintf(stderr, "--user and --pass are required because the proxy exige autenticación\n");
        return 1;
    }

    if (total <= 0 || concurrency <= 0) {
        fprintf(stderr, "total and concurrency must be > 0\n");
        return 1;
    }

    struct addrinfo hints = {0}, *ai_list = NULL;
    hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(proxy_host, proxy_port, &hints, &ai_list);
    if (gai != 0) {
        fprintf(stderr, "getaddrinfo(%s:%s): %s\n", proxy_host, proxy_port, gai_strerror(gai));
        return 1;
    }

    struct stress_options opts = {
        .proxy_ai = ai_list,
        .username = username,
        .password = password,
        .target_host = target_host,
        .request_path = request_path,
        .target_port = target_port,
        .min_response_bytes = min_response,
    };

    atomic_int successes = 0;

    pthread_t *threads = calloc(concurrency, sizeof(pthread_t));
    struct worker_ctx *ctxs = calloc(concurrency, sizeof(struct worker_ctx));
    if (!threads || !ctxs) {
        fprintf(stderr, "Could not allocate worker structures\n");
        free(threads);
        free(ctxs);
        freeaddrinfo(ai_list);
        return 1;
    }

    int per_thread = total / concurrency;
    int remainder = total % concurrency;

    double start = now_seconds();
    for (int i = 0; i < concurrency; i++) {
        ctxs[i].iterations = per_thread + (i < remainder ? 1 : 0);
        ctxs[i].successes = &successes;
        ctxs[i].opts = &opts;
        pthread_create(&threads[i], NULL, worker_thread, &ctxs[i]);
    }

    for (int i = 0; i < concurrency; i++) {
        pthread_join(threads[i], NULL);
    }

    double end = now_seconds();

    int succ = atomic_load(&successes);
    printf("Total attempted: %d\n", total);
    printf("Successful transfers: %d\n", succ);
    printf("Duration: %.2f s\n", end - start);
    if (end > start) {
        printf("Throughput: %.2f sessions/sec\n", succ / (end - start));
    }
    printf("Failures: %d\n", total - succ);

    free(threads);
    free(ctxs);
    freeaddrinfo(ai_list);

    return (succ == total) ? 0 : 1;
}

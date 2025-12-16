#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "protocols/socks5/socks5.h"   // header for functions under test

// Helper: start a simple TCP echo-like server (does not send data, just accepts and closes)
// family: AF_INET or AF_INET6
// Returns listening port via out_port. Spawns a thread that accepts a single
// connection and then closes it.
typedef struct {
    int listen_fd;
} accept_thread_arg_t;

static void *accept_thread(void *arg) {
    accept_thread_arg_t *info = (accept_thread_arg_t *)arg;
    int listen_fd = info->listen_fd;
    free(info);

    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd >= 0) {
        // Simply close the connection.
        close(client_fd);
    }
    close(listen_fd);
    return NULL;
}

static int start_dummy_server(int family, uint16_t *out_port) {
    int sock = socket(family, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (family == AF_INET) {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
        addr.sin_port = htons(0); // dynamic port
        if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind IPv4");
            close(sock);
            return -1;
        }
        socklen_t len = sizeof(addr);
        if (getsockname(sock, (struct sockaddr *)&addr, &len) == 0) {
            *out_port = ntohs(addr.sin_port);
        }
    } else { // IPv6
        struct sockaddr_in6 addr6 = {0};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_loopback; // ::1
        addr6.sin6_port = htons(0);
        if (bind(sock, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
            perror("bind IPv6");
            close(sock);
            return -1;
        }
        socklen_t len = sizeof(addr6);
        if (getsockname(sock, (struct sockaddr *)&addr6, &len) == 0) {
            *out_port = ntohs(addr6.sin6_port);
        }
    }

    if (listen(sock, 1) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    // Spawn accept thread
    pthread_t tid;
    accept_thread_arg_t *thr_arg = malloc(sizeof(accept_thread_arg_t));
    thr_arg->listen_fd = sock;
    pthread_create(&tid, NULL, accept_thread, thr_arg);
    pthread_detach(tid);

    return 0; // success
}

static void test_ipv6_support(void) {
    printf("Running IPv6 support test...\n");

    uint16_t srv_port;
    assert(start_dummy_server(AF_INET6, &srv_port) == 0);

    // Prepare socketpair for client/server communication
    int sp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

    // Build SOCKS5 CONNECT request for ::1 and srv_port
    uint8_t req[22];
    memset(req, 0, sizeof(req));
    req[0] = 0x05; // VER
    req[1] = 0x01; // CMD = CONNECT
    req[2] = 0x00; // RSV
    req[3] = 0x04; // ATYP = IPv6

    // DST.ADDR ::1 (16 bytes)
    // All zeros except last byte 1
    memset(&req[4], 0, 16);
    req[4 + 15] = 1;

    uint16_t port_n = htons(srv_port);
    memcpy(&req[4 + 16], &port_n, 2);

    // Write request into the "client" side before calling handler
    assert(write(sp[1], req, sizeof(req)) == sizeof(req));

    struct socks5args args = {0};
    int dest_port = 0;
    int remote_fd = socks5_handle_request(sp[0], &args, 42, &dest_port);

    assert(remote_fd >= 0);
    assert(dest_port == srv_port);
    close(remote_fd);
    close(sp[0]);
    close(sp[1]);

    printf("IPv6 support test passed!\n");
}

static void test_failover_iterates_addresses(void) {
    printf("Running failover test (IPv6 fails, IPv4 succeeds)...\n");

    uint16_t srv_port;
    assert(start_dummy_server(AF_INET, &srv_port) == 0); // Only IPv4 server

    int sp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);

    // Build domain request for "localhost" to srv_port
    const char *domain = "localhost";
    uint8_t len = (uint8_t)strlen(domain);
    size_t req_len = 4 + 1 + len + 2;
    uint8_t *req = calloc(1, req_len);

    req[0] = 0x05; // VER
    req[1] = 0x01; // CMD
    req[2] = 0x00; // RSV
    req[3] = 0x03; // ATYP = DOMAIN
    req[4] = len;
    memcpy(&req[5], domain, len);
    uint16_t port_n = htons(srv_port);
    memcpy(&req[5 + len], &port_n, 2);

    assert(write(sp[1], req, req_len) == (ssize_t)req_len);

    struct socks5args args = {0};
    int dest_port = 0;
    int remote_fd = socks5_handle_request(sp[0], &args, 43, &dest_port);

    assert(remote_fd >= 0);
    assert(dest_port == srv_port);
    close(remote_fd);
    close(sp[0]);
    close(sp[1]);

    free(req);

    printf("Failover test passed!\n");
}

int main(void) {
    test_ipv6_support();
    test_failover_iterates_addresses();
    printf("All SOCKS5 tests passed.\n");
    return 0;
}

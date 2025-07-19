#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include "socks5.h"
#include "util.h"
#include "../logger.h"
#include "../shared/shared.h"
#include "../args.h"

#define MAX_CLIENTS 1024
#define MAX_PENDING_CONNECTION_REQUESTS 128

struct client {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addr_len;
};

static struct client clients[MAX_CLIENTS];

void cleanup_handler(int sig) {
    log_info("Received signal %d, cleaning up...", sig);
    mgmt_cleanup_shared_memory();
    exit(0);
}

void add_client(int client_fd, struct sockaddr_storage *addr, socklen_t addr_len) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].fd == -1) {
            clients[i].fd = client_fd;
            clients[i].addr = *addr;
            clients[i].addr_len = addr_len;
            return;
        }
    }
    log_error("Too many clients, closing new connection");
    close(client_fd);
}

void remove_client(int index) {
    if (clients[index].fd != -1) {
        close(clients[index].fd);
        clients[index].fd = -1;
    }
}

int create_server_socket(int port) {
    int serverSocket = socket(AF_INET6, SOCK_STREAM, 0);
    if (serverSocket < 0) return -1;

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    if (bind(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        return -1;

    if (listen(serverSocket, MAX_PENDING_CONNECTION_REQUESTS) < 0)
        return -1;

    return serverSocket;
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    struct socks5args args;
    parse_args(argc, argv, &args);

    logger_init(LOG_INFO, "metrics.log");
    atexit(logger_close);

    printf("  SOCKS5 address: %s:%d\n", args.socks_addr, args.socks_port);
    printf("  Management address: %s:%d\n", args.mng_addr, args.mng_port);
    printf("  Disectors enabled: %s\n", args.disectors_enabled ? "yes" : "no");

    int userCount = 0;
    for (int i = 0; i < MAX_USERS; i++) {
        if (args.users[i].name && args.users[i].pass &&
            args.users[i].name[0] != '\0' && args.users[i].pass[0] != '\0') {
            userCount++;
        }
    }
    printf("  Configured users: %d\n", userCount);
    for (int i = 0; i < MAX_USERS; i++) {
        if (args.users[i].name && args.users[i].pass &&
            args.users[i].name[0] != '\0' && args.users[i].pass[0] != '\0') {
            printf("    - %s\n", args.users[i].name);
        }
    }

    if (userCount > 0) {
        log_info("Username/password authentication will be required");
    } else {
        log_info("No authentication will be required");
    }

    if (mgmt_init_shared_memory() < 0) exit(1);

    signal(SIGTERM, cleanup_handler);
    signal(SIGINT, cleanup_handler);

    for (int i = 0; i < MAX_CLIENTS; i++) clients[i].fd = -1;

    int socks5Socket = create_server_socket(args.socks_port);
    if (socks5Socket < 0) exit(1);

    int mgmtSocket = create_server_socket(args.mng_port);
    if (mgmtSocket < 0) {
        close(socks5Socket);
        exit(1);
    }

    struct sockaddr_storage boundAddress;
    socklen_t boundAddressLen = sizeof(boundAddress);
    char addrBuffer[128];

    if (getsockname(socks5Socket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        log_info("SOCKS5 server listening on %s", addrBuffer);
    }
    if (getsockname(mgmtSocket, (struct sockaddr*)&boundAddress, &boundAddressLen) >= 0) {
        printSocketAddress((struct sockaddr*)&boundAddress, addrBuffer);
        log_info("Management server listening on %s", addrBuffer);
    }

    fd_set master_set, read_set;
    int max_fd = socks5Socket > mgmtSocket ? socks5Socket : mgmtSocket;

    FD_ZERO(&master_set);
    FD_SET(socks5Socket, &master_set);
    FD_SET(mgmtSocket, &master_set);

    log_info("Server ready, waiting for connections...");

    while (1) {
        read_set = master_set;
        if (select(max_fd + 1, &read_set, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select"); break;
        }

        if (FD_ISSET(socks5Socket, &read_set)) {
            struct sockaddr_storage client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(socks5Socket, (struct sockaddr*)&client_addr, &addr_len);
            if (client_fd >= 0) {
                fcntl(client_fd, F_SETFL, O_NONBLOCK);
                FD_SET(client_fd, &master_set);
                if (client_fd > max_fd) max_fd = client_fd;
                add_client(client_fd, &client_addr, addr_len);
                printSocketAddress((struct sockaddr*)&client_addr, addrBuffer);
                log_info("New SOCKS5 connection from %s", addrBuffer);
            }
        }

        if (FD_ISSET(mgmtSocket, &read_set)) {
            struct sockaddr_storage client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(mgmtSocket, (struct sockaddr*)&client_addr, &addr_len);
            if (client_fd >= 0) {
                fcntl(client_fd, F_SETFL, O_NONBLOCK);
                printSocketAddress((struct sockaddr*)&client_addr, addrBuffer);
                log_info("New management connection from %s", addrBuffer);
                if (mgmt_handle_client(client_fd) < 0) {
                    log_error("Error handling management client");
                }
                close(client_fd);
                log_info("Management connection closed");
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int fd = clients[i].fd;
            if (fd != -1 && FD_ISSET(fd, &read_set)) {
                printf("[INF] Handling SOCKS5 connection\n");
                int result = handleClient(fd, &args);
                FD_CLR(fd, &master_set);
                remove_client(i);
                if (result < 0) log_error("Client handler failed (fd=%d)", fd);
                else log_info("SOCKS5 connection closed");
            }
        }
    }

    close(socks5Socket);
    close(mgmtSocket);
    mgmt_cleanup_shared_memory();
    return 0;
}
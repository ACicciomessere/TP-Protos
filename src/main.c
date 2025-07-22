#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "protocols/socks5/socks5.h"
#include "utils/logger.h"
#include "utils/util.h"
#include "utils/args.h"
#include "shared.h"

#define MAX_CLIENTS 1024
#define BUFFER_SIZE 4096
#define MAX_PENDING_CONNECTION_REQUESTS 128

typedef enum {
    STATE_GREETING,
    STATE_AUTH,
    STATE_REQUEST,
    STATE_CONNECTING,
    STATE_RELAYING,
    STATE_DONE,
    STATE_ERROR
} client_state;

typedef struct {
    int client_fd;
    uint64_t connection_id;
    int remote_fd;
    client_state state;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    char buffer[BUFFER_SIZE];
    int buffer_len;
    int closed;
} client_t;

client_t clients[MAX_CLIENTS];

void cleanup_handler(int sig) {
    printf("[SIG] Caught signal %d, cleaning up and exiting.\n", sig);
    log_info("Signal %d received. Cleaning up...", sig);
    mgmt_cleanup_shared_memory();
    exit(0);
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    printf("[DBG] Set non-blocking mode on fd=%d\n", fd);
}

void remove_client(int i, fd_set *master_set) {
    if (clients[i].client_fd != -1) {
        printf("[DBG] Closing client fd=%d\n", clients[i].client_fd);
        close(clients[i].client_fd);
        FD_CLR(clients[i].client_fd, master_set);
    }
    if (clients[i].remote_fd != -1) {
        printf("[DBG] Closing remote fd=%d\n", clients[i].remote_fd);
        close(clients[i].remote_fd);
        FD_CLR(clients[i].remote_fd, master_set);
    }
    mgmt_update_stats(0, -1);
    clients[i].client_fd = -1;
    clients[i].remote_fd = -1;
    clients[i].state = STATE_DONE;
}

int create_server_socket(int port) {
    printf("[INF] Creating server socket on port %d...\n", port);
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) return -1;
    if (listen(sock, MAX_PENDING_CONNECTION_REQUESTS) < 0) return -1;

    return sock;
}

int find_available_client_slot(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].client_fd == -1) return i;
    }
    return -1;
}

void relay_data(int from_fd, int to_fd, int client_index) {
    char buffer[BUFFER_SIZE];
    ssize_t nread = recv(from_fd, buffer, sizeof(buffer), 0);
    if (nread <= 0) {
        printf("[DBG] Connection closed in relay (client=%d)\n", clients[client_index].client_fd);
        log_info("Connection closed in relay (client=%d)", clients[client_index].client_fd);
        clients[client_index].state = STATE_DONE;
        return;
    }
    ssize_t nwritten = send(to_fd, buffer, nread, 0);
    if (nwritten > 0) {
        mgmt_update_stats(nwritten, 0);
    }
    if (nwritten < 0) {
        printf("[ERR] Send error in relay (client=%d)\n", clients[client_index].client_fd);
        log_error("Send error in relay (client=%d)", clients[client_index].client_fd);
        clients[client_index].state = STATE_ERROR;
    }
}

int main(int argc, char **argv) {
    struct socks5args args;
    parse_args(argc, argv, &args);
    logger_init(LOG_INFO, "metrics.log");
    atexit(logger_close);
    mgmt_init_shared_memory();    


    // Inicializar memoria compartida
    if (mgmt_init_shared_memory() < 0) {
        log_fatal("Failed to initialize shared memory");
        return 1;
    }

    printf("[INF] Iniciando servidor SOCKS5...\n");

    int server_fd = create_server_socket(args.socks_port);
    if (server_fd < 0) {
        perror("server socket");
        return 1;
    }
    set_nonblocking(server_fd);

    // Iniciar servidor de gestion
    int mgmt_fd = mgmt_server_start(args.mng_port);
        if (mgmt_fd < 0) {
        log_error("No se pudo iniciar el servidor de gestión");
        return 1;
    }
    // Trabajaremos la gestión en el mismo loop multiplexado (un solo hilo).
    set_nonblocking(mgmt_fd);


    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].client_fd = -1;
        clients[i].remote_fd = -1;
        clients[i].state = STATE_DONE;
    }

    fd_set master_set, read_set, write_set;
    FD_ZERO(&master_set);
    FD_SET(server_fd, &master_set);
    FD_SET(mgmt_fd, &master_set);
    int fdmax = (server_fd > mgmt_fd) ? server_fd : mgmt_fd;

    signal(SIGINT, cleanup_handler);

    while (1) {
        read_set = master_set;
        write_set = master_set;

        if (select(fdmax + 1, &read_set, &write_set, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        if (FD_ISSET(server_fd, &read_set)) {
            struct sockaddr_storage client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
            if (client_fd >= 0) {
                set_nonblocking(client_fd);
                int i = find_available_client_slot();
                if (i >= 0) {
                    clients[i].client_fd = client_fd;
                    clients[i].connection_id = mgmt_get_next_connection_id();
                    clients[i].remote_fd = -1;
                    clients[i].state = STATE_GREETING;
                    clients[i].addr = client_addr;
                    clients[i].addr_len = addrlen;
                    clients[i].buffer_len = 0;
                    clients[i].closed = 0;
                    FD_SET(client_fd, &master_set);
                    if (client_fd > fdmax) fdmax = client_fd;
                    printf("[INF] Accepted new client (fd=%d, id=%llu)\n", client_fd, clients[i].connection_id);
                    log_info("Accepted new client (fd=%d, id=%llu)", client_fd, clients[i].connection_id);
                    mgmt_update_stats(0, 1);
                } else {
                    printf("[ERR] Too many clients, rejecting fd=%d\n", client_fd);
                    log_error("Too many clients");
                    close(client_fd);
                }
            }
        }

        if (FD_ISSET(mgmt_fd, &read_set)) {
            int mgmt_client_fd = accept(mgmt_fd, NULL, NULL);
            if (mgmt_client_fd >= 0) {
                /* Management protocol uses blocking recv/send loops.
                 * Clear O_NONBLOCK inherited from the listening socket. */
                int flags = fcntl(mgmt_client_fd, F_GETFL, 0);
                if (flags != -1) {
                    fcntl(mgmt_client_fd, F_SETFL, flags & ~O_NONBLOCK);
                }
                // Manejar la conexión del cliente de gestión en el mismo hilo
                mgmt_handle_client(mgmt_client_fd);
                close(mgmt_client_fd);
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            int cfd = clients[i].client_fd;
            if (cfd == -1) continue;

            if (FD_ISSET(cfd, &read_set) || (clients[i].remote_fd != -1 && FD_ISSET(clients[i].remote_fd, &read_set))) {
                switch (clients[i].state) {
                    case STATE_GREETING:
                        printf("[DBG] Handling GREETING for fd=%d\n", cfd);
                        log_info("Handling GREETING for fd=%d, id=%llu", cfd, clients[i].connection_id);
                        {
                            int res = socks5_handle_greeting(cfd, &args, clients[i].connection_id);
                            if (res < 0) {
                                clients[i].state = STATE_ERROR;
                            } else {
                                clients[i].state = (client_state)res;
                            }
                        }
                        break;
                    case STATE_AUTH:
                        printf("[DBG] Handling AUTH for fd=%d\n", cfd);
                        log_info("Handling AUTH for fd=%d, id=%llu", cfd, clients[i].connection_id);
                        {
                            int res = socks5_handle_auth(cfd, &args, clients[i].connection_id);
                            if (res < 0) {
                                clients[i].state = STATE_ERROR;
                            } else {
                                clients[i].state = (client_state)res;
                            }
                        }
                        break;
                    case STATE_REQUEST:
                        printf("[DBG] Handling REQUEST for fd=%d\n", cfd);
                        log_info("Handling REQUEST for fd=%d, id=%llu", cfd, clients[i].connection_id);
                        clients[i].remote_fd = socks5_handle_request(cfd, &args, clients[i].connection_id);
                        if (clients[i].remote_fd >= 0) {
                            set_nonblocking(clients[i].remote_fd);
                            FD_SET(clients[i].remote_fd, &master_set);
                            if (clients[i].remote_fd > fdmax) fdmax = clients[i].remote_fd;
                            clients[i].state = STATE_RELAYING;
                        } else {
                            clients[i].state = STATE_ERROR;
                        }
                        break;
                    case STATE_RELAYING:
                        if (clients[i].remote_fd != -1 && FD_ISSET(cfd, &read_set)) {
                            relay_data(cfd, clients[i].remote_fd, i);
                        }
                        if (clients[i].remote_fd != -1 && FD_ISSET(clients[i].remote_fd, &read_set)) {
                            relay_data(clients[i].remote_fd, cfd, i);
                        }
                        break;
                    case STATE_ERROR:
                        printf("[ERR] Client in error state (fd=%d), closing.\n", cfd);
                        log_error("Closing client due to error (fd=%d, id=%llu)", cfd, clients[i].connection_id);
                        remove_client(i, &master_set);
                        break;
                    case STATE_DONE:
                        printf("[INF] Client session done (fd=%d), removing.\n", cfd);
                        remove_client(i, &master_set);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    printf("[INF] Server exiting...\n");
    close(server_fd);
    close(mgmt_fd);
    mgmt_cleanup_shared_memory();
    return 0;
}
